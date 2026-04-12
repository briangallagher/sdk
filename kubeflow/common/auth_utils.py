# Copyright 2025 The Kubeflow Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Central Kubernetes client construction and auth resolution.

``load_kubernetes_config`` returns a :class:`kubernetes.client.ApiClient`
configured for Trainer, Katib/Optimizer, and Spark backends.

Resolution order (first match wins)
------------------------------------

1. **Pre-built** ``client_configuration`` — callers fully control TLS, host,
   hooks, and custom auth (e.g. tests, advanced proxies).

2. **Pluggable** ``credentials`` + ``server`` — wires
   ``Configuration.refresh_api_key_hook`` to a :class:`TokenCredentialsBase`
   implementation. Use this for Vault, AWS STS, enterprise IdPs, or the
   optional ``kubernetes_oidc`` flows (client credentials, password, device,
   browser+PKCE). The hook is the Kubernetes Python client's only supported
   extension point for dynamic tokens; it runs before each API call and must
   set ``api_key`` / ``api_key_prefix`` for Bearer tokens when needed.

3. **Explicit bearer** ``token`` + ``server`` — static access token (e.g. CI
   secret, ``kubectl create token``).

4. **Environment** ``KUBEFLOW_TOKEN`` + ``KUBEFLOW_API_HOST`` — same as (3) for
   notebooks and jobs that inject env vars.

5. **Environment OIDC client credentials** — ``KUBEFLOW_OIDC_ISSUER``,
   ``KUBEFLOW_OIDC_CLIENT_ID``, ``KUBEFLOW_OIDC_CLIENT_SECRET``, and
   ``KUBEFLOW_API_HOST`` build :class:`kubernetes_oidc.OIDCClientCredentials`
   (RFC 6749 §4.4). Requires ``pip install kubeflow[oidc]``.

6. **Kubeconfig file** — local dev and shared clusters via ``config_file`` /
   ``context`` (or default kubeconfig when not in-cluster).

7. **In-cluster** service account — pods with a projected service account token.
"""

from __future__ import annotations

import os

from kubernetes import client, config

from kubeflow.common.types import KubernetesBackendConfig
import kubeflow.common.utils as common_utils


def _host_from_cfg(cfg: KubernetesBackendConfig, host: str) -> client.Configuration:
    """Apply ``server``, TLS verification, and optional CA bundle to a fresh Configuration."""
    configuration = client.Configuration()
    configuration.host = host.rstrip("/")
    configuration.verify_ssl = cfg.verify_ssl
    if cfg.ca_cert:
        configuration.ssl_ca_cert = cfg.ca_cert
    return configuration


def _try_oidc_env_client_credentials(cfg: KubernetesBackendConfig) -> client.ApiClient | None:
    """Build an ApiClient from KUBEFLOW_OIDC_* env vars using kubernetes-oidc.

    Covers service-style client credentials against a known issuer when callers
    do not construct ``OIDCClientCredentials`` in code. Returns *None* when the
    required variables are not all set (so resolution can fall through to
    kubeconfig / in-cluster).
    """
    issuer = os.environ.get("KUBEFLOW_OIDC_ISSUER")
    cid = os.environ.get("KUBEFLOW_OIDC_CLIENT_ID")
    secret = os.environ.get("KUBEFLOW_OIDC_CLIENT_SECRET")
    api_host = os.environ.get("KUBEFLOW_API_HOST")
    if not (issuer and cid and secret and api_host):
        return None
    try:
        from kubernetes_oidc import OIDCClientCredentials
    except ImportError as e:
        raise ImportError(
            "KUBEFLOW_OIDC_* environment variables are set but kubernetes-oidc is not "
            'installed. Install with: pip install "kubeflow[oidc]"'
        ) from e
    scopes_env = os.environ.get("KUBEFLOW_OIDC_SCOPES")
    scopes = scopes_env.split() if scopes_env else None
    oidc_creds = OIDCClientCredentials(
        issuer_url=issuer,
        client_id=cid,
        client_secret=secret,
        scopes=scopes,
        verify=cfg.verify_ssl,
    )
    configuration = _host_from_cfg(cfg, api_host)
    configuration.refresh_api_key_hook = oidc_creds.refresh_api_key_hook
    return client.ApiClient(configuration)


def load_kubernetes_config(cfg: KubernetesBackendConfig) -> client.ApiClient:
    """Resolve auth and return a configured :class:`kubernetes.client.ApiClient`."""
    # 1) Pre-built client configuration — caller owns the entire stack.
    if cfg.client_configuration is not None:
        return client.ApiClient(cfg.client_configuration)

    # 2) Pluggable credentials + API server URL — dynamic tokens via hook.
    if cfg.credentials is not None:
        if not cfg.server:
            raise ValueError(
                "KubernetesBackendConfig.credentials requires KubernetesBackendConfig.server "
                "(Kubernetes API URL)."
            )
        configuration = _host_from_cfg(cfg, cfg.server)
        configuration.refresh_api_key_hook = cfg.credentials.refresh_api_key_hook
        return client.ApiClient(configuration)

    # 3) Explicit static bearer token — CI, pre-issued SA tokens, copy-paste from oc/kubectl.
    if cfg.token is not None:
        if not cfg.server:
            raise ValueError(
                "KubernetesBackendConfig.token requires KubernetesBackendConfig.server "
                "(Kubernetes API URL)."
            )
        configuration = _host_from_cfg(cfg, cfg.server)
        configuration.api_key["authorization"] = cfg.token
        configuration.api_key_prefix["authorization"] = "Bearer"
        return client.ApiClient(configuration)

    # 4) Same as (3) via environment — platforms that inject KUBEFLOW_* into workloads.
    env_token = os.environ.get("KUBEFLOW_TOKEN")
    env_host = os.environ.get("KUBEFLOW_API_HOST")
    if env_token and env_host:
        configuration = _host_from_cfg(cfg, env_host)
        configuration.api_key["authorization"] = env_token
        configuration.api_key_prefix["authorization"] = "Bearer"
        return client.ApiClient(configuration)

    # 5) OIDC client credentials from environment — headless clusters / automation.
    oidc_client = _try_oidc_env_client_credentials(cfg)
    if oidc_client is not None:
        return oidc_client

    # 6–7) Standard kubeconfig or in-cluster SA — unchanged from upstream SDK behavior.
    if cfg.config_file or not common_utils.is_running_in_k8s():
        config.load_kube_config(config_file=cfg.config_file, context=cfg.context)
    else:
        config.load_incluster_config()

    return client.ApiClient(cfg.client_configuration)
