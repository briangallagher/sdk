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

"""Authentication bridge between KubernetesBackendConfig and kube-authkit.

Provides three public functions:

- ``resolve_credentials`` -- resolves a ``TokenCredentialsBase`` from explicit
  arguments, kube-authkit strategies, or environment variables.
- ``load_kubernetes_config`` -- builds a Kubernetes ``ApiClient`` using the
  resolved credentials, kubeconfig, or in-cluster service account.
- ``get_kubernetes_client`` -- convenience wrapper that resolves config from
  ``KubernetesBackendConfig`` and returns an ``ApiClient``.
"""

from __future__ import annotations

import logging
import os

from kubernetes import client, config

from kubeflow.common.auth.types import TokenCredentialsBase
from kubeflow.common.types import KubernetesBackendConfig

try:
    from kube_authkit import AuthConfig
    from kube_authkit import get_k8s_client as kube_authkit_get_client  # noqa: F401
    from kube_authkit.factory import AuthFactory

    KUBE_AUTHKIT_AVAILABLE = True
except ImportError:
    KUBE_AUTHKIT_AVAILABLE = False

logger = logging.getLogger(__name__)


class _KubeAuthkitAdapter:
    """Wraps a kube-authkit ``AuthStrategy`` as a ``TokenCredentialsBase``.

    The adapter delegates ``get_token()`` to the strategy (which, after
    the kube-authkit alignment PR, auto-refreshes expired tokens).
    ``refresh_api_key_hook`` updates the K8s ``Configuration`` on every request.
    """

    def __init__(self, strategy) -> None:
        self._strategy = strategy

    def refresh_api_key_hook(self, config: client.Configuration) -> None:
        config.api_key["authorization"] = self._strategy.get_token()
        config.api_key_prefix["authorization"] = "Bearer"

    def get_token(self) -> str:
        return self._strategy.get_token()


class _StaticTokenCredentials:
    """Wraps a static token string as a ``TokenCredentialsBase``."""

    def __init__(self, token: str) -> None:
        self._token = token

    def refresh_api_key_hook(self, config: client.Configuration) -> None:
        config.api_key["authorization"] = self._token
        config.api_key_prefix["authorization"] = "Bearer"

    def get_token(self) -> str:
        return self._token


def resolve_credentials(
    *,
    credentials: TokenCredentialsBase | None = None,
    token: str | None = None,
    auth_method: str | None = None,
    oidc_issuer: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    use_device_flow: bool = False,
    use_client_credentials: bool = False,
    oidc_callback_port: int = 8080,
    scopes: list[str] | None = None,
    k8s_api_host: str | None = None,
    use_keyring: bool = False,
    verify_ssl: bool = True,
    ca_cert: str | None = None,
) -> TokenCredentialsBase | None:
    """Resolve a ``TokenCredentialsBase`` from explicit args or environment.

    Resolution order:

    1. Explicit ``credentials`` object (returned as-is)
    2. Explicit ``token`` -> wrapped in ``_StaticTokenCredentials``
    3. Explicit OIDC / OpenShift config -> kube-authkit strategy via adapter
    4. ``KUBEFLOW_OIDC_*`` env vars -> kube-authkit OIDC strategy via adapter
    5. ``KUBEFLOW_TOKEN`` env var -> ``_StaticTokenCredentials``
    6. ``None`` (nothing found -- caller falls back to kubeconfig / in-cluster)
    """
    if credentials is not None:
        return credentials

    if token is not None:
        return _StaticTokenCredentials(token)

    authkit_creds = _try_authkit_credentials(
        auth_method=auth_method,
        oidc_issuer=oidc_issuer,
        client_id=client_id,
        client_secret=client_secret,
        use_device_flow=use_device_flow,
        use_client_credentials=use_client_credentials,
        oidc_callback_port=oidc_callback_port,
        scopes=scopes,
        k8s_api_host=k8s_api_host,
        use_keyring=use_keyring,
        verify_ssl=verify_ssl,
        ca_cert=ca_cert,
    )
    if authkit_creds is not None:
        return authkit_creds

    env_creds = _try_credentials_from_env(verify_ssl=verify_ssl, ca_cert=ca_cert)
    if env_creds is not None:
        return env_creds

    token_env = os.getenv("KUBEFLOW_TOKEN") or os.getenv("AUTHKIT_TOKEN")
    if token_env:
        return _StaticTokenCredentials(token_env)

    return None


def load_kubernetes_config(
    *,
    config_file: str | None = None,
    context: str | None = None,
    client_configuration: client.Configuration | None = None,
    token: str | None = None,
    server: str | None = None,
    credentials: TokenCredentialsBase | None = None,
    auth_method: str | None = None,
    oidc_issuer: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    use_device_flow: bool = False,
    use_client_credentials: bool = False,
    oidc_callback_port: int = 8080,
    scopes: list[str] | None = None,
    k8s_api_host: str | None = None,
    use_keyring: bool = False,
    verify_ssl: bool = True,
    ca_cert: str | None = None,
) -> client.ApiClient:
    """Build a Kubernetes ``ApiClient`` with flexible auth options.

    Resolution order:

    1. Explicit ``client_configuration`` (pass-through)
    2. Pluggable ``credentials`` / ``token`` / OIDC config / env vars
    3. Kubeconfig file (``config_file`` / ``context`` / default)
    4. In-cluster service account
    """
    if client_configuration is not None:
        return client.ApiClient(configuration=client_configuration)

    resolved = resolve_credentials(
        credentials=credentials,
        token=token,
        auth_method=auth_method,
        oidc_issuer=oidc_issuer,
        client_id=client_id,
        client_secret=client_secret,
        use_device_flow=use_device_flow,
        use_client_credentials=use_client_credentials,
        oidc_callback_port=oidc_callback_port,
        scopes=scopes,
        k8s_api_host=k8s_api_host,
        use_keyring=use_keyring,
        verify_ssl=verify_ssl,
        ca_cert=ca_cert,
    )

    if resolved is not None:
        if server is None:
            server = k8s_api_host or os.getenv("KUBEFLOW_API_HOST") or os.getenv("AUTHKIT_API_HOST")
        if server is None:
            raise ValueError(
                "'server' (or 'k8s_api_host') is required when using credentials or token. "
                "Set it directly or via KUBEFLOW_API_HOST."
            )
        return _build_client_with_credentials(
            resolved, server, verify_ssl=verify_ssl, ca_cert=ca_cert,
        )

    try:
        config.load_kube_config(config_file=config_file, context=context)
        logger.debug("Loaded kubeconfig")
        return client.ApiClient()
    except config.ConfigException:
        pass

    try:
        config.load_incluster_config()
        logger.debug("Loaded in-cluster config")
        return client.ApiClient()
    except config.ConfigException:
        pass

    raise RuntimeError(
        "Could not configure Kubernetes client. Tried: credentials, "
        "token, KUBEFLOW_OIDC_* env vars, KUBEFLOW_TOKEN env var, "
        "kubeconfig, in-cluster config. None succeeded."
    )


def get_kubernetes_client(cfg: KubernetesBackendConfig) -> client.ApiClient:
    """Build a Kubernetes ApiClient from ``KubernetesBackendConfig``.

    This is the main entry point used by trainer, optimizer, and spark backends.
    It maps ``KubernetesBackendConfig`` fields to ``load_kubernetes_config`` params.
    """
    return load_kubernetes_config(
        config_file=cfg.config_file,
        context=cfg.context,
        client_configuration=cfg.client_configuration,
        token=cfg.token,
        server=cfg.server,
        credentials=cfg.credentials,
        auth_method=cfg.auth_method,
        oidc_issuer=cfg.oidc_issuer,
        client_id=cfg.client_id,
        client_secret=cfg.client_secret,
        use_device_flow=cfg.use_device_flow,
        use_client_credentials=cfg.use_client_credentials,
        oidc_callback_port=cfg.oidc_callback_port,
        scopes=cfg.scopes,
        k8s_api_host=cfg.k8s_api_host,
        use_keyring=cfg.use_keyring,
        verify_ssl=cfg.verify_ssl,
        ca_cert=cfg.ca_cert,
    )


def _build_client_with_credentials(
    credentials: TokenCredentialsBase,
    server: str,
    *,
    verify_ssl: bool = True,
    ca_cert: str | None = None,
) -> client.ApiClient:
    k8s_config = client.Configuration()
    k8s_config.host = server
    k8s_config.verify_ssl = verify_ssl
    if ca_cert:
        k8s_config.ssl_ca_cert = ca_cert

    k8s_config.api_key["authorization"] = "placeholder"
    k8s_config.api_key_prefix["authorization"] = "Bearer"
    k8s_config.refresh_api_key_hook = credentials.refresh_api_key_hook

    return client.ApiClient(configuration=k8s_config)


def _try_authkit_credentials(
    *,
    auth_method: str | None,
    oidc_issuer: str | None,
    client_id: str | None,
    client_secret: str | None,
    use_device_flow: bool,
    use_client_credentials: bool,
    oidc_callback_port: int,
    scopes: list[str] | None,
    k8s_api_host: str | None,
    use_keyring: bool,
    verify_ssl: bool,
    ca_cert: str | None,
) -> TokenCredentialsBase | None:
    """Build credentials via kube-authkit strategy if OIDC/OpenShift config is present."""
    if not KUBE_AUTHKIT_AVAILABLE:
        return None

    if auth_method not in ("oidc", "openshift"):
        return None

    auth_params: dict = {
        "method": auth_method,
        "verify_ssl": verify_ssl,
    }

    if k8s_api_host is not None:
        auth_params["k8s_api_host"] = k8s_api_host
    if ca_cert is not None:
        auth_params["ca_cert"] = ca_cert

    if auth_method == "oidc":
        if not oidc_issuer or not client_id:
            return None
        auth_params["oidc_issuer"] = oidc_issuer
        auth_params["client_id"] = client_id
        if client_secret is not None:
            auth_params["client_secret"] = client_secret
        auth_params["use_device_flow"] = use_device_flow
        auth_params["use_client_credentials"] = use_client_credentials
        auth_params["oidc_callback_port"] = oidc_callback_port
        if scopes is not None:
            auth_params["scopes"] = scopes

    auth_params["use_keyring"] = use_keyring

    try:
        auth_config = AuthConfig(**auth_params)
        factory = AuthFactory(auth_config)
        strategy = factory.get_strategy()
        strategy.authenticate()
        logger.debug("Authenticated via kube-authkit %s strategy", auth_method)
        return _KubeAuthkitAdapter(strategy)
    except Exception:
        logger.debug("kube-authkit %s strategy failed", auth_method, exc_info=True)
        return None


def _try_credentials_from_env(
    *, verify_ssl: bool = True, ca_cert: str | None = None,
) -> TokenCredentialsBase | None:
    """Attempt to build OIDC credentials from environment variables."""
    if not KUBE_AUTHKIT_AVAILABLE:
        return None

    issuer = os.getenv("KUBEFLOW_OIDC_ISSUER") or os.getenv("AUTHKIT_OIDC_ISSUER")
    cid = os.getenv("KUBEFLOW_OIDC_CLIENT_ID") or os.getenv("AUTHKIT_CLIENT_ID")
    if not issuer or not cid:
        return None

    secret = os.getenv("KUBEFLOW_OIDC_CLIENT_SECRET") or os.getenv("AUTHKIT_CLIENT_SECRET")
    if not secret:
        logger.info(
            "OIDC issuer and client ID found in env but client secret is missing -- "
            "skipping OIDC env var auth."
        )
        return None

    host = os.getenv("KUBEFLOW_API_HOST") or os.getenv("AUTHKIT_API_HOST")

    try:
        auth_config = AuthConfig(
            method="oidc",
            oidc_issuer=issuer,
            client_id=cid,
            client_secret=secret,
            use_client_credentials=True,
            verify_ssl=verify_ssl,
            **({"ca_cert": ca_cert} if ca_cert else {}),
            **({"k8s_api_host": host} if host else {}),
        )
        factory = AuthFactory(auth_config)
        strategy = factory.get_strategy()
        strategy.authenticate()
        logger.debug("Authenticated via kube-authkit OIDC from env vars")
        return _KubeAuthkitAdapter(strategy)
    except Exception:
        logger.debug("kube-authkit OIDC from env vars failed", exc_info=True)
        return None
