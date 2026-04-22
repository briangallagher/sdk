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

"""Kubernetes client configuration and credential resolution with OIDC support.

Provides two public functions:

- ``resolve_credentials`` — resolves a ``TokenCredentialsBase`` from explicit
  arguments or environment variables.  Usable by both K8s and REST wrappers.
- ``load_kubernetes_config`` — builds a Kubernetes ``ApiClient`` using the
  resolved credentials, kubeconfig, or in-cluster service account.
"""

from __future__ import annotations

import logging
import os

from kubernetes import client, config

from .types import TokenCredentialsBase

logger = logging.getLogger(__name__)


def resolve_credentials(
    *,
    credentials: TokenCredentialsBase | None = None,
    token: str | None = None,
    verify_ssl: bool = True,
    ca_cert: str | None = None,
) -> TokenCredentialsBase | None:
    """Resolve a ``TokenCredentialsBase`` from explicit args or environment.

    This is the shared credential resolution that both K8s and REST wrappers
    use.  It answers: *given what the user provided (or what the environment
    contains), return a credentials object — or None if nothing is available.*

    Resolution order:

    1. Explicit ``credentials`` object (returned as-is)
    2. Explicit ``token`` → wrapped in a ``_StaticTokenCredentials``
    3. ``KUBEFLOW_OIDC_*`` env vars → ``OIDCClientCredentials``
    4. ``KUBEFLOW_TOKEN`` env var → ``_StaticTokenCredentials``
    5. ``None`` (nothing found)

    REST wrappers call ``creds.get_token()`` on the result.  K8s wrappers
    pass the result to ``load_kubernetes_config(credentials=...)``.
    """
    if credentials is not None:
        return credentials

    if token is not None:
        return _StaticTokenCredentials(token)

    oidc_creds = _try_oidc_creds_from_env(verify_ssl=verify_ssl, ca_cert=ca_cert)
    if oidc_creds is not None:
        return oidc_creds

    token_env = os.getenv("KUBEFLOW_TOKEN")
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
    verify_ssl: bool = True,
    ca_cert: str | None = None,
) -> client.ApiClient:
    """Build a Kubernetes ``ApiClient`` with flexible auth options.

    Resolution order:

    1. Explicit ``client_configuration`` (pass-through, no changes)
    2. Pluggable ``credentials`` object (any ``TokenCredentialsBase``)
    3. Explicit ``token`` + ``server``
    4. ``KUBEFLOW_OIDC_*`` environment variables → auto-constructed credentials
    5. ``KUBEFLOW_TOKEN`` + ``KUBEFLOW_API_HOST`` environment variables
    6. Kubeconfig file (``config_file`` / ``context`` / default)
    7. In-cluster service account
    """
    if client_configuration is not None:
        return client.ApiClient(configuration=client_configuration)

    resolved = resolve_credentials(
        credentials=credentials,
        token=token,
        verify_ssl=verify_ssl,
        ca_cert=ca_cert,
    )

    if resolved is not None:
        if server is None:
            server = os.getenv("KUBEFLOW_API_HOST")
        if server is None:
            raise ValueError(
                "'server' is required when using credentials or token. "
                "Set it directly or via KUBEFLOW_API_HOST."
            )
        return _build_client_with_credentials(
            resolved,
            server,
            verify_ssl=verify_ssl,
            ca_cert=ca_cert,
        )

    try:
        config.load_kube_config(
            config_file=config_file,
            context=context,
        )
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


class _StaticTokenCredentials:
    """Wraps a static token string as a ``TokenCredentialsBase``."""

    def __init__(self, token: str) -> None:
        self._token = token

    def refresh_api_key_hook(self, config: client.Configuration) -> None:
        config.api_key["authorization"] = self._token
        config.api_key_prefix["authorization"] = "Bearer"

    def get_token(self) -> str:
        return self._token


def _try_oidc_creds_from_env(
    *,
    verify_ssl: bool = True,
    ca_cert: str | None = None,
) -> TokenCredentialsBase | None:
    """Attempt to build OIDC credentials from environment variables."""
    issuer = os.getenv("KUBEFLOW_OIDC_ISSUER")
    client_id = os.getenv("KUBEFLOW_OIDC_CLIENT_ID")
    if not issuer or not client_id:
        return None

    from .oidc import OIDCClientCredentials

    client_secret = os.getenv("KUBEFLOW_OIDC_CLIENT_SECRET", "")
    if not client_secret:
        logger.info(
            "KUBEFLOW_OIDC_ISSUER and KUBEFLOW_OIDC_CLIENT_ID are set but "
            "KUBEFLOW_OIDC_CLIENT_SECRET is missing — skipping OIDC env var auth. "
            "Set KUBEFLOW_OIDC_CLIENT_SECRET to enable automatic OIDC authentication."
        )
        return None

    return OIDCClientCredentials(
        issuer_url=issuer,
        client_id=client_id,
        client_secret=client_secret,
        verify=ca_cert if ca_cert else verify_ssl,
    )
