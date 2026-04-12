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

"""Authentication bridge between KubernetesBackendConfig and kube-authkit."""

# Kubeflow backends share KubernetesBackendConfig; kube-authkit expects AuthConfig.
# This file maps between those shapes and picks a resolution strategy. Token exchange,
# kubeconfig parsing, and ApiClient construction live in kube-authkit, not here.

import logging

from kubernetes import client

from kubeflow.common.types import KubernetesBackendConfig

try:
    from kube_authkit import AuthConfig, get_k8s_client as kube_authkit_get_client

    KUBE_AUTHKIT_AVAILABLE = True
except ImportError:
    KUBE_AUTHKIT_AVAILABLE = False

logger = logging.getLogger(__name__)


def get_kubernetes_client(cfg: KubernetesBackendConfig) -> client.ApiClient:
    """Build a Kubernetes ApiClient using kube-authkit.

    Resolution order (first match wins after the import guard):

    1. **Pre-built ``client_configuration``** — caller already has a
       ``kubernetes.client.Configuration`` (e.g. custom transport). Returned as
       ``ApiClient`` without invoking kube-authkit.

    2. **Explicit ``auth_method``** — OIDC, OpenShift token, kubeconfig path,
       in-cluster, etc. Backend-specific fields are folded into ``AuthConfig``;
       kube-authkit performs login and builds the client.

    3. **Legacy ``config_file`` / ``context``** — backward compatible with older
       Kubeflow SDK options. Emits a deprecation log; ``config_file`` is mapped to
       ``kubeconfig_path``. ``context`` is not forwarded (use kube-authkit-supported
       mechanisms via ``kubeconfig_path`` / explicit method instead).

    4. **Neither** — ``method="auto"`` so kube-authkit chooses how to authenticate.

    Raises:
        ImportError: If kube-authkit is not installed.
    """
    if not KUBE_AUTHKIT_AVAILABLE:
        raise ImportError(
            "kube-authkit is required for authentication. "
            "Install it with: pip install kube-authkit"
        )

    # Escape hatch: skip AuthConfig entirely when the caller owns Configuration.
    if cfg.client_configuration is not None:
        logger.debug("Using provided client_configuration")
        return client.ApiClient(cfg.client_configuration)

    # Common TLS / endpoint hints applied for any kube-authkit path below.
    auth_params: dict = {"verify_ssl": cfg.verify_ssl}

    if cfg.k8s_api_host is not None:
        auth_params["k8s_api_host"] = cfg.k8s_api_host
    if cfg.kubeconfig_path is not None:
        auth_params["kubeconfig_path"] = cfg.kubeconfig_path
    if cfg.ca_cert is not None:
        auth_params["ca_cert"] = cfg.ca_cert

    if cfg.auth_method is not None:
        auth_params["method"] = cfg.auth_method

        # OIDC-specific knobs; other methods ignore these keys if present in AuthConfig.
        if cfg.auth_method == "oidc":
            auth_params["oidc_issuer"] = cfg.oidc_issuer
            auth_params["client_id"] = cfg.client_id
            auth_params["client_secret"] = cfg.client_secret
            auth_params["use_device_flow"] = cfg.use_device_flow
            auth_params["oidc_callback_port"] = cfg.oidc_callback_port
            if cfg.scopes is not None:
                auth_params["scopes"] = cfg.scopes

        if cfg.auth_method == "openshift" and cfg.token is not None:
            auth_params["token"] = cfg.token

        auth_params["use_keyring"] = cfg.use_keyring

    elif cfg.config_file is not None or cfg.context is not None:
        logger.warning(
            "The 'config_file' and 'context' parameters are deprecated. "
            "Use 'kubeconfig_path' and 'auth_method=\"kubeconfig\"' instead."
        )
        auth_params["method"] = "kubeconfig"
        if cfg.config_file is not None:
            auth_params["kubeconfig_path"] = cfg.config_file

    else:
        auth_params["method"] = "auto"

    auth_config = AuthConfig(**auth_params)
    api_client = kube_authkit_get_client(auth_config)
    logger.debug("Authenticated via kube-authkit")
    return api_client
