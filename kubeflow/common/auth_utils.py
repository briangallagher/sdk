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

"""Shared authentication initialization for Kubernetes backends."""

import logging
import os

from kubernetes import client, config

from kubeflow.common.types import KubernetesBackendConfig
import kubeflow.common.utils as common_utils

logger = logging.getLogger(__name__)


def load_kubernetes_config(cfg: KubernetesBackendConfig) -> client.ApiClient:
    """Build a Kubernetes ApiClient from the backend configuration.

    Resolution order:
    1. Pre-built client_configuration (escape hatch)
    2. Pluggable credentials with server URL
    3. Explicit token + server
    4. KUBEFLOW_TOKEN / KUBEFLOW_API_HOST env vars
    5. KUBEFLOW_OIDC_* env vars (client credentials grant)
    6. Kubeconfig file (external or default)
    7. In-cluster service account
    """
    if cfg.client_configuration is not None:
        return client.ApiClient(cfg.client_configuration)

    if cfg.credentials and cfg.server:
        conf = client.Configuration()
        conf.host = cfg.server
        conf.verify_ssl = cfg.verify_ssl
        if cfg.ca_cert:
            conf.ssl_ca_cert = cfg.ca_cert
        conf.refresh_api_key_hook = cfg.credentials.refresh_api_key_hook
        return client.ApiClient(conf)

    if cfg.token and cfg.server:
        conf = client.Configuration()
        conf.api_key["authorization"] = cfg.token
        conf.api_key_prefix["authorization"] = "Bearer"
        conf.host = cfg.server
        conf.verify_ssl = cfg.verify_ssl
        if cfg.ca_cert:
            conf.ssl_ca_cert = cfg.ca_cert
        return client.ApiClient(conf)

    token_env = os.getenv("KUBEFLOW_TOKEN")
    host_env = os.getenv("KUBEFLOW_API_HOST")
    if token_env and host_env:
        logger.debug("Using KUBEFLOW_TOKEN env var for authentication")
        conf = client.Configuration()
        conf.api_key["authorization"] = token_env
        conf.api_key_prefix["authorization"] = "Bearer"
        conf.host = host_env
        conf.verify_ssl = cfg.verify_ssl
        return client.ApiClient(conf)

    oidc_issuer = os.getenv("KUBEFLOW_OIDC_ISSUER")
    oidc_client_id = os.getenv("KUBEFLOW_OIDC_CLIENT_ID")
    if oidc_issuer and oidc_client_id and host_env:
        logger.debug("Using KUBEFLOW_OIDC_* env vars for OIDC client credentials")
        from kubeflow.common.auth.oidc import OIDCClientCredentials

        creds = OIDCClientCredentials(
            issuer_url=oidc_issuer,
            client_id=oidc_client_id,
            client_secret=os.getenv("KUBEFLOW_OIDC_CLIENT_SECRET", ""),
        )
        conf = client.Configuration()
        conf.host = host_env
        conf.verify_ssl = cfg.verify_ssl
        conf.refresh_api_key_hook = creds.refresh_api_key_hook
        return client.ApiClient(conf)

    if cfg.config_file or not common_utils.is_running_in_k8s():
        config.load_kube_config(config_file=cfg.config_file, context=cfg.context)
    else:
        config.load_incluster_config()

    return client.ApiClient(cfg.client_configuration)
