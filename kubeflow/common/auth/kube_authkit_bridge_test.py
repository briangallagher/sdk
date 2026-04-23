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

"""Tests for kubeflow.common.auth — bridge, resolution, adapter, identity."""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
from kubernetes import client

from kubeflow.common.auth.identity import identity_annotations
from kubeflow.common.auth.kube_authkit_bridge import (
    _KubeAuthkitAdapter,
    _StaticTokenCredentials,
    _build_client_with_credentials,
    get_kubernetes_client,
    load_kubernetes_config,
    resolve_credentials,
)
from kubeflow.common.auth.types import TokenCredentialsBase
from kubeflow.common.types import KubernetesBackendConfig


# ---------------------------------------------------------------------------
# TokenCredentialsBase protocol compliance
# ---------------------------------------------------------------------------

class TestTokenCredentialsBaseProtocol:
    def test_static_token_satisfies_protocol(self):
        creds = _StaticTokenCredentials("tok")
        assert isinstance(creds, TokenCredentialsBase)

    def test_adapter_satisfies_protocol(self):
        strategy = MagicMock()
        strategy.get_token.return_value = "tok"
        adapter = _KubeAuthkitAdapter(strategy)
        assert isinstance(adapter, TokenCredentialsBase)

    def test_custom_object_satisfies_protocol(self):
        class MyCreds:
            def refresh_api_key_hook(self, config):
                pass
            def get_token(self):
                return "x"
        assert isinstance(MyCreds(), TokenCredentialsBase)


# ---------------------------------------------------------------------------
# _StaticTokenCredentials
# ---------------------------------------------------------------------------

class TestStaticTokenCredentials:
    def test_get_token(self):
        creds = _StaticTokenCredentials("my-token")
        assert creds.get_token() == "my-token"

    def test_refresh_api_key_hook_updates_config(self):
        creds = _StaticTokenCredentials("my-token")
        cfg = client.Configuration()
        creds.refresh_api_key_hook(cfg)
        assert cfg.api_key["authorization"] == "my-token"
        assert cfg.api_key_prefix["authorization"] == "Bearer"


# ---------------------------------------------------------------------------
# _KubeAuthkitAdapter
# ---------------------------------------------------------------------------

class TestKubeAuthkitAdapter:
    def test_get_token_delegates(self):
        strategy = MagicMock()
        strategy.get_token.return_value = "delegated-tok"
        adapter = _KubeAuthkitAdapter(strategy)
        assert adapter.get_token() == "delegated-tok"
        strategy.get_token.assert_called_once()

    def test_refresh_api_key_hook_delegates(self):
        strategy = MagicMock()
        strategy.get_token.return_value = "refreshed-tok"
        adapter = _KubeAuthkitAdapter(strategy)
        cfg = client.Configuration()
        adapter.refresh_api_key_hook(cfg)
        assert cfg.api_key["authorization"] == "refreshed-tok"
        assert cfg.api_key_prefix["authorization"] == "Bearer"


# ---------------------------------------------------------------------------
# _build_client_with_credentials
# ---------------------------------------------------------------------------

class TestBuildClientWithCredentials:
    def test_wires_hook_and_server(self):
        creds = _StaticTokenCredentials("tok")
        api_client = _build_client_with_credentials(
            creds, "https://api.test:6443"
        )
        assert isinstance(api_client, client.ApiClient)
        assert api_client.configuration.host == "https://api.test:6443"
        assert api_client.configuration.refresh_api_key_hook is not None
        # Verify the hook actually works by calling it
        api_client.configuration.refresh_api_key_hook(api_client.configuration)
        assert api_client.configuration.api_key["authorization"] == "tok"

    def test_ca_cert_and_verify_ssl(self):
        creds = _StaticTokenCredentials("tok")
        api_client = _build_client_with_credentials(
            creds, "https://api.test:6443",
            verify_ssl=False, ca_cert="/tmp/ca.pem",
        )
        assert api_client.configuration.verify_ssl is False
        assert api_client.configuration.ssl_ca_cert == "/tmp/ca.pem"


# ---------------------------------------------------------------------------
# resolve_credentials
# ---------------------------------------------------------------------------

class TestResolveCredentials:
    def test_explicit_credentials_returned_as_is(self):
        creds = _StaticTokenCredentials("explicit")
        result = resolve_credentials(credentials=creds)
        assert result is creds

    def test_explicit_token_wrapped(self):
        result = resolve_credentials(token="my-token")
        assert isinstance(result, _StaticTokenCredentials)
        assert result.get_token() == "my-token"

    def test_credentials_takes_priority_over_token(self):
        creds = _StaticTokenCredentials("creds")
        result = resolve_credentials(credentials=creds, token="token")
        assert result is creds

    @patch.dict("os.environ", {"KUBEFLOW_TOKEN": "env-tok"}, clear=False)
    def test_kubeflow_token_env_fallback(self):
        result = resolve_credentials()
        assert result is not None
        assert result.get_token() == "env-tok"

    @patch.dict("os.environ", {"AUTHKIT_TOKEN": "authkit-tok"}, clear=False)
    def test_authkit_token_env_fallback(self):
        result = resolve_credentials()
        assert result is not None
        assert result.get_token() == "authkit-tok"

    @patch.dict("os.environ", {}, clear=True)
    def test_returns_none_when_nothing_available(self):
        result = resolve_credentials()
        assert result is None


# ---------------------------------------------------------------------------
# load_kubernetes_config
# ---------------------------------------------------------------------------

class TestLoadKubernetesConfig:
    def test_client_configuration_passthrough(self):
        cfg = client.Configuration()
        cfg.host = "https://example.test:6443"
        result = load_kubernetes_config(client_configuration=cfg)
        assert isinstance(result, client.ApiClient)
        assert result.configuration.host == "https://example.test:6443"

    def test_token_with_server(self):
        result = load_kubernetes_config(
            token="my-token", server="https://api.test:6443"
        )
        assert isinstance(result, client.ApiClient)
        assert result.configuration.host == "https://api.test:6443"
        assert result.configuration.refresh_api_key_hook is not None

    def test_token_without_server_raises(self):
        with pytest.raises(ValueError, match="server"):
            load_kubernetes_config(token="tok")

    def test_credentials_with_server(self):
        creds = _StaticTokenCredentials("creds-tok")
        result = load_kubernetes_config(
            credentials=creds, server="https://api.test:6443"
        )
        assert isinstance(result, client.ApiClient)
        assert result.configuration.refresh_api_key_hook is not None
        result.configuration.refresh_api_key_hook(result.configuration)
        assert result.configuration.api_key["authorization"] == "creds-tok"

    @patch("kubeflow.common.auth.kube_authkit_bridge.config.load_kube_config")
    def test_kubeconfig_fallback(self, mock_load):
        mock_load.return_value = None
        result = load_kubernetes_config(config_file="/path/config")
        assert isinstance(result, client.ApiClient)
        mock_load.assert_called_once_with(config_file="/path/config", context=None)

    @patch("kubeflow.common.auth.kube_authkit_bridge.config.load_kube_config")
    @patch("kubeflow.common.auth.kube_authkit_bridge.config.load_incluster_config")
    def test_incluster_fallback(self, mock_incluster, mock_kube):
        from kubernetes.config import ConfigException
        mock_kube.side_effect = ConfigException("no config")
        mock_incluster.return_value = None
        result = load_kubernetes_config()
        assert isinstance(result, client.ApiClient)
        mock_incluster.assert_called_once()

    @patch("kubeflow.common.auth.kube_authkit_bridge.config.load_kube_config")
    @patch("kubeflow.common.auth.kube_authkit_bridge.config.load_incluster_config")
    def test_all_fallbacks_fail_raises_runtime_error(self, mock_incluster, mock_kube):
        from kubernetes.config import ConfigException
        mock_kube.side_effect = ConfigException("no config")
        mock_incluster.side_effect = ConfigException("not in cluster")
        with pytest.raises(RuntimeError, match="Could not configure"):
            load_kubernetes_config()


# ---------------------------------------------------------------------------
# get_kubernetes_client
# ---------------------------------------------------------------------------

class TestGetKubernetesClient:
    def test_prebuilt_client_configuration(self):
        cfg_obj = client.Configuration()
        cfg_obj.host = "https://example:6443"
        backend = KubernetesBackendConfig(client_configuration=cfg_obj)
        result = get_kubernetes_client(backend)
        assert isinstance(result, client.ApiClient)

    def test_token_and_server(self):
        backend = KubernetesBackendConfig(
            token="tok", server="https://api.test:6443"
        )
        result = get_kubernetes_client(backend)
        assert isinstance(result, client.ApiClient)

    def test_credentials_field(self):
        creds = _StaticTokenCredentials("creds-tok")
        backend = KubernetesBackendConfig(
            credentials=creds, server="https://api.test:6443"
        )
        result = get_kubernetes_client(backend)
        assert isinstance(result, client.ApiClient)
        assert result.configuration.refresh_api_key_hook is not None
        result.configuration.refresh_api_key_hook(result.configuration)
        assert result.configuration.api_key["authorization"] == "creds-tok"

    @patch("kubeflow.common.auth.kube_authkit_bridge.config.load_kube_config")
    def test_legacy_config_file(self, mock_load):
        mock_load.return_value = None
        backend = KubernetesBackendConfig(config_file="/path/config")
        result = get_kubernetes_client(backend)
        assert isinstance(result, client.ApiClient)

    @patch("kubeflow.common.auth.kube_authkit_bridge.config.load_kube_config")
    def test_default_auto_detection(self, mock_load):
        mock_load.return_value = None
        backend = KubernetesBackendConfig()
        result = get_kubernetes_client(backend)
        assert isinstance(result, client.ApiClient)


# ---------------------------------------------------------------------------
# identity_annotations
# ---------------------------------------------------------------------------

def _make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).rstrip(b"=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    sig = base64.urlsafe_b64encode(b"fake-signature").rstrip(b"=")
    return f"{header.decode()}.{body.decode()}.{sig.decode()}"


class TestIdentityAnnotations:
    def test_full_claims(self):
        token = _make_jwt({
            "sub": "user-123",
            "email": "user@example.com",
            "preferred_username": "jdoe",
            "groups": ["team-a", "team-b"],
        })
        result = identity_annotations(token)
        assert result["kubeflow.org/user-id"] == "user-123"
        assert result["kubeflow.org/user-email"] == "user@example.com"
        assert result["kubeflow.org/user-name"] == "jdoe"
        assert result["kubeflow.org/user-groups"] == "team-a,team-b"

    def test_partial_claims(self):
        token = _make_jwt({"sub": "user-456"})
        result = identity_annotations(token)
        assert result == {"kubeflow.org/user-id": "user-456"}

    def test_empty_payload(self):
        token = _make_jwt({})
        result = identity_annotations(token)
        assert result == {}

    def test_invalid_token_returns_empty(self):
        result = identity_annotations("not-a-jwt")
        assert result == {}

    def test_groups_as_single_string(self):
        token = _make_jwt({"groups": ["admins"]})
        result = identity_annotations(token)
        assert result["kubeflow.org/user-groups"] == "admins"


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------

class TestBackwardCompatibility:
    """Ensure old config_file / context patterns still work."""

    @patch("kubeflow.common.auth.kube_authkit_bridge.config.load_kube_config")
    def test_config_file_and_context(self, mock_load):
        mock_load.return_value = None
        backend = KubernetesBackendConfig(
            config_file="/legacy/config", context="my-ctx"
        )
        result = get_kubernetes_client(backend)
        assert isinstance(result, client.ApiClient)
        mock_load.assert_called_once_with(
            config_file="/legacy/config", context="my-ctx"
        )

    def test_verify_ssl_default_true(self):
        backend = KubernetesBackendConfig()
        assert backend.verify_ssl is True

    def test_new_fields_default_none(self):
        backend = KubernetesBackendConfig()
        assert backend.credentials is None
        assert backend.server is None
        assert backend.use_client_credentials is False
