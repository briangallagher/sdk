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

"""Tests for the auth resolution chain and resolve_credentials."""

from __future__ import annotations

from unittest.mock import patch

import pytest
import responses

from kubeflow.common.auth.resolution import load_kubernetes_config, resolve_credentials

ISSUER = "https://keycloak.example.com/realms/test"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"

DISCOVERY_RESPONSE = {
    "issuer": ISSUER,
    "token_endpoint": TOKEN_ENDPOINT,
    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
    "device_authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth/device",
}
TOKEN_RESPONSE = {
    "access_token": "test-access-token",
    "refresh_token": "test-refresh-token",
    "expires_in": 300,
    "token_type": "Bearer",
}


class TestTokenAuth:
    def test_token_builds_client(self):
        from kubernetes.client import Configuration

        api_client = load_kubernetes_config(
            token="test-token",
            server="https://api.cluster:6443",
        )
        assert api_client.configuration.host == "https://api.cluster:6443"
        assert api_client.configuration.refresh_api_key_hook is not None

        cfg = Configuration()
        api_client.configuration.refresh_api_key_hook(cfg)
        assert cfg.api_key["authorization"] == "test-token"
        assert cfg.api_key_prefix["authorization"] == "Bearer"

    def test_missing_server_raises(self):
        with pytest.raises(ValueError, match="server"):
            load_kubernetes_config(token="test-token")

    def test_server_from_env(self):
        with patch.dict("os.environ", {"KUBEFLOW_API_HOST": "https://from-env:6443"}):
            api_client = load_kubernetes_config(token="test-token")
        assert api_client.configuration.host == "https://from-env:6443"


class TestCredentialsAuth:
    @responses.activate
    def test_credentials_wires_hook(self):
        responses.add(responses.GET, DISCOVERY_URL, json=DISCOVERY_RESPONSE)
        responses.add(responses.POST, TOKEN_ENDPOINT, json=TOKEN_RESPONSE)

        from kubeflow.common.auth import OIDCClientCredentials

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test-client",
            client_secret="test-secret",
        )
        api_client = load_kubernetes_config(
            credentials=creds,
            server="https://api.cluster:6443",
        )
        assert api_client.configuration.host == "https://api.cluster:6443"
        assert api_client.configuration.refresh_api_key_hook is not None

    def test_credentials_missing_server_raises(self):
        creds_stub = type(
            "FakeCreds",
            (),
            {
                "refresh_api_key_hook": lambda self, c: None,
                "get_token": lambda self: "t",
            },
        )()
        with pytest.raises(ValueError, match="server"):
            load_kubernetes_config(credentials=creds_stub)


class TestEnvVarAuth:
    @responses.activate
    def test_oidc_env_vars_construct_client(self):
        responses.add(responses.GET, DISCOVERY_URL, json=DISCOVERY_RESPONSE)
        responses.add(responses.POST, TOKEN_ENDPOINT, json=TOKEN_RESPONSE)

        with patch.dict(
            "os.environ",
            {
                "KUBEFLOW_OIDC_ISSUER": ISSUER,
                "KUBEFLOW_OIDC_CLIENT_ID": "env-client",
                "KUBEFLOW_OIDC_CLIENT_SECRET": "env-secret",
                "KUBEFLOW_API_HOST": "https://api.cluster:6443",
            },
        ):
            api_client = load_kubernetes_config()

        assert api_client.configuration.host == "https://api.cluster:6443"
        assert api_client.configuration.refresh_api_key_hook is not None

    def test_token_env_vars(self):
        from kubernetes.client import Configuration

        with patch.dict(
            "os.environ",
            {
                "KUBEFLOW_TOKEN": "env-token",
                "KUBEFLOW_API_HOST": "https://api.cluster:6443",
            },
        ):
            api_client = load_kubernetes_config()

        assert api_client.configuration.host == "https://api.cluster:6443"
        assert api_client.configuration.refresh_api_key_hook is not None

        cfg = Configuration()
        api_client.configuration.refresh_api_key_hook(cfg)
        assert cfg.api_key["authorization"] == "env-token"


class TestTLS:
    def test_verify_ssl_false(self):
        api_client = load_kubernetes_config(
            token="t",
            server="https://s:6443",
            verify_ssl=False,
        )
        assert api_client.configuration.verify_ssl is False

    def test_ca_cert(self):
        api_client = load_kubernetes_config(
            token="t",
            server="https://s:6443",
            ca_cert="/path/to/ca.crt",
        )
        assert api_client.configuration.ssl_ca_cert == "/path/to/ca.crt"


# ---------------------------------------------------------------------------
# resolve_credentials — shared credential resolution for K8s and REST
# ---------------------------------------------------------------------------


class TestResolveCredentials:
    """resolve_credentials returns a TokenCredentialsBase or None."""

    def test_explicit_credentials_returned_as_is(self):
        class MyCreds:
            def refresh_api_key_hook(self, config):
                pass

            def get_token(self):
                return "custom"

        creds = MyCreds()
        result = resolve_credentials(credentials=creds)
        assert result is creds

    def test_explicit_token_wraps_as_static(self):
        result = resolve_credentials(token="my-static-token")
        assert result is not None
        assert result.get_token() == "my-static-token"

    @responses.activate
    def test_oidc_env_vars_return_credentials(self):
        responses.add(responses.GET, DISCOVERY_URL, json=DISCOVERY_RESPONSE)

        with patch.dict(
            "os.environ",
            {
                "KUBEFLOW_OIDC_ISSUER": ISSUER,
                "KUBEFLOW_OIDC_CLIENT_ID": "env-client",
                "KUBEFLOW_OIDC_CLIENT_SECRET": "env-secret",
            },
        ):
            result = resolve_credentials()

        assert result is not None
        assert hasattr(result, "refresh_api_key_hook")
        assert hasattr(result, "get_token")

    def test_kubeflow_token_env_returns_static(self):
        with patch.dict("os.environ", {"KUBEFLOW_TOKEN": "env-tok"}):
            result = resolve_credentials()

        assert result is not None
        assert result.get_token() == "env-tok"

    def test_nothing_available_returns_none(self):
        with patch.dict("os.environ", {}, clear=True):
            result = resolve_credentials()

        assert result is None

    def test_explicit_credentials_takes_priority_over_env(self):
        class MyCreds:
            def refresh_api_key_hook(self, config):
                pass

            def get_token(self):
                return "explicit"

        creds = MyCreds()
        with patch.dict("os.environ", {"KUBEFLOW_TOKEN": "env-tok"}):
            result = resolve_credentials(credentials=creds)

        assert result is creds

    def test_explicit_token_takes_priority_over_env(self):
        with patch.dict("os.environ", {"KUBEFLOW_TOKEN": "env-tok"}):
            result = resolve_credentials(token="explicit-tok")

        assert result is not None
        assert result.get_token() == "explicit-tok"

    def test_static_credentials_hook_writes_bearer(self):
        """Static token credentials also satisfy refresh_api_key_hook."""
        from kubernetes.client import Configuration

        result = resolve_credentials(token="hook-test-token")
        assert result is not None

        config = Configuration()
        result.refresh_api_key_hook(config)
        assert config.api_key["authorization"] == "hook-test-token"
        assert config.api_key_prefix["authorization"] == "Bearer"


class TestResolveCredentialsRestWrapper:
    """Demonstrates resolve_credentials used by REST wrappers."""

    @responses.activate
    def test_rest_wrapper_pattern_with_oidc_env(self):
        """A REST wrapper resolves creds from env and calls get_token()."""
        responses.add(responses.GET, DISCOVERY_URL, json=DISCOVERY_RESPONSE)
        responses.add(responses.POST, TOKEN_ENDPOINT, json=TOKEN_RESPONSE)

        with patch.dict(
            "os.environ",
            {
                "KUBEFLOW_OIDC_ISSUER": ISSUER,
                "KUBEFLOW_OIDC_CLIENT_ID": "env-client",
                "KUBEFLOW_OIDC_CLIENT_SECRET": "env-secret",
            },
        ):
            creds = resolve_credentials()

        assert creds is not None
        token = creds.get_token()
        assert token == "test-access-token"

    def test_rest_wrapper_pattern_with_static_token(self):
        """A REST wrapper resolves a static token from env."""
        with patch.dict("os.environ", {"KUBEFLOW_TOKEN": "static-rest-token"}):
            creds = resolve_credentials()

        assert creds is not None
        assert creds.get_token() == "static-rest-token"
