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

"""End-to-end scenario tests for the unified auth system.

Each test simulates a real-world use case, using mocked HTTP responses.
Tests verify the complete flow from credential construction through to
K8s Configuration wiring and token retrieval.
"""

from __future__ import annotations

import base64
import json
import time
from unittest.mock import patch

from kubernetes.client import Configuration
import pytest
import responses

from kubeflow.common.auth import (
    OIDCClientCredentials,
    OIDCDeviceFlowCredentials,
    OIDCPasswordCredentials,
    TokenCredentialsBase,
    discover,
    extract_jwt_claims,
    identity_annotations,
    load_kubernetes_config,
)
from kubeflow.common.auth.errors import (
    AuthenticationError,
    DiscoveryError,
    InvalidCredentialsError,
    ProviderUnreachableError,
    TokenExchangeError,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

ISSUER = "https://keycloak.example.com/realms/test"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
AUTH_ENDPOINT = f"{ISSUER}/protocol/openid-connect/auth"
DEVICE_ENDPOINT = f"{ISSUER}/protocol/openid-connect/auth/device"
SERVER = "https://api.cluster:6443"

DISCOVERY_RESPONSE = {
    "issuer": ISSUER,
    "token_endpoint": TOKEN_ENDPOINT,
    "authorization_endpoint": AUTH_ENDPOINT,
    "device_authorization_endpoint": DEVICE_ENDPOINT,
}


def _make_jwt_token(payload: dict) -> str:
    """Build a minimal JWT (header.payload.signature) for testing."""
    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        .rstrip(b"=")
        .decode()
    )
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(b"fake-sig").rstrip(b"=").decode()
    return f"{header}.{body}.{sig}"


JWT_CLAIMS = {
    "sub": "user-123",
    "email": "alice@example.com",
    "preferred_username": "alice",
    "iss": ISSUER,
    "exp": int(time.time()) + 3600,
}
JWT_TOKEN = _make_jwt_token(JWT_CLAIMS)

TOKEN_RESPONSE = {
    "access_token": JWT_TOKEN,
    "refresh_token": "refresh-token-value",
    "expires_in": 300,
    "token_type": "Bearer",
}

REFRESHED_TOKEN = _make_jwt_token({**JWT_CLAIMS, "sub": "user-123-refreshed"})
REFRESHED_RESPONSE = {
    "access_token": REFRESHED_TOKEN,
    "refresh_token": "new-refresh-token",
    "expires_in": 300,
    "token_type": "Bearer",
}


def _register_discovery(rsps=None):
    """Register a standard discovery response."""
    target = rsps if rsps is not None else responses
    target.add(responses.GET, DISCOVERY_URL, json=DISCOVERY_RESPONSE)


def _register_token(token_resp=None, rsps=None):
    """Register a standard token endpoint response."""
    target = rsps if rsps is not None else responses
    target.add(responses.POST, TOKEN_ENDPOINT, json=token_resp or TOKEN_RESPONSE)


# ---------------------------------------------------------------------------
# AC1: OIDC token authentication
# ---------------------------------------------------------------------------


class TestAc1OidcTokenAuth:
    """AC1: OIDC token authentication — the system must obtain a bearer token
    from an OIDC provider and use it for K8s API calls."""

    @responses.activate
    def test_client_credentials_full_flow(self):
        """CI/CD pipeline with client credentials → K8s API call succeeds."""
        _register_discovery()
        _register_token()

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="ci-client",
            client_secret="ci-secret",
        )
        api_client = load_kubernetes_config(credentials=creds, server=SERVER)

        assert api_client.configuration.host == SERVER
        assert api_client.configuration.refresh_api_key_hook is not None

        config = Configuration()
        creds.refresh_api_key_hook(config)

        assert config.api_key["authorization"] == JWT_TOKEN
        assert config.api_key_prefix["authorization"] == "Bearer"

        body = responses.calls[1].request.body
        if isinstance(body, bytes):
            body = body.decode()
        assert "grant_type=client_credentials" in body
        assert "client_id=ci-client" in body
        assert "client_secret=ci-secret" in body

    @responses.activate
    def test_password_grant_full_flow(self):
        """Notebook with password grant → K8s API call succeeds."""
        _register_discovery()
        _register_token()

        creds = OIDCPasswordCredentials(
            issuer_url=ISSUER,
            client_id="notebook-client",
            username="alice",
            password="s3cret",
        )
        load_kubernetes_config(credentials=creds, server=SERVER)

        config = Configuration()
        creds.refresh_api_key_hook(config)

        assert config.api_key["authorization"] == JWT_TOKEN

        body = responses.calls[1].request.body
        if isinstance(body, bytes):
            body = body.decode()
        assert "grant_type=password" in body
        assert "username=alice" in body
        assert "password=s3cret" in body


# ---------------------------------------------------------------------------
# AC2: Automatic token refresh
# ---------------------------------------------------------------------------


class TestAc2AutomaticTokenRefresh:
    """AC2: Tokens must refresh transparently when they expire."""

    @responses.activate
    def test_expired_token_triggers_refresh_via_hook(self):
        """Token expires mid-session → hook refreshes transparently."""
        _register_discovery()
        _register_token()
        _register_token(REFRESHED_RESPONSE)

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test-client",
            client_secret="test-secret",
        )

        config = Configuration()
        creds.refresh_api_key_hook(config)
        assert config.api_key["authorization"] == JWT_TOKEN

        creds._expires_at = time.monotonic() - 1

        creds.refresh_api_key_hook(config)
        assert config.api_key["authorization"] == REFRESHED_TOKEN

    @responses.activate
    def test_expired_token_triggers_refresh_via_get_token(self):
        """get_token also refreshes when expired."""
        _register_discovery()
        _register_token()
        _register_token(REFRESHED_RESPONSE)

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test-client",
            client_secret="test-secret",
        )

        token1 = creds.get_token()
        assert token1 == JWT_TOKEN

        creds._expires_at = time.monotonic() - 1

        token2 = creds.get_token()
        assert token2 == REFRESHED_TOKEN

    @responses.activate
    def test_refresh_token_used_when_available(self):
        """Refresh token is sent in the refresh request body."""
        _register_discovery()
        _register_token()
        _register_token(REFRESHED_RESPONSE)

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test-client",
            client_secret="test-secret",
        )
        creds.get_token()
        creds._expires_at = time.monotonic() - 1
        creds.get_token()

        refresh_body = responses.calls[2].request.body
        if isinstance(refresh_body, bytes):
            refresh_body = refresh_body.decode()
        assert "grant_type=refresh_token" in refresh_body
        assert "refresh_token=refresh-token-value" in refresh_body

    @responses.activate
    def test_full_reexchange_when_refresh_fails(self):
        """Full re-exchange when refresh token fails."""
        _register_discovery()
        _register_token()
        responses.add(responses.POST, TOKEN_ENDPOINT, status=401)
        _register_token(REFRESHED_RESPONSE)

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test-client",
            client_secret="test-secret",
        )
        creds.get_token()
        creds._expires_at = time.monotonic() - 1
        token2 = creds.get_token()

        assert token2 == REFRESHED_TOKEN
        assert len(responses.calls) == 4  # discovery + token + failed refresh + re-exchange


# ---------------------------------------------------------------------------
# AC3: Identity propagation
# ---------------------------------------------------------------------------


class TestAc3IdentityPropagation:
    """AC3: JWT claims extracted for CRD annotations."""

    @responses.activate
    def test_get_token_to_claims_to_annotations(self):
        """Full pipeline: get_token → extract_jwt_claims → identity_annotations."""
        _register_discovery()
        _register_token()

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test-client",
            client_secret="test-secret",
        )
        token = creds.get_token()

        claims = extract_jwt_claims(token)
        assert claims["sub"] == "user-123"
        assert claims["email"] == "alice@example.com"

        annotations = identity_annotations(token)
        assert annotations["kubeflow.org/user-id"] == "user-123"
        assert annotations["kubeflow.org/user-email"] == "alice@example.com"
        assert annotations["kubeflow.org/user-name"] == "alice"


# ---------------------------------------------------------------------------
# AC4: Actionable auth errors
# ---------------------------------------------------------------------------


class TestAc4ActionableErrors:
    """AC4: Auth errors are specific and actionable, not raw HTTP errors."""

    @responses.activate
    def test_bad_credentials_raises_invalid_credentials(self):
        """Bad credentials → InvalidCredentialsError (not raw 401)."""
        _register_discovery()
        responses.add(responses.POST, TOKEN_ENDPOINT, status=401, json={"error": "invalid_client"})

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="bad-client",
            client_secret="bad-secret",
        )
        with pytest.raises(InvalidCredentialsError, match="rejected"):
            creds.get_token()

    @responses.activate
    def test_forbidden_raises_invalid_credentials(self):
        """403 from token endpoint → InvalidCredentialsError."""
        _register_discovery()
        responses.add(responses.POST, TOKEN_ENDPOINT, status=403)

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test-client",
            client_secret="test-secret",
        )
        with pytest.raises(InvalidCredentialsError):
            creds.get_token()

    @responses.activate
    def test_unreachable_idp_raises_provider_unreachable(self):
        """Unreachable IDP → ProviderUnreachableError."""
        responses.add(
            responses.GET,
            DISCOVERY_URL,
            body=ConnectionError("Connection refused"),
        )
        with pytest.raises(ProviderUnreachableError):
            OIDCClientCredentials(
                issuer_url=ISSUER,
                client_id="test-client",
                client_secret="test-secret",
            )

    @responses.activate
    def test_issuer_mismatch_raises_discovery_error(self):
        """Issuer mismatch → DiscoveryError."""
        bad_response = {**DISCOVERY_RESPONSE, "issuer": "https://evil.example.com"}
        responses.add(responses.GET, DISCOVERY_URL, json=bad_response)
        with pytest.raises(DiscoveryError, match="issuer mismatch"):
            discover(ISSUER)

    @responses.activate
    def test_token_exchange_500_raises_token_exchange_error(self):
        """Server error on token exchange → TokenExchangeError."""
        _register_discovery()
        responses.add(responses.POST, TOKEN_ENDPOINT, status=500)

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test-client",
            client_secret="test-secret",
        )
        with pytest.raises(TokenExchangeError):
            creds.get_token()

    @responses.activate
    def test_all_auth_errors_inherit_from_authentication_error(self):
        """All custom errors are AuthenticationError subclasses."""
        _register_discovery()
        responses.add(responses.POST, TOKEN_ENDPOINT, status=401)

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test-client",
            client_secret="test-secret",
        )
        with pytest.raises(AuthenticationError):
            creds.get_token()

    @responses.activate
    def test_token_endpoint_unreachable_raises_provider_unreachable(self):
        """Token endpoint unreachable → ProviderUnreachableError."""
        _register_discovery()
        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            body=ConnectionError("Connection refused"),
        )

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test-client",
            client_secret="test-secret",
        )
        with pytest.raises(ProviderUnreachableError):
            creds.get_token()


# ---------------------------------------------------------------------------
# AC5: Backward compatibility
# ---------------------------------------------------------------------------


class TestAc5BackwardCompatibility:
    """AC5: Existing usage patterns continue to work."""

    def test_load_with_token_and_server(self):
        """Existing token= and server= still work."""
        api_client = load_kubernetes_config(
            token="static-token",
            server="https://api.cluster:6443",
        )
        assert api_client.configuration.host == "https://api.cluster:6443"
        assert api_client.configuration.refresh_api_key_hook is not None

        config = Configuration()
        api_client.configuration.refresh_api_key_hook(config)
        assert config.api_key["authorization"] == "static-token"

    def test_backward_compat_import_from_auth_utils(self):
        """import from kubeflow.common.auth_utils still works."""
        from kubeflow.common.auth_utils import load_kubernetes_config as lkc

        api_client = lkc(token="t", server="https://s:6443")
        assert api_client.configuration.host == "https://s:6443"

    def test_backward_compat_import_from_common_types(self):
        """import TokenCredentialsBase from kubeflow.common.types still works."""
        from kubeflow.common.types import (  # noqa: N811
            TokenCredentialsBase as CredentialsFromTypes,
        )

        assert CredentialsFromTypes is TokenCredentialsBase


# ---------------------------------------------------------------------------
# AC7: Performance — cached tokens skip HTTP
# ---------------------------------------------------------------------------


class TestAc7Performance:
    """AC7: Second call with valid token does NOT make HTTP request."""

    @responses.activate
    def test_cached_token_no_http(self):
        """Second hook call with valid token skips HTTP."""
        _register_discovery()
        _register_token()

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test-client",
            client_secret="test-secret",
        )

        config = Configuration()
        creds.refresh_api_key_hook(config)
        call_count_after_first = len(responses.calls)

        creds.refresh_api_key_hook(config)
        assert len(responses.calls) == call_count_after_first

    @responses.activate
    def test_get_token_cached(self):
        """Second get_token call with valid token skips HTTP."""
        _register_discovery()
        _register_token()

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test-client",
            client_secret="test-secret",
        )

        creds.get_token()
        call_count = len(responses.calls)
        creds.get_token()
        assert len(responses.calls) == call_count


# ---------------------------------------------------------------------------
# R1: Token configuration
# ---------------------------------------------------------------------------


class TestR1TokenConfiguration:
    """R1: OIDCClientCredentials with all params → correct token endpoint call."""

    @responses.activate
    def test_all_params_passed_to_token_endpoint(self):
        _register_discovery()
        _register_token()

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="my-client",
            client_secret="my-secret",
            scopes=["openid", "profile"],
        )
        creds.get_token()

        body = responses.calls[1].request.body
        if isinstance(body, bytes):
            body = body.decode()
        assert "grant_type=client_credentials" in body
        assert "client_id=my-client" in body
        assert "client_secret=my-secret" in body
        assert "scope=openid" in body
        assert "profile" in body

    @responses.activate
    def test_verify_false_passed_through(self):
        """verify=False passes through to requests."""
        _register_discovery()
        _register_token()

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test",
            client_secret="test",
            verify=False,
        )
        creds.get_token()
        assert creds._verify is False

    @responses.activate
    def test_verify_ca_path_passed_through(self):
        """verify="/path/to/ca.crt" passes through to requests."""
        _register_discovery()
        _register_token()

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test",
            client_secret="test",
            verify="/path/to/ca.crt",
        )
        creds.get_token()
        assert creds._verify == "/path/to/ca.crt"


# ---------------------------------------------------------------------------
# R2: Explicit token injection
# ---------------------------------------------------------------------------


class TestR2ExplicitTokenInjection:
    """R2: load_kubernetes_config(token=, server=) → correct bearer header."""

    def test_static_token_wired_correctly(self):
        api_client = load_kubernetes_config(token="my-jwt-here", server=SERVER)
        cfg = api_client.configuration
        assert cfg.host == SERVER
        assert cfg.refresh_api_key_hook is not None

        test_cfg = Configuration()
        cfg.refresh_api_key_hook(test_cfg)
        assert test_cfg.api_key["authorization"] == "my-jwt-here"
        assert test_cfg.api_key_prefix["authorization"] == "Bearer"


# ---------------------------------------------------------------------------
# R3: Env var auth
# ---------------------------------------------------------------------------


class TestR3EnvVarAuth:
    """R3: Environment variable based authentication."""

    @responses.activate
    def test_oidc_env_vars_construct_working_client(self):
        """KUBEFLOW_OIDC_* env vars → OIDC client constructed and working."""
        _register_discovery()
        _register_token()

        with patch.dict(
            "os.environ",
            {
                "KUBEFLOW_OIDC_ISSUER": ISSUER,
                "KUBEFLOW_OIDC_CLIENT_ID": "env-client",
                "KUBEFLOW_OIDC_CLIENT_SECRET": "env-secret",
                "KUBEFLOW_API_HOST": SERVER,
            },
        ):
            api_client = load_kubernetes_config()

        assert api_client.configuration.host == SERVER
        assert api_client.configuration.refresh_api_key_hook is not None

    def test_token_env_vars_working(self):
        """KUBEFLOW_TOKEN + KUBEFLOW_API_HOST → static token working."""
        with patch.dict(
            "os.environ",
            {
                "KUBEFLOW_TOKEN": "env-token",
                "KUBEFLOW_API_HOST": SERVER,
            },
        ):
            api_client = load_kubernetes_config()

        assert api_client.configuration.refresh_api_key_hook is not None
        config = Configuration()
        api_client.configuration.refresh_api_key_hook(config)
        assert config.api_key["authorization"] == "env-token"

    @responses.activate
    def test_oidc_env_missing_secret_skips(self):
        """Missing CLIENT_SECRET falls through to next resolution strategy."""
        with patch.dict(
            "os.environ",
            {
                "KUBEFLOW_OIDC_ISSUER": ISSUER,
                "KUBEFLOW_OIDC_CLIENT_ID": "env-client",
                "KUBEFLOW_API_HOST": SERVER,
                "KUBEFLOW_TOKEN": "fallback-token",
            },
            clear=False,
        ):
            api_client = load_kubernetes_config()

        assert api_client.configuration.refresh_api_key_hook is not None
        config = Configuration()
        api_client.configuration.refresh_api_key_hook(config)
        assert config.api_key["authorization"] == "fallback-token"


# ---------------------------------------------------------------------------
# R4: TLS / custom CA
# ---------------------------------------------------------------------------


class TestR4TlsCustomCa:
    """R4: TLS verification options pass through correctly."""

    def test_verify_false_in_k8s_config(self):
        api_client = load_kubernetes_config(
            token="t",
            server=SERVER,
            verify_ssl=False,
        )
        assert api_client.configuration.verify_ssl is False

    def test_ca_cert_in_k8s_config(self):
        api_client = load_kubernetes_config(
            token="t",
            server=SERVER,
            ca_cert="/path/to/ca.crt",
        )
        assert api_client.configuration.ssl_ca_cert == "/path/to/ca.crt"


# ---------------------------------------------------------------------------
# R5: Pluggable credentials
# ---------------------------------------------------------------------------


class TestR5PluggableCredentials:
    """R5: Custom TokenCredentialsBase implementation → works with load_kubernetes_config."""

    def test_custom_protocol_implementation(self):
        class MyCustomAuth:
            def refresh_api_key_hook(self, config: Configuration) -> None:
                config.api_key["authorization"] = "custom-token"
                config.api_key_prefix["authorization"] = "Bearer"

            def get_token(self) -> str:
                return "custom-token"

        creds = MyCustomAuth()
        assert isinstance(creds, TokenCredentialsBase)

        api_client = load_kubernetes_config(credentials=creds, server=SERVER)
        assert api_client.configuration.refresh_api_key_hook is not None

        config = Configuration()
        creds.refresh_api_key_hook(config)
        assert config.api_key["authorization"] == "custom-token"


# ---------------------------------------------------------------------------
# R6: Client credentials grant (full flow)
# ---------------------------------------------------------------------------


class TestR6ClientCredentialsGrant:
    """R6: Full flow: discover → exchange → get bearer token."""

    @responses.activate
    def test_full_client_credentials_flow(self):
        _register_discovery()
        _register_token()

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="ci-client",
            client_secret="ci-secret",
        )

        assert len(responses.calls) == 1
        assert responses.calls[0].request.url == DISCOVERY_URL

        token = creds.get_token()
        assert token == JWT_TOKEN

        assert len(responses.calls) == 2
        assert responses.calls[1].request.url == TOKEN_ENDPOINT


# ---------------------------------------------------------------------------
# R7: Password grant (full flow)
# ---------------------------------------------------------------------------


class TestR7PasswordGrant:
    """R7: Full flow: discover → exchange with username/password → get bearer token."""

    @responses.activate
    def test_full_password_flow(self):
        _register_discovery()
        _register_token()

        creds = OIDCPasswordCredentials(
            issuer_url=ISSUER,
            client_id="notebook-client",
            username="alice",
            password="password123",
        )
        token = creds.get_token()
        assert token == JWT_TOKEN

        body = responses.calls[1].request.body
        if isinstance(body, bytes):
            body = body.decode()
        assert "grant_type=password" in body
        assert "username=alice" in body
        assert "password=password123" in body

    @responses.activate
    def test_password_with_client_secret(self):
        _register_discovery()
        _register_token()

        creds = OIDCPasswordCredentials(
            issuer_url=ISSUER,
            client_id="notebook-client",
            username="alice",
            password="password123",
            client_secret="confidential",
        )
        creds.get_token()

        body = responses.calls[1].request.body
        if isinstance(body, bytes):
            body = body.decode()
        assert "client_secret=confidential" in body


# ---------------------------------------------------------------------------
# R8: Device flow
# ---------------------------------------------------------------------------


class TestR8DeviceFlow:
    """R8: Full device code flow with various outcomes."""

    @responses.activate
    def test_full_device_flow(self):
        """Full flow: discover → device auth → poll → get token."""
        _register_discovery()
        responses.add(
            responses.POST,
            DEVICE_ENDPOINT,
            json={
                "device_code": "dev-code-123",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://example.com/device",
                "interval": 0,
                "expires_in": 10,
            },
        )
        _register_token()

        prompted = {}

        def callback(uri, code, complete):
            prompted["uri"] = uri
            prompted["code"] = code

        creds = OIDCDeviceFlowCredentials(
            issuer_url=ISSUER,
            client_id="device-client",
            prompt_callback=callback,
        )
        token = creds.get_token()

        assert token == JWT_TOKEN
        assert prompted["uri"] == "https://example.com/device"
        assert prompted["code"] == "ABCD-EFGH"

    @responses.activate
    def test_handles_authorization_pending_and_slow_down(self):
        """Handles authorization_pending and slow_down before success."""
        _register_discovery()
        responses.add(
            responses.POST,
            DEVICE_ENDPOINT,
            json={
                "device_code": "dev-code",
                "user_code": "CODE",
                "verification_uri": "https://example.com/device",
                "interval": 0,
                "expires_in": 30,
            },
        )
        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json={"error": "authorization_pending"},
            status=400,
        )
        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json={"error": "slow_down"},
            status=400,
        )
        _register_token()

        creds = OIDCDeviceFlowCredentials(
            issuer_url=ISSUER,
            client_id="device-client",
            prompt_callback=lambda *a: None,
        )
        token = creds.get_token()
        assert token == JWT_TOKEN

    @responses.activate
    def test_handles_access_denied(self):
        """access_denied → InvalidCredentialsError."""
        _register_discovery()
        responses.add(
            responses.POST,
            DEVICE_ENDPOINT,
            json={
                "device_code": "dev-code",
                "user_code": "CODE",
                "verification_uri": "https://example.com/device",
                "interval": 0,
                "expires_in": 10,
            },
        )
        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json={"error": "access_denied"},
            status=400,
        )

        creds = OIDCDeviceFlowCredentials(
            issuer_url=ISSUER,
            client_id="device-client",
            prompt_callback=lambda *a: None,
        )
        with pytest.raises(InvalidCredentialsError, match="denied"):
            creds.get_token()

    @responses.activate
    def test_handles_expired_token(self):
        """expired_token → TokenExchangeError."""
        _register_discovery()
        responses.add(
            responses.POST,
            DEVICE_ENDPOINT,
            json={
                "device_code": "dev-code",
                "user_code": "CODE",
                "verification_uri": "https://example.com/device",
                "interval": 0,
                "expires_in": 10,
            },
        )
        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json={"error": "expired_token"},
            status=400,
        )

        creds = OIDCDeviceFlowCredentials(
            issuer_url=ISSUER,
            client_id="device-client",
            prompt_callback=lambda *a: None,
        )
        with pytest.raises(TokenExchangeError, match="expired"):
            creds.get_token()

    @responses.activate
    def test_missing_device_endpoint(self):
        """No device_authorization_endpoint → TokenExchangeError."""
        no_device = {
            k: v for k, v in DISCOVERY_RESPONSE.items() if k != "device_authorization_endpoint"
        }
        responses.add(responses.GET, DISCOVERY_URL, json=no_device)

        creds = OIDCDeviceFlowCredentials(
            issuer_url=ISSUER,
            client_id="device-client",
            prompt_callback=lambda *a: None,
        )
        with pytest.raises(TokenExchangeError, match="device_authorization_endpoint"):
            creds.get_token()


# ---------------------------------------------------------------------------
# R10: Dual-interface auth
# ---------------------------------------------------------------------------


class TestR10DualInterfaceAuth:
    """R10: Same creds used for refresh_api_key_hook AND get_token()."""

    @responses.activate
    def test_same_token_from_both_interfaces(self):
        """Token is identical from both interfaces."""
        _register_discovery()
        _register_token()

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test",
            client_secret="test",
        )

        token_from_get = creds.get_token()

        config = Configuration()
        creds.refresh_api_key_hook(config)
        token_from_hook = config.api_key["authorization"]

        assert token_from_get == token_from_hook

    @responses.activate
    def test_refresh_happens_once_for_both_interfaces(self):
        """Refresh happens once even when both interfaces are used."""
        _register_discovery()
        _register_token()

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test",
            client_secret="test",
        )

        creds.get_token()
        call_count = len(responses.calls)

        config = Configuration()
        creds.refresh_api_key_hook(config)
        assert len(responses.calls) == call_count


# ---------------------------------------------------------------------------
# R11: Unified config
# ---------------------------------------------------------------------------


class TestR11UnifiedConfig:
    """R11: load_kubernetes_config(credentials=creds, server=) wires hook correctly."""

    @responses.activate
    def test_wires_hook_to_k8s_config(self):
        _register_discovery()
        _register_token()

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test",
            client_secret="test",
        )
        api_client = load_kubernetes_config(credentials=creds, server=SERVER)

        cfg = api_client.configuration
        assert cfg.host == SERVER
        assert cfg.refresh_api_key_hook == creds.refresh_api_key_hook
        assert cfg.api_key_prefix["authorization"] == "Bearer"


# ---------------------------------------------------------------------------
# R12: Keyring persistence
# ---------------------------------------------------------------------------


class TestR12KeyringPersistence:
    """R12: save_refresh_token → load_refresh_token roundtrip."""

    def test_save_and_load_roundtrip(self):
        """Keyring save/load roundtrip (with mocked keyring)."""
        store: dict[tuple[str, str], str] = {}

        class FakeKeyring:
            class errors:  # noqa: N801
                class PasswordDeleteError(Exception):
                    pass

            @staticmethod
            def set_password(service, username, password):
                store[(service, username)] = password

            @staticmethod
            def get_password(service, username):
                return store.get((service, username))

            @staticmethod
            def delete_password(service, username):
                if (service, username) not in store:
                    raise FakeKeyring.errors.PasswordDeleteError()
                del store[(service, username)]

        with patch.dict("sys.modules", {"keyring": FakeKeyring}):
            from kubeflow.common.auth.oidc.keyring import (
                delete_refresh_token,
                load_refresh_token,
                save_refresh_token,
            )

            save_refresh_token(ISSUER, "my-client", "refresh-tok-123")
            loaded = load_refresh_token(ISSUER, "my-client")
            assert loaded == "refresh-tok-123"

            delete_refresh_token(ISSUER, "my-client")
            assert load_refresh_token(ISSUER, "my-client") is None


# ---------------------------------------------------------------------------
# R13: Identity propagation
# ---------------------------------------------------------------------------


class TestR13IdentityPropagation:
    """R13: get_token → extract_jwt_claims → identity_annotations → correct dict."""

    @responses.activate
    def test_full_identity_pipeline(self):
        _register_discovery()
        _register_token()

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test",
            client_secret="test",
        )
        token = creds.get_token()

        claims = extract_jwt_claims(token)
        assert claims["sub"] == "user-123"
        assert claims["email"] == "alice@example.com"
        assert claims["preferred_username"] == "alice"

        annotations = identity_annotations(token)
        assert annotations == {
            "kubeflow.org/user-id": "user-123",
            "kubeflow.org/user-email": "alice@example.com",
            "kubeflow.org/user-name": "alice",
        }


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------


class TestProtocolCompliance:
    """OIDC credential classes satisfy the TokenCredentialsBase protocol."""

    @responses.activate
    def test_client_credentials_is_token_credentials_base(self):
        _register_discovery()
        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test",
            client_secret="test",
        )
        assert isinstance(creds, TokenCredentialsBase)

    @responses.activate
    def test_password_credentials_is_token_credentials_base(self):
        _register_discovery()
        creds = OIDCPasswordCredentials(
            issuer_url=ISSUER,
            client_id="test",
            username="u",
            password="p",
        )
        assert isinstance(creds, TokenCredentialsBase)

    @responses.activate
    def test_device_flow_is_token_credentials_base(self):
        _register_discovery()
        creds = OIDCDeviceFlowCredentials(
            issuer_url=ISSUER,
            client_id="test",
            prompt_callback=lambda *a: None,
        )
        assert isinstance(creds, TokenCredentialsBase)

    @responses.activate
    def test_repr_redacts_secrets(self):
        _register_discovery()
        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test",
            client_secret="super-secret",
        )
        r = repr(creds)
        assert "super-secret" not in r
        assert "REDACTED" in r

    @responses.activate
    def test_password_repr_redacts(self):
        _register_discovery()
        creds = OIDCPasswordCredentials(
            issuer_url=ISSUER,
            client_id="test",
            username="user",
            password="super-secret",
        )
        r = repr(creds)
        assert "super-secret" not in r
        assert "REDACTED" in r


# ---------------------------------------------------------------------------
# Browser flow tests
# ---------------------------------------------------------------------------


class TestBrowserFlow:
    """Browser flow: PKCE generation, callback handling, state validation."""

    def test_pkce_pair_generation(self):
        """PKCE verifier and challenge are valid and deterministic in length."""
        from kubeflow.common.auth.oidc.browser_flow import _generate_pkce_pair

        verifier, challenge = _generate_pkce_pair()
        assert len(verifier) > 0
        assert len(challenge) > 0
        assert verifier != challenge

        import hashlib
        import base64

        expected_digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected_challenge = base64.urlsafe_b64encode(expected_digest).rstrip(b"=").decode("ascii")
        assert challenge == expected_challenge

    def test_pkce_pair_is_random(self):
        """Each call produces a different pair."""
        from kubeflow.common.auth.oidc.browser_flow import _generate_pkce_pair

        pair1 = _generate_pkce_pair()
        pair2 = _generate_pkce_pair()
        assert pair1[0] != pair2[0]

    @responses.activate
    def test_missing_authorization_endpoint_raises(self):
        """No authorization_endpoint in discovery → TokenExchangeError."""
        from kubeflow.common.auth import OIDCBrowserFlowCredentials

        no_auth = {
            k: v for k, v in DISCOVERY_RESPONSE.items() if k != "authorization_endpoint"
        }
        responses.add(responses.GET, DISCOVERY_URL, json=no_auth)

        creds = OIDCBrowserFlowCredentials(
            issuer_url=ISSUER,
            client_id="browser-client",
        )
        with pytest.raises(TokenExchangeError, match="authorization_endpoint"):
            creds.get_token()

    @responses.activate
    def test_callback_state_mismatch(self):
        """State mismatch in callback → TokenExchangeError."""
        from kubeflow.common.auth.oidc.browser_flow import _CallbackServer

        import secrets
        import urllib.request

        state = secrets.token_urlsafe(32)
        server = _CallbackServer(0, state)
        port = server.server_address[1]

        import threading

        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/callback?state=wrong-state&code=test-code",
                timeout=2,
            )
        except Exception:
            pass

        thread.join(timeout=3)
        server.server_close()
        assert server.callback_error == "state_mismatch"
        assert server.auth_code is None

    @responses.activate
    def test_callback_captures_auth_code(self):
        """Valid callback with matching state captures the authorization code."""
        from kubeflow.common.auth.oidc.browser_flow import _CallbackServer

        import threading
        import urllib.request

        state = "test-state-value"
        server = _CallbackServer(0, state)
        port = server.server_address[1]

        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/callback?state={state}&code=auth-code-123",
                timeout=2,
            )
        except Exception:
            pass

        thread.join(timeout=3)
        server.server_close()
        assert server.auth_code == "auth-code-123"
        assert server.callback_error is None

    @responses.activate
    def test_callback_missing_code(self):
        """Callback without authorization code → error."""
        from kubeflow.common.auth.oidc.browser_flow import _CallbackServer

        import threading
        import urllib.request

        state = "test-state"
        server = _CallbackServer(0, state)
        port = server.server_address[1]

        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/callback?state={state}",
                timeout=2,
            )
        except Exception:
            pass

        thread.join(timeout=3)
        server.server_close()
        assert server.callback_error == "missing_code"

    @responses.activate
    def test_callback_error_from_provider(self):
        """Provider returns an error in the callback → error captured."""
        from kubeflow.common.auth.oidc.browser_flow import _CallbackServer

        import threading
        import urllib.request

        state = "test-state"
        server = _CallbackServer(0, state)
        port = server.server_address[1]

        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/callback?error=access_denied",
                timeout=2,
            )
        except Exception:
            pass

        thread.join(timeout=3)
        server.server_close()
        assert server.callback_error == "access_denied"

    @responses.activate
    def test_callback_host_header_validation(self):
        """Invalid Host header is rejected."""
        from kubeflow.common.auth.oidc.browser_flow import _CallbackServer

        import http.client
        import threading

        state = "test-state"
        server = _CallbackServer(0, state)
        port = server.server_address[1]

        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            conn.putrequest("GET", f"/callback?state={state}&code=test", skip_host=True)
            conn.putheader("Host", "evil.example.com:8080")
            conn.endheaders()
            resp = conn.getresponse()
            assert resp.status == 400
        finally:
            conn.close()

        thread.join(timeout=3)
        server.server_close()
        assert server.auth_code is None


# ---------------------------------------------------------------------------
# Malformed response tests
# ---------------------------------------------------------------------------


class TestMalformedResponses:
    """Verify defensive handling of non-JSON and incomplete token responses."""

    @responses.activate
    def test_discovery_non_json_response(self):
        """Discovery endpoint returning HTML → DiscoveryError."""
        responses.add(
            responses.GET,
            DISCOVERY_URL,
            body="<html>Not Found</html>",
            content_type="text/html",
        )
        from kubeflow.common.auth.errors import DiscoveryError

        with pytest.raises(DiscoveryError, match="not valid JSON"):
            OIDCClientCredentials(
                issuer_url=ISSUER,
                client_id="test",
                client_secret="test",
            )

    @responses.activate
    def test_token_endpoint_non_json_response(self):
        """Token endpoint returning HTML → TokenExchangeError."""
        _register_discovery()
        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            body="<html>Internal Server Error</html>",
            content_type="text/html",
        )

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test",
            client_secret="test",
        )
        with pytest.raises(TokenExchangeError, match="non-JSON"):
            creds.get_token()

    @responses.activate
    def test_token_response_missing_access_token(self):
        """Token response JSON without access_token → TokenExchangeError."""
        _register_discovery()
        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json={"token_type": "Bearer", "expires_in": 300},
        )

        creds = OIDCClientCredentials(
            issuer_url=ISSUER,
            client_id="test",
            client_secret="test",
        )
        with pytest.raises(TokenExchangeError, match="missing.*access_token"):
            creds.get_token()

    @responses.activate
    def test_device_flow_non_json_error_response(self):
        """Device flow polling gets non-JSON error → TokenExchangeError."""
        _register_discovery()
        responses.add(
            responses.POST,
            DEVICE_ENDPOINT,
            json={
                "device_code": "dev-code",
                "user_code": "CODE",
                "verification_uri": "https://example.com/device",
                "interval": 0,
                "expires_in": 10,
            },
        )
        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            body="Gateway Timeout",
            status=504,
            content_type="text/plain",
        )

        creds = OIDCDeviceFlowCredentials(
            issuer_url=ISSUER,
            client_id="device-client",
            prompt_callback=lambda *a: None,
        )
        with pytest.raises(TokenExchangeError, match="non-JSON"):
            creds.get_token()

    @responses.activate
    def test_device_flow_success_non_json(self):
        """Device flow 200 with non-JSON → TokenExchangeError."""
        _register_discovery()
        responses.add(
            responses.POST,
            DEVICE_ENDPOINT,
            json={
                "device_code": "dev-code",
                "user_code": "CODE",
                "verification_uri": "https://example.com/device",
                "interval": 0,
                "expires_in": 10,
            },
        )
        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            body="OK but not JSON",
            status=200,
            content_type="text/plain",
        )

        creds = OIDCDeviceFlowCredentials(
            issuer_url=ISSUER,
            client_id="device-client",
            prompt_callback=lambda *a: None,
        )
        with pytest.raises(TokenExchangeError, match="not valid JSON"):
            creds.get_token()

    @responses.activate
    def test_device_flow_success_missing_access_token(self):
        """Device flow 200 without access_token → TokenExchangeError."""
        _register_discovery()
        responses.add(
            responses.POST,
            DEVICE_ENDPOINT,
            json={
                "device_code": "dev-code",
                "user_code": "CODE",
                "verification_uri": "https://example.com/device",
                "interval": 0,
                "expires_in": 10,
            },
        )
        responses.add(
            responses.POST,
            TOKEN_ENDPOINT,
            json={"token_type": "Bearer"},
            status=200,
        )

        creds = OIDCDeviceFlowCredentials(
            issuer_url=ISSUER,
            client_id="device-client",
            prompt_callback=lambda *a: None,
        )
        with pytest.raises(TokenExchangeError, match="missing.*access_token"):
            creds.get_token()


# ---------------------------------------------------------------------------
# Identity: groups claim
# ---------------------------------------------------------------------------


class TestIdentityGroupsClaim:
    """Verify groups claim is extracted into annotations."""

    def test_groups_as_list(self):
        token = _make_jwt_token({
            "sub": "user-1",
            "groups": ["admins", "ml-team"],
        })
        annotations = identity_annotations(token)
        assert annotations["kubeflow.org/user-groups"] == "admins,ml-team"

    def test_groups_as_string(self):
        token = _make_jwt_token({
            "sub": "user-1",
            "groups": "single-group",
        })
        annotations = identity_annotations(token)
        assert annotations["kubeflow.org/user-groups"] == "single-group"

    def test_no_groups_no_annotation(self):
        token = _make_jwt_token({"sub": "user-1"})
        annotations = identity_annotations(token)
        assert "kubeflow.org/user-groups" not in annotations
