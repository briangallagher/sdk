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

"""Tests for OIDC discovery."""

from __future__ import annotations

import pytest
import responses

from kubeflow.common.auth.errors import DiscoveryError, ProviderUnreachableError
from kubeflow.common.auth.oidc.discovery import OIDCProviderMetadata, discover

ISSUER = "https://keycloak.example.com/realms/test"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
AUTH_ENDPOINT = f"{ISSUER}/protocol/openid-connect/auth"
DEVICE_ENDPOINT = f"{ISSUER}/protocol/openid-connect/auth/device"

DISCOVERY_RESPONSE = {
    "issuer": ISSUER,
    "token_endpoint": TOKEN_ENDPOINT,
    "authorization_endpoint": AUTH_ENDPOINT,
    "device_authorization_endpoint": DEVICE_ENDPOINT,
}


class TestDiscover:
    @responses.activate
    def test_returns_metadata(self):
        responses.add(responses.GET, DISCOVERY_URL, json=DISCOVERY_RESPONSE)
        metadata = discover(ISSUER)
        assert metadata.token_endpoint == TOKEN_ENDPOINT
        assert metadata.authorization_endpoint == AUTH_ENDPOINT
        assert metadata.device_authorization_endpoint == DEVICE_ENDPOINT
        assert metadata.issuer == ISSUER

    @responses.activate
    def test_trailing_slash_normalised(self):
        responses.add(responses.GET, DISCOVERY_URL, json=DISCOVERY_RESPONSE)
        metadata = discover(ISSUER + "/")
        assert metadata.token_endpoint == TOKEN_ENDPOINT

    @responses.activate
    def test_issuer_mismatch_raises_discovery_error(self):
        bad_response = {**DISCOVERY_RESPONSE, "issuer": "https://evil.example.com"}
        responses.add(responses.GET, DISCOVERY_URL, json=bad_response)
        with pytest.raises(DiscoveryError, match="issuer mismatch"):
            discover(ISSUER)

    @responses.activate
    def test_missing_token_endpoint_raises_discovery_error(self):
        responses.add(responses.GET, DISCOVERY_URL, json={"issuer": ISSUER})
        with pytest.raises(DiscoveryError, match="missing.*token_endpoint"):
            discover(ISSUER)

    @responses.activate
    def test_http_error_raises_discovery_error(self):
        responses.add(responses.GET, DISCOVERY_URL, status=500)
        with pytest.raises(DiscoveryError):
            discover(ISSUER)

    @responses.activate
    def test_connection_error_raises_provider_unreachable(self):
        responses.add(
            responses.GET,
            DISCOVERY_URL,
            body=ConnectionError("Connection refused"),
        )
        with pytest.raises(ProviderUnreachableError):
            discover(ISSUER)

    @responses.activate
    def test_metadata_is_frozen_dataclass(self):
        responses.add(responses.GET, DISCOVERY_URL, json=DISCOVERY_RESPONSE)
        metadata = discover(ISSUER)
        assert isinstance(metadata, OIDCProviderMetadata)
        with pytest.raises(AttributeError):
            metadata.token_endpoint = "something else"

    @responses.activate
    def test_optional_endpoints_default_to_none(self):
        minimal = {"issuer": ISSUER, "token_endpoint": TOKEN_ENDPOINT}
        responses.add(responses.GET, DISCOVERY_URL, json=minimal)
        metadata = discover(ISSUER)
        assert metadata.authorization_endpoint is None
        assert metadata.device_authorization_endpoint is None
