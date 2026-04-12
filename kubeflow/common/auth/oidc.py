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

"""Built-in OIDC credential providers for common grant types."""

import time

from kubernetes import client
import requests

from kubeflow.common.types import TokenCredentialsBase


class _OIDCBaseCredentials(TokenCredentialsBase):
    """Base for OIDC credential classes. Handles discovery and token lifecycle."""

    def __init__(self, issuer_url: str, client_id: str):
        self._client_id = client_id
        self._token_endpoint = self._discover(issuer_url)
        self._access_token: str | None = None
        self._expires_at: float = 0

    def _discover(self, issuer_url: str) -> str:
        resp = requests.get(
            f"{issuer_url.rstrip('/')}/.well-known/openid-configuration",
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["token_endpoint"]

    def _exchange(self, data: dict) -> None:
        resp = requests.post(self._token_endpoint, data=data, timeout=10)
        resp.raise_for_status()
        token_data = resp.json()
        self._access_token = token_data["access_token"]
        # Refresh slightly before ``expires_in`` so concurrent requests rarely hit 401s.
        self._expires_at = time.time() + token_data.get("expires_in", 300) - 30

    def refresh_api_key_hook(self, config: client.Configuration) -> None:
        """Kubernetes client hook: refresh token material on ``Configuration`` before requests.

        Calls ``_do_token_exchange`` only when ``time.time() >= _expires_at``; always sets
        Bearer ``api_key`` / ``api_key_prefix`` from the current access token.
        """
        if time.time() >= self._expires_at:
            self._do_token_exchange()
        config.api_key["authorization"] = self._access_token
        config.api_key_prefix["authorization"] = "Bearer"

    def _do_token_exchange(self) -> None:
        raise NotImplementedError


class OIDCClientCredentials(_OIDCBaseCredentials):
    """Client credentials grant for CI/CD and service-to-service authentication."""

    def __init__(self, issuer_url: str, client_id: str, client_secret: str):
        super().__init__(issuer_url, client_id)
        self._client_secret = client_secret
        self._do_token_exchange()

    def _do_token_exchange(self) -> None:
        self._exchange(
            {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            }
        )


class OIDCPasswordCredentials(_OIDCBaseCredentials):
    """Resource owner password grant for testing and automation.

    Note: This grant type is deprecated in OAuth 2.1 but remains widely
    used in testing environments (e.g., Keycloak QE setups).
    """

    def __init__(self, issuer_url: str, client_id: str, username: str, password: str):
        super().__init__(issuer_url, client_id)
        self._username = username
        self._password = password
        self._do_token_exchange()

    def _do_token_exchange(self) -> None:
        self._exchange(
            {
                "grant_type": "password",
                "client_id": self._client_id,
                "username": self._username,
                "password": self._password,
            }
        )
