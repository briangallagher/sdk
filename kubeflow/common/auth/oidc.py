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

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"client_id={self._client_id!r}, "
            f"token_endpoint={self._token_endpoint!r}, "
            f"has_token={self._access_token is not None})"
        )

    def _discover(self, issuer_url: str) -> str:
        normalised = issuer_url.rstrip("/")
        resp = requests.get(
            f"{normalised}/.well-known/openid-configuration",
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        response_issuer = data.get("issuer")
        if response_issuer is not None:
            if response_issuer.rstrip("/") != normalised:
                raise ValueError(
                    f"OIDC issuer mismatch: requested {normalised!r} but "
                    f"discovery document returned {response_issuer!r}. "
                    f"This may indicate a misconfigured or compromised provider."
                )

        return data["token_endpoint"]

    def _exchange(self, data: dict) -> None:
        resp = requests.post(self._token_endpoint, data=data, timeout=10)
        resp.raise_for_status()
        token_data = resp.json()
        self._access_token = token_data["access_token"]
        self._expires_at = time.monotonic() + token_data.get("expires_in", 300) - 30

    def refresh_api_key_hook(self, config: client.Configuration) -> None:
        """Kubernetes client hook: refresh token material on ``Configuration`` before requests.

        Calls ``_do_token_exchange`` only when the token is expired or absent; always sets
        Bearer ``api_key`` / ``api_key_prefix`` from the current access token.
        """
        if self._access_token is None or time.monotonic() >= self._expires_at:
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

    def __repr__(self) -> str:
        return (
            f"OIDCClientCredentials("
            f"client_id={self._client_id!r}, "
            f"token_endpoint={self._token_endpoint!r}, "
            f"client_secret=<REDACTED>, "
            f"has_token={self._access_token is not None})"
        )

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

    def __repr__(self) -> str:
        return (
            f"OIDCPasswordCredentials("
            f"client_id={self._client_id!r}, "
            f"username={self._username!r}, "
            f"token_endpoint={self._token_endpoint!r}, "
            f"password=<REDACTED>, "
            f"has_token={self._access_token is not None})"
        )

    def _do_token_exchange(self) -> None:
        self._exchange(
            {
                "grant_type": "password",
                "client_id": self._client_id,
                "username": self._username,
                "password": self._password,
            }
        )
