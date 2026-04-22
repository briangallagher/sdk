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

"""Base class for OIDC credential implementations.

Implements the ``refresh_api_key_hook`` / ``get_token`` interface expected
by ``TokenCredentialsBase`` via structural subtyping (duck typing), so this
module has **zero** Kubeflow imports and remains extractable.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import requests

if TYPE_CHECKING:
    from kubernetes.client import Configuration

from .discovery import OIDCProviderMetadata, discover
from .errors import (
    AuthenticationError,
    InvalidCredentialsError,
    ProviderUnreachableError,
    TokenExchangeError,
)

_EXPIRY_BUFFER_SECONDS = 30


class _OIDCBaseCredentials:
    """Base for OIDC credential classes.

    Handles discovery, token exchange, and the ``refresh_api_key_hook`` contract
    expected by ``kubernetes.client.Configuration``.

    Does NOT inherit from ``TokenCredentialsBase`` — it satisfies the
    ``TokenCredentialsBase`` Protocol structurally.
    """

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        *,
        scopes: list[str] | None = None,
        verify: bool | str = True,
        timeout: float = 10.0,
    ) -> None:
        self._client_id = client_id
        self._scopes = scopes
        self._verify = verify
        self._timeout = timeout
        self._metadata: OIDCProviderMetadata = discover(
            issuer_url,
            verify=verify,
            timeout=timeout,
        )
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._expires_at: float = 0.0

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"client_id={self._client_id!r}, "
            f"token_endpoint={self._metadata.token_endpoint!r}, "
            f"has_token={self._access_token is not None})"
        )

    @property
    def access_token(self) -> str | None:
        """The current access token, or *None* if no exchange has occurred."""
        return self._access_token

    @property
    def token_endpoint(self) -> str:
        return self._metadata.token_endpoint

    def get_token(self) -> str:
        """Return a valid access token, refreshing if necessary.

        Unlike ``refresh_api_key_hook`` (which writes into a K8s
        ``Configuration``), this method returns the token directly.  Useful
        when the caller needs the token itself — e.g. to decode JWT claims
        for identity propagation, or to set an HTTP ``Authorization`` header
        on a non-K8s client.
        """
        if self._access_token is None:
            self._do_token_exchange()
        elif self._is_expired():
            self._do_refresh()
        # _access_token is guaranteed non-None here: the None branch above
        # calls _do_token_exchange which sets it via _store_token_data.
        return self._access_token  # type: ignore[return-value]

    def _exchange(self, data: dict[str, Any]) -> dict[str, Any]:
        """POST to the token endpoint and store the result."""
        if self._scopes:
            data["scope"] = " ".join(self._scopes)

        try:
            resp = requests.post(
                self._metadata.token_endpoint,
                data=data,
                verify=self._verify,
                timeout=self._timeout,
            )
            resp.raise_for_status()
        except (requests.ConnectionError, ConnectionError) as exc:
            raise ProviderUnreachableError(
                f"Cannot reach token endpoint {self._metadata.token_endpoint}: {exc}"
            ) from exc
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status == 401 or status == 403:
                raise InvalidCredentialsError(
                    f"Credentials rejected by provider (HTTP {status}): {exc}"
                ) from exc
            raise TokenExchangeError(f"Token exchange failed (HTTP {status}): {exc}") from exc
        except requests.RequestException as exc:
            raise ProviderUnreachableError(
                f"Cannot reach token endpoint {self._metadata.token_endpoint}: {exc}"
            ) from exc

        try:
            token_data = resp.json()
        except (ValueError, RuntimeError) as exc:
            raise TokenExchangeError(
                f"Token endpoint returned non-JSON response: {exc}"
            ) from exc

        if "access_token" not in token_data:
            raise TokenExchangeError(
                "Token response missing 'access_token'. "
                f"Response keys: {sorted(token_data.keys())}"
            )

        self._store_token_data(token_data)
        return token_data

    def _store_token_data(self, token_data: dict[str, Any]) -> None:
        """Extract and cache token fields from a successful token response."""
        self._access_token = token_data["access_token"]
        self._refresh_token = token_data.get("refresh_token")
        self._expires_at = (
            time.monotonic() + token_data.get("expires_in", 300) - _EXPIRY_BUFFER_SECONDS
        )

    def _is_expired(self) -> bool:
        return time.monotonic() >= self._expires_at

    def _do_token_exchange(self) -> dict[str, Any]:
        raise NotImplementedError

    def _do_refresh(self) -> dict[str, Any]:
        """Attempt a refresh-token exchange; fall back to a full exchange."""
        if self._refresh_token:
            try:
                return self._exchange(
                    {
                        "grant_type": "refresh_token",
                        "client_id": self._client_id,
                        "refresh_token": self._refresh_token,
                    }
                )
            except AuthenticationError:
                pass
        return self._do_token_exchange()

    def refresh_api_key_hook(self, config: Configuration) -> None:
        """Hook for ``kubernetes.client.Configuration.refresh_api_key_hook``.

        Called before every K8s API request.  If the current token is expired
        (or absent), performs a token exchange or refresh and updates the
        configuration with the new bearer token.
        """
        if self._access_token is None or self._is_expired():
            if self._access_token is None:
                self._do_token_exchange()
            else:
                self._do_refresh()

        config.api_key["authorization"] = self._access_token
        config.api_key_prefix["authorization"] = "Bearer"
