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

"""OIDC resource owner password grant (RFC 6749 §4.3)."""

from __future__ import annotations

from typing import Any

from .base import _OIDCBaseCredentials


class OIDCPasswordCredentials(_OIDCBaseCredentials):
    """OIDC resource owner password grant — for testing and automation.

    Implements `RFC 6749 §4.3 <https://datatracker.ietf.org/doc/html/rfc6749#section-4.3>`_.

    .. warning::
        The password grant is deprecated in OAuth 2.1. Use client credentials
        or device flow for new integrations.  This class exists for testing
        environments and legacy systems that require it.

    Example::

        from kubeflow.common.auth import OIDCPasswordCredentials

        creds = OIDCPasswordCredentials(
            issuer_url="https://keycloak.example.com/realms/myrealm",
            client_id="my-client",
            username="test-user",
            password="test-pass",
        )
    """

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        username: str,
        password: str,
        *,
        client_secret: str = "",
        scopes: list[str] | None = None,
        verify: bool | str = True,
        timeout: float = 10.0,
    ) -> None:
        self._username = username
        self._password = password
        self._client_secret = client_secret
        super().__init__(
            issuer_url,
            client_id,
            scopes=scopes,
            verify=verify,
            timeout=timeout,
        )

    def __repr__(self) -> str:
        return (
            f"OIDCPasswordCredentials("
            f"client_id={self._client_id!r}, "
            f"username={self._username!r}, "
            f"token_endpoint={self._metadata.token_endpoint!r}, "
            f"password=<REDACTED>, "
            f"has_token={self._access_token is not None})"
        )

    def _do_token_exchange(self) -> dict[str, Any]:
        data: dict[str, str] = {
            "grant_type": "password",
            "client_id": self._client_id,
            "username": self._username,
            "password": self._password,
        }
        if self._client_secret:
            data["client_secret"] = self._client_secret
        return self._exchange(data)
