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

"""OIDC client credentials grant (RFC 6749 §4.4)."""

from __future__ import annotations

from typing import Any

from .base import _OIDCBaseCredentials


class OIDCClientCredentials(_OIDCBaseCredentials):
    """OIDC client credentials grant — for CI/CD, service-to-service auth.

    Implements `RFC 6749 §4.4 <https://datatracker.ietf.org/doc/html/rfc6749#section-4.4>`_.

    Example::

        from kubeflow.trainer import TrainerClient
        from kubeflow.common.auth import OIDCClientCredentials

        creds = OIDCClientCredentials(
            issuer_url="https://keycloak.example.com/realms/myrealm",
            client_id="my-client",
            client_secret="my-secret",
        )
        client = TrainerClient(
            backend_config={
                "credentials": creds,
                "server": "https://api.cluster:6443",
            }
        )
    """

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        client_secret: str,
        *,
        scopes: list[str] | None = None,
        verify: bool | str = True,
        timeout: float = 10.0,
    ) -> None:
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
            f"OIDCClientCredentials("
            f"client_id={self._client_id!r}, "
            f"token_endpoint={self._metadata.token_endpoint!r}, "
            f"client_secret=<REDACTED>, "
            f"has_token={self._access_token is not None})"
        )

    def _do_token_exchange(self) -> dict[str, Any]:
        return self._exchange(
            {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            }
        )
