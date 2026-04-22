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

"""OIDC device authorization grant (RFC 8628).

Used in headless environments — CLI, CI/CD, remote notebooks — where the user
authenticates in a browser on a separate device.
"""

from __future__ import annotations

from collections.abc import Callable
import sys
import time
from typing import Any, TextIO

import requests

from .base import _OIDCBaseCredentials
from .errors import InvalidCredentialsError, ProviderUnreachableError, TokenExchangeError


class OIDCDeviceFlowCredentials(_OIDCBaseCredentials):
    """OIDC device code flow credentials.

    Implements `RFC 8628 <https://datatracker.ietf.org/doc/html/rfc8628>`_.

    On first use, prints a verification URL and user code to the console.
    The user visits the URL on any device, enters the code, and authenticates.
    The SDK polls the token endpoint until the user approves.

    Example::

        from kubeflow.common.auth import OIDCDeviceFlowCredentials

        creds = OIDCDeviceFlowCredentials(
            issuer_url="https://keycloak.example.com/realms/myrealm",
            client_id="my-client",
        )
        # Prints: "Visit https://keycloak.example.com/device and enter code: ABCD-EFGH"
    """

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        *,
        scopes: list[str] | None = None,
        verify: bool | str = True,
        timeout: float = 10.0,
        output: TextIO | None = None,
        prompt_callback: Callable[[str, str, str], None] | None = None,
    ) -> None:
        self._output = output or sys.stderr
        self._prompt_callback = prompt_callback
        super().__init__(
            issuer_url,
            client_id,
            scopes=scopes,
            verify=verify,
            timeout=timeout,
        )

    def _do_token_exchange(self) -> dict[str, Any]:
        if self._metadata.device_authorization_endpoint is None:
            raise TokenExchangeError(
                "OIDC provider does not support the device authorization grant. "
                "The 'device_authorization_endpoint' was not found in the "
                "provider's .well-known/openid-configuration."
            )

        data: dict[str, str] = {"client_id": self._client_id}
        if self._scopes:
            data["scope"] = " ".join(self._scopes)

        try:
            resp = requests.post(
                self._metadata.device_authorization_endpoint,
                data=data,
                verify=self._verify,
                timeout=self._timeout,
            )
            resp.raise_for_status()
        except requests.ConnectionError as exc:
            raise ProviderUnreachableError(
                f"Cannot reach device authorization endpoint: {exc}"
            ) from exc
        except requests.HTTPError as exc:
            raise TokenExchangeError(f"Device authorization request failed: {exc}") from exc

        device_data = resp.json()

        device_code: str = device_data["device_code"]
        user_code: str = device_data["user_code"]
        verification_uri: str = device_data["verification_uri"]
        verification_uri_complete: str = device_data.get("verification_uri_complete", "")
        interval: int = device_data.get("interval", 5)
        expires_in: int = device_data.get("expires_in", 600)

        self._prompt_user(verification_uri, user_code, verification_uri_complete)

        return self._poll_for_token(device_code, interval, expires_in)

    def _prompt_user(
        self,
        verification_uri: str,
        user_code: str,
        verification_uri_complete: str,
    ) -> None:
        if self._prompt_callback:
            self._prompt_callback(
                verification_uri,
                user_code,
                verification_uri_complete,
            )
            return

        msg = f"\nTo authenticate, visit:\n\n  {verification_uri}\n\nand enter code: {user_code}\n"
        if verification_uri_complete:
            msg += f"\nOr visit directly: {verification_uri_complete}\n"
        msg += "\nWaiting for authentication...\n"
        self._output.write(msg)
        self._output.flush()

    def _poll_for_token(
        self,
        device_code: str,
        interval: int,
        expires_in: int,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + expires_in

        while time.monotonic() < deadline:
            time.sleep(interval)

            try:
                resp = requests.post(
                    self._metadata.token_endpoint,
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "client_id": self._client_id,
                        "device_code": device_code,
                    },
                    verify=self._verify,
                    timeout=self._timeout,
                )
            except requests.RequestException:
                continue

            if resp.status_code == 200:
                try:
                    token_data = resp.json()
                except (ValueError, RuntimeError) as exc:
                    raise TokenExchangeError(
                        f"Device flow token response is not valid JSON: {exc}"
                    ) from exc
                if "access_token" not in token_data:
                    raise TokenExchangeError(
                        "Device flow token response missing 'access_token'. "
                        f"Response keys: {sorted(token_data.keys())}"
                    )
                self._store_token_data(token_data)
                return token_data

            try:
                error_data = resp.json()
            except (ValueError, RuntimeError):
                raise TokenExchangeError(
                    f"Device flow polling received HTTP {resp.status_code} "
                    f"with non-JSON body: {resp.text[:200]}"
                )
            error = error_data.get("error", "")

            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            if error == "expired_token":
                raise TokenExchangeError(
                    "Device code expired before user completed authentication."
                )
            if error == "access_denied":
                raise InvalidCredentialsError("User denied the device authorization request.")
            raise TokenExchangeError(f"Device flow token exchange failed: {error_data}")

        raise TokenExchangeError("Device flow timed out waiting for user authentication.")
