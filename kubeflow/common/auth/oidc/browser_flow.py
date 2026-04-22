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

"""OIDC authorization code flow with PKCE (RFC 7636).

Opens the user's browser to the IDP login page, runs a temporary local HTTP
server to capture the redirect callback, and exchanges the authorization code
for tokens.  Used for local development and notebook environments with browser
access.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import os
import secrets
import threading
from typing import Any
import urllib.parse
import webbrowser

from .base import _OIDCBaseCredentials
from .errors import TokenExchangeError


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code verifier and S256 code challenge."""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that captures the OAuth redirect callback."""

    def do_GET(self) -> None:
        host = self.headers.get("Host", "")
        allowed = {
            f"localhost:{self.server.server_address[1]}",
            f"127.0.0.1:{self.server.server_address[1]}",
        }
        if host not in allowed:
            self.send_error(400, "Invalid Host header")
            return

        params = urllib.parse.parse_qs(
            urllib.parse.urlparse(self.path).query,
        )

        if "error" in params:
            self.server.callback_error = params["error"][0]
            self._respond("Authentication failed. You can close this tab.")
            return

        state = params.get("state", [None])[0]
        if state != self.server.state_expected:
            self.server.callback_error = "state_mismatch"
            self._respond("State mismatch — possible CSRF. You can close this tab.")
            return

        code = params.get("code", [None])[0]
        if not code:
            self.server.callback_error = "missing_code"
            self._respond("No authorization code received. You can close this tab.")
            return

        self.server.auth_code = code
        self._respond("Authentication successful! You can close this tab.")

    def _respond(self, body: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        html = (
            f"<html><body style='font-family:sans-serif;text-align:center;"
            f"padding:40px'><h2>{body}</h2></body></html>"
        )
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        pass


class _CallbackServer(http.server.HTTPServer):
    """HTTPServer subclass that carries per-flow callback state."""

    def __init__(self, port: int, state_expected: str) -> None:
        super().__init__(("127.0.0.1", port), _CallbackHandler)
        self.auth_code: str | None = None
        self.callback_error: str | None = None
        self.state_expected = state_expected


class OIDCBrowserFlowCredentials(_OIDCBaseCredentials):
    """OIDC authorization code flow with PKCE — for browser-based auth.

    Implements `RFC 7636 <https://datatracker.ietf.org/doc/html/rfc7636>`_
    and `OIDC Core §3.1 <https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth>`_.

    Opens the user's default browser to the IDP login page, starts a temporary
    HTTP server on localhost to capture the redirect, and exchanges the
    authorization code for tokens.

    Example::

        from kubeflow.common.auth import OIDCBrowserFlowCredentials

        creds = OIDCBrowserFlowCredentials(
            issuer_url="https://keycloak.example.com/realms/myrealm",
            client_id="my-client",
        )
    """

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        *,
        redirect_port: int = 8400,
        scopes: list[str] | None = None,
        verify: bool | str = True,
        timeout: float = 10.0,
        browser_open_timeout: float = 300.0,
    ) -> None:
        self._redirect_port = redirect_port
        self._browser_open_timeout = browser_open_timeout
        super().__init__(
            issuer_url,
            client_id,
            scopes=scopes,
            verify=verify,
            timeout=timeout,
        )

    def _do_token_exchange(self) -> dict[str, Any]:
        if self._metadata.authorization_endpoint is None:
            raise TokenExchangeError("OIDC provider does not expose an authorization_endpoint.")

        verifier, challenge = _generate_pkce_pair()
        state = secrets.token_urlsafe(32)
        redirect_uri = f"http://localhost:{self._redirect_port}/callback"

        scopes = list(self._scopes or [])
        if "openid" not in scopes:
            scopes.insert(0, "openid")

        auth_params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        auth_url = f"{self._metadata.authorization_endpoint}?{urllib.parse.urlencode(auth_params)}"

        server = _CallbackServer(self._redirect_port, state)
        server_thread = threading.Thread(target=server.handle_request, daemon=True)
        server_thread.start()

        webbrowser.open(auth_url)

        server_thread.join(timeout=self._browser_open_timeout)
        server.server_close()

        if server.callback_error:
            raise TokenExchangeError(f"Browser authentication failed: {server.callback_error}")
        if server.auth_code is None:
            raise TokenExchangeError("Timed out waiting for browser authentication callback.")

        return self._exchange(
            {
                "grant_type": "authorization_code",
                "client_id": self._client_id,
                "code": server.auth_code,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            }
        )
