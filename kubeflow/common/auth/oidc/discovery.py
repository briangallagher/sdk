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

"""OIDC discovery — fetch provider metadata from .well-known/openid-configuration."""

from __future__ import annotations

from dataclasses import dataclass

import requests

from .errors import DiscoveryError, ProviderUnreachableError


@dataclass(frozen=True)
class OIDCProviderMetadata:
    """Subset of OIDC provider metadata relevant for token operations."""

    token_endpoint: str
    authorization_endpoint: str | None = None
    device_authorization_endpoint: str | None = None
    issuer: str | None = None


def discover(
    issuer_url: str,
    *,
    verify: bool | str = True,
    timeout: float = 10.0,
) -> OIDCProviderMetadata:
    """Fetch OIDC provider metadata via discovery.

    Args:
        issuer_url: The OIDC issuer URL (e.g. https://keycloak.example.com/realms/myrealm).
        verify: TLS verification — True (default), False, or a path to a CA bundle.
        timeout: HTTP request timeout in seconds.

    Returns:
        Provider metadata with discovered endpoints.

    Raises:
        ProviderUnreachableError: If the discovery request fails due to a connection error.
        DiscoveryError: If discovery succeeds but the response is invalid or issuer mismatches.
    """
    normalised_issuer = issuer_url.rstrip("/")
    url = f"{normalised_issuer}/.well-known/openid-configuration"

    try:
        resp = requests.get(url, verify=verify, timeout=timeout)
        resp.raise_for_status()
    except (requests.ConnectionError, ConnectionError) as exc:
        raise ProviderUnreachableError(
            f"Cannot reach OIDC provider at {normalised_issuer}: {exc}"
        ) from exc
    except requests.HTTPError as exc:
        raise DiscoveryError(f"OIDC discovery failed for {normalised_issuer}: {exc}") from exc
    except requests.RequestException as exc:
        raise ProviderUnreachableError(
            f"Cannot reach OIDC provider at {normalised_issuer}: {exc}"
        ) from exc

    try:
        data = resp.json()
    except (ValueError, RuntimeError) as exc:
        raise DiscoveryError(
            f"OIDC discovery response from {normalised_issuer} is not valid JSON: {exc}"
        ) from exc

    response_issuer = data.get("issuer")
    if response_issuer is not None and response_issuer.rstrip("/") != normalised_issuer:
        raise DiscoveryError(
            f"OIDC issuer mismatch: requested {normalised_issuer!r} but "
            f"discovery document returned {response_issuer!r}. "
            f"This may indicate a misconfigured or compromised provider."
        )

    if "token_endpoint" not in data:
        raise DiscoveryError(
            f"OIDC discovery response from {normalised_issuer} is missing 'token_endpoint'."
        )

    return OIDCProviderMetadata(
        token_endpoint=data["token_endpoint"],
        authorization_endpoint=data.get("authorization_endpoint"),
        device_authorization_endpoint=data.get("device_authorization_endpoint"),
        issuer=response_issuer,
    )
