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

"""Optional keyring-backed token persistence.

Stores OIDC refresh tokens in the system keyring (Mac Keychain, GNOME Keyring,
Windows Credential Manager, etc.) so that interactive flows don't require
re-authentication on every invocation.

Requires: ``pip install kubeflow[oidc-keyring]``
"""

from __future__ import annotations

import contextlib

_SERVICE_PREFIX = "kubeflow-oidc"


def _keyring():
    """Lazy import — only fails if the optional ``keyring`` package isn't installed."""
    try:
        import keyring

        return keyring
    except ImportError:
        raise ImportError(
            "Keyring support requires the 'keyring' package. "
            "Install it with: pip install kubeflow[oidc-keyring]"
        ) from None


def save_refresh_token(issuer_url: str, client_id: str, refresh_token: str) -> None:
    """Persist a refresh token in the system keyring."""
    kr = _keyring()
    service = f"{_SERVICE_PREFIX}:{issuer_url}"
    kr.set_password(service, client_id, refresh_token)


def load_refresh_token(issuer_url: str, client_id: str) -> str | None:
    """Load a previously stored refresh token, or return None."""
    kr = _keyring()
    service = f"{_SERVICE_PREFIX}:{issuer_url}"
    return kr.get_password(service, client_id)


def delete_refresh_token(issuer_url: str, client_id: str) -> None:
    """Remove a stored refresh token."""
    kr = _keyring()
    service = f"{_SERVICE_PREFIX}:{issuer_url}"
    with contextlib.suppress(kr.errors.PasswordDeleteError):
        kr.delete_password(service, client_id)
