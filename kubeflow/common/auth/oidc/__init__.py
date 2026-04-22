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

"""OIDC authentication for Kubeflow SDKs.

This subpackage is **extractable** — it has zero imports from ``kubeflow.*``
and can be vendored independently.

All credential classes integrate with the Kubernetes Python client via
``Configuration.refresh_api_key_hook``.

Credential classes:

- ``OIDCClientCredentials``  — client credentials grant (CI/CD)
- ``OIDCPasswordCredentials`` — resource owner password grant (testing)
- ``OIDCDeviceFlowCredentials`` — device code flow (headless notebooks)
- ``OIDCBrowserFlowCredentials`` — auth code + PKCE (local development)
"""

from .browser_flow import OIDCBrowserFlowCredentials
from .client_credentials import OIDCClientCredentials
from .device_flow import OIDCDeviceFlowCredentials
from .discovery import OIDCProviderMetadata, discover
from .errors import (
    AuthenticationError,
    DiscoveryError,
    InvalidCredentialsError,
    ProviderUnreachableError,
    TokenExchangeError,
    TokenExpiredError,
)
from .password import OIDCPasswordCredentials

__all__ = [
    "OIDCClientCredentials",
    "OIDCPasswordCredentials",
    "OIDCDeviceFlowCredentials",
    "OIDCBrowserFlowCredentials",
    "OIDCProviderMetadata",
    "discover",
    "AuthenticationError",
    "DiscoveryError",
    "InvalidCredentialsError",
    "ProviderUnreachableError",
    "TokenExchangeError",
    "TokenExpiredError",
]
