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

"""Unified authentication for Kubeflow SDKs.

Public API:

- ``TokenCredentialsBase`` — Protocol for pluggable token credentials
- ``load_kubernetes_config`` — resolution chain for K8s client configuration
- Error hierarchy — ``AuthenticationError`` and subclasses
- Identity — ``extract_jwt_claims``, ``identity_annotations``
- OIDC credentials — client credentials, password, device flow, browser flow
- OIDC discovery — ``discover``, ``OIDCProviderMetadata``
"""

from .errors import (
    AuthenticationError,
    DiscoveryError,
    InvalidCredentialsError,
    ProviderUnreachableError,
    TokenExchangeError,
    TokenExpiredError,
)
from .identity import extract_jwt_claims, identity_annotations
from .oidc import (
    OIDCBrowserFlowCredentials,
    OIDCClientCredentials,
    OIDCDeviceFlowCredentials,
    OIDCPasswordCredentials,
    OIDCProviderMetadata,
    discover,
)
from .resolution import load_kubernetes_config, resolve_credentials
from .types import TokenCredentialsBase

__all__ = [
    "TokenCredentialsBase",
    "load_kubernetes_config",
    "resolve_credentials",
    "AuthenticationError",
    "DiscoveryError",
    "InvalidCredentialsError",
    "ProviderUnreachableError",
    "TokenExchangeError",
    "TokenExpiredError",
    "extract_jwt_claims",
    "identity_annotations",
    "OIDCClientCredentials",
    "OIDCPasswordCredentials",
    "OIDCDeviceFlowCredentials",
    "OIDCBrowserFlowCredentials",
    "OIDCProviderMetadata",
    "discover",
]
