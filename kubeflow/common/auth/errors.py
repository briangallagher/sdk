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

"""Authentication error hierarchy.

All error classes are defined in ``kubeflow.common.auth.oidc.errors`` so
the OIDC subpackage stays self-contained, and re-exported here for
convenient access at the ``kubeflow.common.auth`` level.
"""

from .oidc.errors import (
    AuthenticationError,
    DiscoveryError,
    InvalidCredentialsError,
    ProviderUnreachableError,
    TokenExchangeError,
    TokenExpiredError,
)

__all__ = [
    "AuthenticationError",
    "DiscoveryError",
    "InvalidCredentialsError",
    "ProviderUnreachableError",
    "TokenExchangeError",
    "TokenExpiredError",
]
