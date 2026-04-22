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

Defined within the oidc subpackage so it remains extractable with zero
Kubeflow imports.  Re-exported at ``kubeflow.common.auth.errors``.
"""


class AuthenticationError(Exception):
    """Base for all auth errors."""


class DiscoveryError(AuthenticationError):
    """OIDC discovery failed."""


class TokenExchangeError(AuthenticationError):
    """Token exchange or refresh failed."""


class TokenExpiredError(AuthenticationError):
    """Token expired and could not be refreshed."""


class ProviderUnreachableError(AuthenticationError):
    """Cannot reach the OIDC provider."""


class InvalidCredentialsError(AuthenticationError):
    """Credentials were rejected by the provider."""
