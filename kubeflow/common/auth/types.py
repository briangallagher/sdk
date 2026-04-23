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

"""Token credentials protocol for pluggable authentication."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from kubernetes.client import Configuration


@runtime_checkable
class TokenCredentialsBase(Protocol):
    """Protocol for pluggable token credentials.

    Any object that implements ``refresh_api_key_hook`` and ``get_token``
    can be used as credentials for ``KubernetesBackendConfig`` and
    ``load_kubernetes_config``.

    ``refresh_api_key_hook`` is called by the Kubernetes Python client before
    every API request, enabling automatic token refresh for K8s operations.

    ``get_token`` returns a valid access token string for REST clients
    (e.g. KFP, Model Registry) or any consumer that needs a raw bearer token.
    """

    def refresh_api_key_hook(self, config: Configuration) -> None:
        """Called before every K8s API request to refresh the bearer token."""
        ...

    def get_token(self) -> str:
        """Return a valid access token, refreshing if necessary."""
        ...
