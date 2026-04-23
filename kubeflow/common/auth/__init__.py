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

from kubeflow.common.auth.identity import identity_annotations
from kubeflow.common.auth.kube_authkit_bridge import (
    get_kubernetes_client,
    load_kubernetes_config,
    resolve_credentials,
)
from kubeflow.common.auth.types import TokenCredentialsBase

__all__ = [
    "TokenCredentialsBase",
    "get_kubernetes_client",
    "load_kubernetes_config",
    "resolve_credentials",
    "identity_annotations",
]
