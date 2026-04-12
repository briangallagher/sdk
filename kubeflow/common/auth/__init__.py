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

"""Authentication utilities.

This module re-exports OIDC credential classes from the kubernetes-oidc
package. Install with: pip install kubeflow[oidc]

kubernetes-oidc is optional so lightweight or air-gapped installs avoid
pulling OAuth/OIDC stacks, HTTP helpers beyond kubernetes, and interactive
browser/device flows unless users opt in.
"""

try:
    from kubernetes_oidc import (
        OIDCBrowserFlowCredentials,
        OIDCClientCredentials,
        OIDCDeviceFlowCredentials,
        OIDCPasswordCredentials,
    )

    __all__ = [
        "OIDCClientCredentials",
        "OIDCPasswordCredentials",
        "OIDCDeviceFlowCredentials",
        "OIDCBrowserFlowCredentials",
    ]
except ImportError:
    __all__ = []
