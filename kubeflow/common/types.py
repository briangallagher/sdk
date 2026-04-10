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


from kubernetes import client
from pydantic import BaseModel


class KubernetesBackendConfig(BaseModel):
    namespace: str | None = None
    config_file: str | None = None
    context: str | None = None
    client_configuration: client.Configuration | None = None

    # kube-authkit authentication fields
    auth_method: str | None = None  # "auto", "kubeconfig", "incluster", "oidc", "openshift"
    k8s_api_host: str | None = None
    kubeconfig_path: str | None = None

    # OIDC configuration
    oidc_issuer: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: list[str] | None = None
    use_device_flow: bool = False
    oidc_callback_port: int = 8080

    # Token-based authentication
    token: str | None = None

    # Advanced options
    use_keyring: bool = False
    verify_ssl: bool = True
    ca_cert: str | None = None

    class Config:
        arbitrary_types_allowed = True
