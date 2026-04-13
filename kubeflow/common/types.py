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

import abc

from kubernetes import client
from pydantic import BaseModel


class TokenCredentialsBase(abc.ABC):
    """Base class for pluggable credential providers.

    The refresh_api_key_hook method is called before every Kubernetes API
    request via Configuration.refresh_api_key_hook — the only auth extension
    point on the K8s Python client. Despite its name, this hook handles both
    initial token acquisition and refresh. Implementations should check token
    validity and only perform an exchange when needed.
    """

    @abc.abstractmethod
    def refresh_api_key_hook(self, config: client.Configuration) -> None:
        raise NotImplementedError()


class KubernetesBackendConfig(BaseModel):
    namespace: str | None = None
    config_file: str | None = None
    context: str | None = None
    client_configuration: client.Configuration | None = None
    # Auth fields
    token: str | None = None
    server: str | None = None
    verify_ssl: bool = True
    ca_cert: str | None = None
    # When set, ``server`` must also be set; wired via ``auth_utils.load_kubernetes_config``.
    credentials: TokenCredentialsBase | None = None

    class Config:
        arbitrary_types_allowed = True
