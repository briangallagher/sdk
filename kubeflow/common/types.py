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
    """Base class for pluggable credential providers with automatic token refresh.

    Implement refresh_api_key_hook to provide custom token refresh logic.
    The hook is called before each Kubernetes API request.
    """

    @abc.abstractmethod
    def refresh_api_key_hook(self, config: client.Configuration) -> None:
        raise NotImplementedError()


class KubernetesBackendConfig(BaseModel):
    namespace: str | None = None
    config_file: str | None = None
    context: str | None = None
    client_configuration: client.Configuration | None = None
    token: str | None = None
    server: str | None = None
    verify_ssl: bool = True
    ca_cert: str | None = None
    credentials: TokenCredentialsBase | None = None

    class Config:
        arbitrary_types_allowed = True
