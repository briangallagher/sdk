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

"""Unit tests for :mod:`kubeflow.common.auth.kube_authkit_bridge`.

``AuthConfig`` and ``get_k8s_client`` are patched on the bridge module so tests
do not depend on kube-authkit behavior or installation.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
from kubernetes import client

from kubeflow.common.types import KubernetesBackendConfig


@pytest.fixture
def bridge_module():
    import kubeflow.common.auth.kube_authkit_bridge as mod

    return mod


@pytest.fixture
def authkit_available(bridge_module):
    """Force the bridge to behave as if kube-authkit were importable."""
    with patch.object(bridge_module, "KUBE_AUTHKIT_AVAILABLE", True):
        yield bridge_module


def test_prebuilt_client_configuration_returns_api_client_directly(
    authkit_available, bridge_module
):
    """When ``client_configuration`` is set, return ``ApiClient`` without calling kube-authkit."""
    configuration = client.Configuration()
    configuration.host = "https://example.test:6443"
    cfg = KubernetesBackendConfig(client_configuration=configuration)

    with patch.object(bridge_module, "kube_authkit_get_client") as mock_get_client:
        with patch.object(bridge_module, "AuthConfig") as mock_auth_config:
            result = bridge_module.get_kubernetes_client(cfg)

    assert isinstance(result, client.ApiClient)
    mock_get_client.assert_not_called()
    mock_auth_config.assert_not_called()


def test_oidc_auth_method_maps_to_auth_config(authkit_available, bridge_module):
    cfg = KubernetesBackendConfig(
        auth_method="oidc",
        oidc_issuer="https://issuer.example",
        client_id="my-client",
        client_secret="secret",
        scopes=["openid", "profile"],
        use_device_flow=True,
        oidc_callback_port=9000,
        use_keyring=True,
        verify_ssl=False,
        k8s_api_host="https://api.example:6443",
        ca_cert="/tmp/ca.pem",
    )
    fake_client = MagicMock()
    with patch.object(bridge_module, "kube_authkit_get_client", return_value=fake_client) as mock_get:
        with patch.object(bridge_module, "AuthConfig") as mock_auth_config:
            out = bridge_module.get_kubernetes_client(cfg)

    mock_auth_config.assert_called_once_with(
        verify_ssl=False,
        k8s_api_host="https://api.example:6443",
        ca_cert="/tmp/ca.pem",
        method="oidc",
        oidc_issuer="https://issuer.example",
        client_id="my-client",
        client_secret="secret",
        use_device_flow=True,
        oidc_callback_port=9000,
        scopes=["openid", "profile"],
        use_keyring=True,
    )
    mock_get.assert_called_once_with(mock_auth_config.return_value)
    assert out is fake_client


def test_openshift_auth_method_passes_token(authkit_available, bridge_module):
    cfg = KubernetesBackendConfig(
        auth_method="openshift",
        token="sha256~deadbeef",
        use_keyring=False,
    )
    with patch.object(bridge_module, "kube_authkit_get_client", return_value=MagicMock()) as mock_get:
        with patch.object(bridge_module, "AuthConfig") as mock_auth_config:
            bridge_module.get_kubernetes_client(cfg)

    mock_auth_config.assert_called_once_with(
        verify_ssl=True,
        method="openshift",
        token="sha256~deadbeef",
        use_keyring=False,
    )
    mock_get.assert_called_once()


def test_legacy_config_file_maps_to_kubeconfig_and_warns(
    authkit_available, bridge_module, caplog
):
    caplog.set_level(logging.WARNING)
    cfg = KubernetesBackendConfig(config_file="/legacy/kubeconfig")

    with patch.object(bridge_module, "kube_authkit_get_client", return_value=MagicMock()):
        with patch.object(bridge_module, "AuthConfig") as mock_auth_config:
            bridge_module.get_kubernetes_client(cfg)

    mock_auth_config.assert_called_once_with(
        verify_ssl=True,
        method="kubeconfig",
        kubeconfig_path="/legacy/kubeconfig",
    )
    assert any("deprecated" in r.message.lower() for r in caplog.records)


def test_legacy_context_only_warns_and_sets_kubeconfig_method(
    authkit_available, bridge_module, caplog
):
    caplog.set_level(logging.WARNING)
    cfg = KubernetesBackendConfig(context="my-context")

    with patch.object(bridge_module, "kube_authkit_get_client", return_value=MagicMock()):
        with patch.object(bridge_module, "AuthConfig") as mock_auth_config:
            bridge_module.get_kubernetes_client(cfg)

    mock_auth_config.assert_called_once_with(verify_ssl=True, method="kubeconfig")
    assert any("deprecated" in r.message.lower() for r in caplog.records)


def test_auto_detection_when_no_explicit_auth_params(authkit_available, bridge_module):
    cfg = KubernetesBackendConfig()

    with patch.object(bridge_module, "kube_authkit_get_client", return_value=MagicMock()):
        with patch.object(bridge_module, "AuthConfig") as mock_auth_config:
            bridge_module.get_kubernetes_client(cfg)

    mock_auth_config.assert_called_once_with(verify_ssl=True, method="auto")


def test_raises_import_error_when_kube_authkit_unavailable(bridge_module):
    cfg = KubernetesBackendConfig()

    with patch.object(bridge_module, "KUBE_AUTHKIT_AVAILABLE", False):
        with pytest.raises(ImportError, match="kube-authkit"):
            bridge_module.get_kubernetes_client(cfg)


def test_kubeconfig_path_and_verify_ssl_propagate(authkit_available, bridge_module):
    cfg = KubernetesBackendConfig(
        auth_method="kubeconfig",
        kubeconfig_path="/home/user/.kube/config",
        verify_ssl=False,
        k8s_api_host="https://cluster.local",
        ca_cert="/etc/pki/ca.pem",
    )

    with patch.object(bridge_module, "kube_authkit_get_client", return_value=MagicMock()):
        with patch.object(bridge_module, "AuthConfig") as mock_auth_config:
            bridge_module.get_kubernetes_client(cfg)

    mock_auth_config.assert_called_once_with(
        verify_ssl=False,
        k8s_api_host="https://cluster.local",
        kubeconfig_path="/home/user/.kube/config",
        ca_cert="/etc/pki/ca.pem",
        method="kubeconfig",
        use_keyring=False,
    )


def test_oidc_optional_scopes_omitted_when_none(authkit_available, bridge_module):
    cfg = KubernetesBackendConfig(
        auth_method="oidc",
        oidc_issuer="https://issuer",
        client_id="id",
        scopes=None,
    )

    with patch.object(bridge_module, "kube_authkit_get_client", return_value=MagicMock()):
        with patch.object(bridge_module, "AuthConfig") as mock_auth_config:
            bridge_module.get_kubernetes_client(cfg)

    _, kwargs = mock_auth_config.call_args
    assert "scopes" not in kwargs


def test_explicit_kubeconfig_does_not_emit_deprecation_warning(
    authkit_available, bridge_module, caplog
):
    caplog.set_level(logging.WARNING)
    cfg = KubernetesBackendConfig(
        auth_method="kubeconfig",
        kubeconfig_path="/path/config",
    )

    with patch.object(bridge_module, "kube_authkit_get_client", return_value=MagicMock()):
        with patch.object(bridge_module, "AuthConfig"):
            bridge_module.get_kubernetes_client(cfg)

    assert not any("deprecated" in r.message.lower() for r in caplog.records)


def test_kubeconfig_path_passed_with_auto_method(authkit_available, bridge_module):
    """``kubeconfig_path`` without ``auth_method`` still reaches kube-authkit on the auto path."""
    cfg = KubernetesBackendConfig(kubeconfig_path="/x/kubeconfig")

    with patch.object(bridge_module, "kube_authkit_get_client", return_value=MagicMock()):
        with patch.object(bridge_module, "AuthConfig") as mock_auth_config:
            bridge_module.get_kubernetes_client(cfg)

    mock_auth_config.assert_called_once_with(
        verify_ssl=True,
        kubeconfig_path="/x/kubeconfig",
        method="auto",
    )


def test_incluster_auth_method_maps_common_fields(authkit_available, bridge_module):
    cfg = KubernetesBackendConfig(
        auth_method="incluster",
        use_keyring=True,
        verify_ssl=False,
        k8s_api_host="https://kubernetes.default",
    )

    with patch.object(bridge_module, "kube_authkit_get_client", return_value=MagicMock()):
        with patch.object(bridge_module, "AuthConfig") as mock_auth_config:
            bridge_module.get_kubernetes_client(cfg)

    mock_auth_config.assert_called_once_with(
        verify_ssl=False,
        k8s_api_host="https://kubernetes.default",
        method="incluster",
        use_keyring=True,
    )


def test_openshift_without_token_omits_token_key(authkit_available, bridge_module):
    cfg = KubernetesBackendConfig(auth_method="openshift", token=None)

    with patch.object(bridge_module, "kube_authkit_get_client", return_value=MagicMock()):
        with patch.object(bridge_module, "AuthConfig") as mock_auth_config:
            bridge_module.get_kubernetes_client(cfg)

    _, kwargs = mock_auth_config.call_args
    assert "token" not in kwargs
