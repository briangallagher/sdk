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

"""Unit tests for Kubernetes auth helpers and OIDC credential providers."""

from __future__ import annotations

import builtins
import contextlib
import os
import sys
import types
from unittest.mock import patch
from urllib.parse import parse_qs

from kubernetes import client
import pytest
import responses

import kubeflow.common.auth.oidc as kf_oidc
from kubeflow.common.auth.oidc import OIDCClientCredentials, OIDCPasswordCredentials
from kubeflow.common.auth_utils import load_kubernetes_config
from kubeflow.common.types import KubernetesBackendConfig, TokenCredentialsBase


class _DummyTokenCreds(TokenCredentialsBase):
    """Concrete credentials for exercising TokenCredentialsBase + load_kubernetes_config."""

    def __init__(self) -> None:
        self.hook_calls = 0

    def refresh_api_key_hook(self, configuration: client.Configuration) -> None:
        self.hook_calls += 1
        configuration.api_key["authorization"] = "dummy-access-token"
        configuration.api_key_prefix["authorization"] = "Bearer"

def _http_request_body(body: bytes | str | None) -> str:
    if body is None:
        return ""
    return body.decode() if isinstance(body, bytes) else body


class _KubernetesOidcShim:
    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        client_secret: str,
        scopes: list[str] | None = None,
        verify: bool = True,
    ) -> None:
        del scopes, verify
        inner = kf_oidc.OIDCClientCredentials(issuer_url, client_id, client_secret)
        self.refresh_api_key_hook = inner.refresh_api_key_hook


def _kubernetes_oidc_shim_module():
    import types as std_types
    m = std_types.ModuleType("kubernetes_oidc")
    m.OIDCClientCredentials = _KubernetesOidcShim
    return m


@pytest.fixture(autouse=True)
def _reset_responses_registry() -> None:
    with contextlib.suppress(Exception):
        responses.reset()
    yield


@pytest.fixture
def clear_kubeflow_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("KUBEFLOW_"):
            monkeypatch.delenv(key, raising=False)


def test_token_credentials_base_cannot_be_instantiated() -> None:
    with pytest.raises(TypeError, match="abstract"):
        TokenCredentialsBase()  # type: ignore[abstract]


def test_custom_credentials_used_with_load_kubernetes_config(clear_kubeflow_env) -> None:
    creds = _DummyTokenCreds()
    cfg = KubernetesBackendConfig(server="https://api.example/", credentials=creds)

    api = load_kubernetes_config(cfg)
    conf = api.configuration
    assert conf.host == "https://api.example"
    # ApiClient may wrap or copy Configuration; assert behavior, not object identity.
    assert callable(conf.refresh_api_key_hook)
    conf.refresh_api_key_hook(conf)
    assert creds.hook_calls == 1
    assert conf.api_key.get("authorization") == "dummy-access-token"
    assert conf.api_key_prefix.get("authorization") == "Bearer"


def test_load_kubernetes_config_prebuilt_client_configuration(clear_kubeflow_env) -> None:
    prebuilt = client.Configuration()
    prebuilt.host = "https://prebuilt.example/"
    cfg = KubernetesBackendConfig(client_configuration=prebuilt)

    with patch("kubeflow.common.auth_utils.client.ApiClient") as api_client_cls:
        load_kubernetes_config(cfg)
    api_client_cls.assert_called_once_with(prebuilt)


def test_load_kubernetes_config_prebuilt_wins_over_kubeflow_token_env(
    clear_kubeflow_env, monkeypatch
) -> None:
    monkeypatch.setenv("KUBEFLOW_TOKEN", "env-should-not-win")
    monkeypatch.setenv("KUBEFLOW_API_HOST", "https://env/")
    prebuilt = client.Configuration()
    prebuilt.host = "https://prebuilt/"
    cfg = KubernetesBackendConfig(client_configuration=prebuilt)

    api = load_kubernetes_config(cfg)
    assert api.configuration.host == "https://prebuilt/"


def test_load_kubernetes_config_pluggable_credentials_wires_hook(clear_kubeflow_env) -> None:
    creds = _DummyTokenCreds()
    cfg = KubernetesBackendConfig(
        server="https://cluster.example/",
        credentials=creds,
        verify_ssl=False,
        ca_cert="/tmp/ca.pem",
    )

    api = load_kubernetes_config(cfg)
    conf = api.configuration
    assert callable(conf.refresh_api_key_hook)
    assert conf.verify_ssl is False
    assert conf.ssl_ca_cert == "/tmp/ca.pem"


def test_load_kubernetes_config_credentials_requires_server(clear_kubeflow_env) -> None:
    with pytest.raises(ValueError, match="server"):
        load_kubernetes_config(
            KubernetesBackendConfig(credentials=_DummyTokenCreds()),
        )


def test_load_kubernetes_config_explicit_token_and_server(clear_kubeflow_env) -> None:
    cfg = KubernetesBackendConfig(
        token="s3cr3t",
        server="https://api.k8s/",
        verify_ssl=True,
        ca_cert="/etc/ca.crt",
    )

    api = load_kubernetes_config(cfg)
    conf = api.configuration
    assert conf.host == "https://api.k8s"
    assert conf.api_key["authorization"] == "s3cr3t"
    assert conf.api_key_prefix["authorization"] == "Bearer"
    assert conf.ssl_ca_cert == "/etc/ca.crt"


def test_load_kubernetes_config_explicit_token_requires_server(clear_kubeflow_env) -> None:
    with pytest.raises(ValueError, match="server"):
        load_kubernetes_config(KubernetesBackendConfig(token="only-token"))


def test_load_kubernetes_config_explicit_token_beats_env_token(
    clear_kubeflow_env, monkeypatch
) -> None:
    monkeypatch.setenv("KUBEFLOW_TOKEN", "from-env")
    monkeypatch.setenv("KUBEFLOW_API_HOST", "https://env-host/")
    cfg = KubernetesBackendConfig(token="from-cfg", server="https://api.cfg/")

    api = load_kubernetes_config(cfg)
    assert api.configuration.api_key["authorization"] == "from-cfg"
    assert api.configuration.host == "https://api.cfg"


def test_load_kubernetes_config_kubeflow_token_env(clear_kubeflow_env, monkeypatch) -> None:
    monkeypatch.setenv("KUBEFLOW_TOKEN", "env-token")
    monkeypatch.setenv("KUBEFLOW_API_HOST", "https://env-host/")
    cfg = KubernetesBackendConfig(verify_ssl=False)

    api = load_kubernetes_config(cfg)
    conf = api.configuration
    assert conf.host == "https://env-host"
    assert conf.api_key["authorization"] == "env-token"
    assert conf.api_key_prefix["authorization"] == "Bearer"
    assert conf.verify_ssl is False


def test_load_kubernetes_config_oidc_env_client_credentials(
    clear_kubeflow_env, monkeypatch
) -> None:
    monkeypatch.setenv("KUBEFLOW_API_HOST", "https://api.from.env/")
    monkeypatch.setenv("KUBEFLOW_OIDC_ISSUER", "https://issuer.example/idp")
    monkeypatch.setenv("KUBEFLOW_OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("KUBEFLOW_OIDC_CLIENT_SECRET", "csecret")

    calls: list[tuple[str, dict]] = []

    class FakeOIDCClientCredentials:
        def __init__(self, **kwargs) -> None:
            calls.append(("init", kwargs))

        def refresh_api_key_hook(self, configuration: client.Configuration) -> None:
            configuration.api_key["authorization"] = "oidc-at"
            configuration.api_key_prefix["authorization"] = "Bearer"

    fake_mod = types.ModuleType("kubernetes_oidc")
    fake_mod.OIDCClientCredentials = FakeOIDCClientCredentials
    monkeypatch.setitem(sys.modules, "kubernetes_oidc", fake_mod)

    api = load_kubernetes_config(KubernetesBackendConfig())
    monkeypatch.delitem(sys.modules, "kubernetes_oidc", raising=False)

    conf = api.configuration
    assert conf.host == "https://api.from.env"
    assert calls and calls[0][0] == "init"
    init_kw = calls[0][1]
    assert init_kw["issuer_url"] == "https://issuer.example/idp"
    assert init_kw["client_id"] == "cid"
    assert init_kw["client_secret"] == "csecret"
    assert callable(conf.refresh_api_key_hook)
    conf.refresh_api_key_hook(conf)
    assert conf.api_key["authorization"] == "oidc-at"


def test_load_kubernetes_config_oidc_env_import_error(clear_kubeflow_env, monkeypatch) -> None:
    monkeypatch.setenv("KUBEFLOW_API_HOST", "https://api/")
    monkeypatch.setenv("KUBEFLOW_OIDC_ISSUER", "https://issuer/")
    monkeypatch.setenv("KUBEFLOW_OIDC_CLIENT_ID", "id")
    monkeypatch.setenv("KUBEFLOW_OIDC_CLIENT_SECRET", "sec")

    real_import = builtins.__import__

    def blocking_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[no-untyped-def]
        if name == "kubernetes_oidc":
            raise ImportError("simulated missing kubernetes_oidc")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocking_import)
    with pytest.raises(ImportError, match="kubeflow\\[oidc\\]"):
        load_kubernetes_config(KubernetesBackendConfig())
    monkeypatch.setattr(builtins, "__import__", real_import)


def test_load_kubernetes_config_partial_oidc_env_falls_through_to_kubeconfig(
    clear_kubeflow_env, monkeypatch
) -> None:
    monkeypatch.setenv("KUBEFLOW_OIDC_ISSUER", "https://issuer/")
    cfg = KubernetesBackendConfig(config_file="/tmp/kubeconfig")

    with (
        patch("kubeflow.common.auth_utils.common_utils.is_running_in_k8s", return_value=False),
        patch("kubeflow.common.auth_utils.config.load_kube_config") as load_kc,
        patch("kubeflow.common.auth_utils.config.load_incluster_config") as load_ic,
        patch("kubeflow.common.auth_utils.client.ApiClient") as api_client_cls,
    ):
        load_kubernetes_config(cfg)

    load_kc.assert_called_once_with(config_file="/tmp/kubeconfig", context=None)
    load_ic.assert_not_called()
    api_client_cls.assert_called_once_with(None)


def test_load_kubernetes_config_kubeconfig_fallback(clear_kubeflow_env) -> None:
    cfg = KubernetesBackendConfig(config_file="/tmp/kubeconfig")

    with (
        patch("kubeflow.common.auth_utils.common_utils.is_running_in_k8s", return_value=False),
        patch("kubeflow.common.auth_utils.config.load_kube_config") as load_kc,
        patch("kubeflow.common.auth_utils.config.load_incluster_config") as load_ic,
        patch("kubeflow.common.auth_utils.client.ApiClient") as api_client_cls,
    ):
        load_kubernetes_config(cfg)

    load_kc.assert_called_once_with(config_file="/tmp/kubeconfig", context=None)
    load_ic.assert_not_called()
    api_client_cls.assert_called_once_with(None)


def test_load_kubernetes_config_incluster_fallback(clear_kubeflow_env) -> None:
    cfg = KubernetesBackendConfig()

    with (
        patch("kubeflow.common.auth_utils.common_utils.is_running_in_k8s", return_value=True),
        patch("kubeflow.common.auth_utils.config.load_kube_config") as load_kc,
        patch("kubeflow.common.auth_utils.config.load_incluster_config") as load_ic,
        patch("kubeflow.common.auth_utils.client.ApiClient") as api_client_cls,
    ):
        load_kubernetes_config(cfg)

    load_kc.assert_not_called()
    load_ic.assert_called_once_with()
    api_client_cls.assert_called_once_with(None)


def test_oidc_device_and_browser_placeholders_accepted_via_credentials(
    clear_kubeflow_env,
) -> None:
    """Device and browser flows are used via credentials=… (not env); hooks must wire."""

    class FakeDevice(TokenCredentialsBase):
        def refresh_api_key_hook(self, configuration: client.Configuration) -> None:
            configuration.api_key["authorization"] = "device"
            configuration.api_key_prefix["authorization"] = "Bearer"

    class FakeBrowser(TokenCredentialsBase):
        def refresh_api_key_hook(self, configuration: client.Configuration) -> None:
            configuration.api_key["authorization"] = "browser"
            configuration.api_key_prefix["authorization"] = "Bearer"

    for creds, expected in ((FakeDevice(), "device"), (FakeBrowser(), "browser")):
        api = load_kubernetes_config(
            KubernetesBackendConfig(server="https://apiserver/", credentials=creds)
        )
        conf = api.configuration
        conf.refresh_api_key_hook(conf)
        assert conf.api_key["authorization"] == expected


def test_kubernetes_oidc_integration_mocked_http_client_credentials(
    clear_kubeflow_env, monkeypatch
) -> None:
    """Env OIDC path wires a kubernetes_oidc-style credential object to the K8s hook."""

    hook_calls = {"n": 0}

    class HookCreds:
        def refresh_api_key_hook(self, configuration: client.Configuration) -> None:
            hook_calls["n"] += 1
            configuration.api_key["authorization"] = "from-hook"
            configuration.api_key_prefix["authorization"] = "Bearer"

    hook = HookCreds()

    class FakeOIDCClientCredentials:
        def __init__(self, *args, **kwargs) -> None:
            pass

        refresh_api_key_hook = hook.refresh_api_key_hook

    fake_mod = types.ModuleType("kubernetes_oidc")
    fake_mod.OIDCClientCredentials = FakeOIDCClientCredentials
    monkeypatch.setitem(sys.modules, "kubernetes_oidc", fake_mod)

    monkeypatch.setenv("KUBEFLOW_API_HOST", "https://api/")
    monkeypatch.setenv("KUBEFLOW_OIDC_ISSUER", "https://issuer/")
    monkeypatch.setenv("KUBEFLOW_OIDC_CLIENT_ID", "c")
    monkeypatch.setenv("KUBEFLOW_OIDC_CLIENT_SECRET", "s")

    api = load_kubernetes_config(KubernetesBackendConfig())

    monkeypatch.delitem(sys.modules, "kubernetes_oidc", raising=False)

    conf = api.configuration
    conf.refresh_api_key_hook(conf)
    assert hook_calls["n"] == 1
    assert conf.api_key["authorization"] == "from-hook"


def test_kubeflow_oidc_scopes_passed_to_oidc_constructor(clear_kubeflow_env, monkeypatch) -> None:
    monkeypatch.setenv("KUBEFLOW_API_HOST", "https://api/")
    monkeypatch.setenv("KUBEFLOW_OIDC_ISSUER", "https://issuer/")
    monkeypatch.setenv("KUBEFLOW_OIDC_CLIENT_ID", "c")
    monkeypatch.setenv("KUBEFLOW_OIDC_CLIENT_SECRET", "s")
    monkeypatch.setenv("KUBEFLOW_OIDC_SCOPES", "openid profile email")

    inits: list[dict] = []

    class FakeOIDCClientCredentials:
        def __init__(self, **kwargs) -> None:
            inits.append(kwargs)

        def refresh_api_key_hook(self, configuration: client.Configuration) -> None:
            configuration.api_key["authorization"] = "t"
            configuration.api_key_prefix["authorization"] = "Bearer"

    fake_mod = types.ModuleType("kubernetes_oidc")
    fake_mod.OIDCClientCredentials = FakeOIDCClientCredentials
    monkeypatch.setitem(sys.modules, "kubernetes_oidc", fake_mod)

    load_kubernetes_config(KubernetesBackendConfig())
    monkeypatch.delitem(sys.modules, "kubernetes_oidc", raising=False)

    assert inits[0].get("scopes") == ["openid", "profile", "email"]

@responses.activate
def test_oidc_client_credentials_discovery_and_exchange_on_init() -> None:
    responses.get(
        "https://issuer-disco/.well-known/openid-configuration",
        json={"token_endpoint": "https://issuer-disco/token"},
        status=200,
    )
    responses.post(
        "https://issuer-disco/token",
        json={"access_token": "at1", "expires_in": 300},
        status=200,
    )
    creds = OIDCClientCredentials(
        issuer_url="https://issuer-disco/",
        client_id="my-id",
        client_secret="my-secret",
    )
    posts = [c for c in responses.calls if c.request.method == "POST"]
    assert len(posts) == 1
    params = parse_qs(_http_request_body(posts[0].request.body))
    assert params["grant_type"] == ["client_credentials"]
    conf = client.Configuration()
    creds.refresh_api_key_hook(conf)
    assert conf.api_key["authorization"] == "at1"


@responses.activate
def test_oidc_client_credentials_hook_skips_exchange_while_valid() -> None:
    responses.get(
        "https://issuer-skip/.well-known/openid-configuration",
        json={"token_endpoint": "https://issuer-skip/token"},
        status=200,
    )
    responses.post(
        "https://issuer-skip/token",
        json={"access_token": "at1", "expires_in": 3600},
        status=200,
    )
    creds = OIDCClientCredentials(
        issuer_url="https://issuer-skip/",
        client_id="cid",
        client_secret="sec",
    )
    posts_after_init = [c for c in responses.calls if c.request.method == "POST"]
    creds._expires_at = float("inf")
    conf = client.Configuration()
    creds.refresh_api_key_hook(conf)
    posts_after_hook = [c for c in responses.calls if c.request.method == "POST"]
    assert len(posts_after_hook) == len(posts_after_init)


@responses.activate
def test_oidc_client_credentials_hook_re_exchanges_when_expired() -> None:
    responses.get(
        "https://issuer-reex/.well-known/openid-configuration",
        json={"token_endpoint": "https://issuer-reex/token"},
        status=200,
    )
    responses.post(
        "https://issuer-reex/token",
        json={"access_token": "first", "expires_in": 100},
        status=200,
    )
    responses.post(
        "https://issuer-reex/token",
        json={"access_token": "second", "expires_in": 100},
        status=200,
    )
    creds = OIDCClientCredentials(
        issuer_url="https://issuer-reex/",
        client_id="cid",
        client_secret="sec",
    )
    assert len([c for c in responses.calls if c.request.method == "POST"]) == 1
    creds._expires_at = 0.0
    conf = client.Configuration()
    creds.refresh_api_key_hook(conf)
    assert len([c for c in responses.calls if c.request.method == "POST"]) == 2
    assert conf.api_key["authorization"] == "second"


@responses.activate
def test_oidc_password_credentials_grant_and_hook() -> None:
    responses.get(
        "https://issuer-pw/.well-known/openid-configuration",
        json={"token_endpoint": "https://issuer-pw/token"},
        status=200,
    )
    responses.post(
        "https://issuer-pw/token",
        json={"access_token": "pw-at", "expires_in": 120},
        status=200,
    )
    creds = OIDCPasswordCredentials(
        issuer_url="https://issuer-pw/",
        client_id="cid",
        username="alice",
        password="wonderland",
    )
    posts = [c for c in responses.calls if c.request.method == "POST"]
    assert len(posts) == 1
    params = parse_qs(_http_request_body(posts[0].request.body))
    assert params["grant_type"] == ["password"]
    conf = client.Configuration()
    creds.refresh_api_key_hook(conf)
    assert conf.api_key["authorization"] == "pw-at"


@responses.activate
def test_oidc_password_refresh_hook_reloads_when_expired() -> None:
    responses.get(
        "https://issuer-pwre/.well-known/openid-configuration",
        json={"token_endpoint": "https://issuer-pwre/token"},
        status=200,
    )
    responses.post(
        "https://issuer-pwre/token",
        json={"access_token": "a", "expires_in": 50},
        status=200,
    )
    responses.post(
        "https://issuer-pwre/token",
        json={"access_token": "b", "expires_in": 50},
        status=200,
    )
    creds = OIDCPasswordCredentials(
        issuer_url="https://issuer-pwre/",
        client_id="cid",
        username="u",
        password="p",
    )
    creds._expires_at = 0.0
    conf = client.Configuration()
    creds.refresh_api_key_hook(conf)
    assert len([c for c in responses.calls if c.request.method == "POST"]) == 2
    assert conf.api_key["authorization"] == "b"

