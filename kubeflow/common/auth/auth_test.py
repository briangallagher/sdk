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
from unittest.mock import patch
from urllib.parse import parse_qs

from kubernetes import client
import pytest
import requests
import responses

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

    calls: list[tuple[str, tuple, dict]] = []

    class FakeOIDCClientCredentials:
        def __init__(self, *args, **kwargs) -> None:
            calls.append(("init", args, kwargs))

        def refresh_api_key_hook(self, configuration: client.Configuration) -> None:
            configuration.api_key["authorization"] = "oidc-at"
            configuration.api_key_prefix["authorization"] = "Bearer"

    with patch(
        "kubeflow.common.auth.oidc.OIDCClientCredentials", FakeOIDCClientCredentials
    ):
        api = load_kubernetes_config(KubernetesBackendConfig())

    conf = api.configuration
    assert conf.host == "https://api.from.env"
    assert calls and calls[0][0] == "init"
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
        if name == "kubeflow.common.auth.oidc" and "OIDCClientCredentials" in (fromlist or ()):
            raise ImportError("simulated missing oidc module")
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


def test_oidc_env_integration_wires_hook_to_configuration(
    clear_kubeflow_env, monkeypatch
) -> None:
    """Env OIDC path wires an OIDCClientCredentials hook to the K8s Configuration."""

    hook_calls = {"n": 0}

    class FakeOIDCClientCredentials:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def refresh_api_key_hook(self, configuration: client.Configuration) -> None:
            hook_calls["n"] += 1
            configuration.api_key["authorization"] = "from-hook"
            configuration.api_key_prefix["authorization"] = "Bearer"

    monkeypatch.setenv("KUBEFLOW_API_HOST", "https://api/")
    monkeypatch.setenv("KUBEFLOW_OIDC_ISSUER", "https://issuer/")
    monkeypatch.setenv("KUBEFLOW_OIDC_CLIENT_ID", "c")
    monkeypatch.setenv("KUBEFLOW_OIDC_CLIENT_SECRET", "s")

    with patch(
        "kubeflow.common.auth.oidc.OIDCClientCredentials", FakeOIDCClientCredentials
    ):
        api = load_kubernetes_config(KubernetesBackendConfig())

    conf = api.configuration
    conf.refresh_api_key_hook(conf)
    assert hook_calls["n"] == 1
    assert conf.api_key["authorization"] == "from-hook"


def test_oidc_env_passes_correct_args_to_constructor(clear_kubeflow_env, monkeypatch) -> None:
    """Env OIDC passes issuer, client_id, client_secret to OIDCClientCredentials."""
    monkeypatch.setenv("KUBEFLOW_API_HOST", "https://api/")
    monkeypatch.setenv("KUBEFLOW_OIDC_ISSUER", "https://idp.example/realms/test")
    monkeypatch.setenv("KUBEFLOW_OIDC_CLIENT_ID", "my-client")
    monkeypatch.setenv("KUBEFLOW_OIDC_CLIENT_SECRET", "my-secret")

    captured: list[dict] = []

    class FakeOIDCClientCredentials:
        def __init__(self, issuer_url, client_id, client_secret) -> None:
            captured.append({
                "issuer_url": issuer_url,
                "client_id": client_id,
                "client_secret": client_secret,
            })

        def refresh_api_key_hook(self, configuration: client.Configuration) -> None:
            configuration.api_key["authorization"] = "t"
            configuration.api_key_prefix["authorization"] = "Bearer"

    with patch(
        "kubeflow.common.auth.oidc.OIDCClientCredentials", FakeOIDCClientCredentials
    ):
        load_kubernetes_config(KubernetesBackendConfig())

    assert len(captured) == 1
    assert captured[0]["issuer_url"] == "https://idp.example/realms/test"
    assert captured[0]["client_id"] == "my-client"
    assert captured[0]["client_secret"] == "my-secret"

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


# ---------------------------------------------------------------------------
# Error scenario tests (Strat AC4 — actionable authentication errors)
# ---------------------------------------------------------------------------


@responses.activate
def test_oidc_bad_credentials_raises_http_error() -> None:
    """Wrong client secret surfaces a clear HTTP 401 from the token endpoint."""
    responses.get(
        "https://issuer-err/.well-known/openid-configuration",
        json={"issuer": "https://issuer-err", "token_endpoint": "https://issuer-err/token"},
        status=200,
    )
    responses.post(
        "https://issuer-err/token",
        json={"error": "invalid_client", "error_description": "Bad client credentials"},
        status=401,
    )
    with pytest.raises(requests.HTTPError, match="401"):
        OIDCClientCredentials(
            issuer_url="https://issuer-err",
            client_id="cid",
            client_secret="wrong-secret",
        )


@responses.activate
def test_oidc_unreachable_issuer_raises_connection_error() -> None:
    """Unreachable IDP raises ConnectionError during discovery, not a generic 401."""
    responses.get(
        "https://unreachable/.well-known/openid-configuration",
        body=requests.ConnectionError("DNS resolution failed"),
    )
    with pytest.raises(requests.ConnectionError, match="DNS"):
        OIDCClientCredentials(
            issuer_url="https://unreachable",
            client_id="cid",
            client_secret="sec",
        )


@responses.activate
def test_oidc_discovery_returns_non_200_raises_http_error() -> None:
    """IDP returning 500 during discovery surfaces as HTTPError."""
    responses.get(
        "https://broken-idp/.well-known/openid-configuration",
        json={"error": "internal"},
        status=500,
    )
    with pytest.raises(requests.HTTPError, match="500"):
        OIDCClientCredentials(
            issuer_url="https://broken-idp",
            client_id="cid",
            client_secret="sec",
        )


@responses.activate
def test_oidc_issuer_mismatch_raises_value_error() -> None:
    """Discovery doc with mismatched issuer raises ValueError (SEC-4 mitigation)."""
    responses.get(
        "https://legit-issuer/.well-known/openid-configuration",
        json={
            "issuer": "https://evil.example",
            "token_endpoint": "https://evil.example/token",
        },
        status=200,
    )
    with pytest.raises(ValueError, match="issuer mismatch"):
        OIDCClientCredentials(
            issuer_url="https://legit-issuer",
            client_id="cid",
            client_secret="sec",
        )


@responses.activate
def test_oidc_token_endpoint_error_during_refresh_raises() -> None:
    """Token endpoint failure during refresh (not init) surfaces clearly."""
    responses.get(
        "https://issuer-ref-err/.well-known/openid-configuration",
        json={"issuer": "https://issuer-ref-err", "token_endpoint": "https://issuer-ref-err/token"},
        status=200,
    )
    responses.post(
        "https://issuer-ref-err/token",
        json={"access_token": "t1", "expires_in": 300},
        status=200,
    )
    responses.post(
        "https://issuer-ref-err/token",
        json={"error": "server_error"},
        status=500,
    )
    creds = OIDCClientCredentials(
        issuer_url="https://issuer-ref-err",
        client_id="cid",
        client_secret="sec",
    )
    creds._expires_at = 0.0
    conf = client.Configuration()
    with pytest.raises(requests.HTTPError, match="500"):
        creds.refresh_api_key_hook(conf)


# ---------------------------------------------------------------------------
# Security tests (SEC-1 repr redaction, SEC-5 monotonic clock)
# ---------------------------------------------------------------------------


@responses.activate
def test_repr_redacts_client_secret() -> None:
    """OIDCClientCredentials repr must never expose client_secret (SEC-1)."""
    responses.get(
        "https://issuer-repr/.well-known/openid-configuration",
        json={"issuer": "https://issuer-repr", "token_endpoint": "https://issuer-repr/token"},
        status=200,
    )
    responses.post(
        "https://issuer-repr/token",
        json={"access_token": "secret-token-value", "expires_in": 300},
        status=200,
    )
    creds = OIDCClientCredentials(
        issuer_url="https://issuer-repr",
        client_id="my-client",
        client_secret="super-secret-value",
    )
    r = repr(creds)
    assert "super-secret-value" not in r
    assert "secret-token-value" not in r
    assert "my-client" in r


@responses.activate
def test_repr_redacts_password() -> None:
    """OIDCPasswordCredentials repr must never expose password (SEC-1)."""
    responses.get(
        "https://issuer-pwrepr/.well-known/openid-configuration",
        json={"issuer": "https://issuer-pwrepr", "token_endpoint": "https://issuer-pwrepr/token"},
        status=200,
    )
    responses.post(
        "https://issuer-pwrepr/token",
        json={"access_token": "at", "expires_in": 300},
        status=200,
    )
    creds = OIDCPasswordCredentials(
        issuer_url="https://issuer-pwrepr",
        client_id="cid",
        username="alice",
        password="hunter2",
    )
    r = repr(creds)
    assert "hunter2" not in r
    assert "alice" in r


@responses.activate
def test_monotonic_clock_used_for_expiry() -> None:
    """Token expiry is tracked with time.monotonic, not time.time (SEC-5)."""
    import time as time_mod

    responses.get(
        "https://issuer-mono/.well-known/openid-configuration",
        json={"issuer": "https://issuer-mono", "token_endpoint": "https://issuer-mono/token"},
        status=200,
    )
    responses.post(
        "https://issuer-mono/token",
        json={"access_token": "t", "expires_in": 300},
        status=200,
    )
    before = time_mod.monotonic()
    creds = OIDCClientCredentials(
        issuer_url="https://issuer-mono",
        client_id="cid",
        client_secret="sec",
    )
    after = time_mod.monotonic()
    assert before + 270 - 1 <= creds._expires_at <= after + 270 + 1


# ---------------------------------------------------------------------------
# Multi-backend and shared credentials tests
# ---------------------------------------------------------------------------


def test_single_credentials_shared_across_multiple_backends(clear_kubeflow_env) -> None:
    """One credential object works when passed to multiple backend configs."""
    creds = _DummyTokenCreds()
    config_kwargs = {"credentials": creds, "server": "https://api.shared/"}

    api1 = load_kubernetes_config(KubernetesBackendConfig(**config_kwargs))
    api2 = load_kubernetes_config(KubernetesBackendConfig(**config_kwargs))

    api1.configuration.refresh_api_key_hook(api1.configuration)
    api2.configuration.refresh_api_key_hook(api2.configuration)

    assert creds.hook_calls == 2
    assert api1.configuration.api_key["authorization"] == "dummy-access-token"
    assert api2.configuration.api_key["authorization"] == "dummy-access-token"


# ---------------------------------------------------------------------------
# Custom credential provider tests (Vault-style, rotating tokens)
# ---------------------------------------------------------------------------


def test_vault_style_rotating_credentials(clear_kubeflow_env) -> None:
    """Enterprise Vault-style credentials that rotate on each call."""

    class VaultCredentials(TokenCredentialsBase):
        def __init__(self) -> None:
            self._call_count = 0

        def refresh_api_key_hook(self, config: client.Configuration) -> None:
            self._call_count += 1
            config.api_key["authorization"] = f"vault-token-{self._call_count}"
            config.api_key_prefix["authorization"] = "Bearer"

    creds = VaultCredentials()
    api = load_kubernetes_config(
        KubernetesBackendConfig(server="https://api.vault/", credentials=creds)
    )
    conf = api.configuration
    conf.refresh_api_key_hook(conf)
    assert conf.api_key["authorization"] == "vault-token-1"
    conf.refresh_api_key_hook(conf)
    assert conf.api_key["authorization"] == "vault-token-2"


def test_aws_sts_style_credentials(clear_kubeflow_env) -> None:
    """AWS STS-style credentials that assume a role and return a session token."""

    class STSCredentials(TokenCredentialsBase):
        def __init__(self, role_arn: str) -> None:
            self._role_arn = role_arn

        def refresh_api_key_hook(self, config: client.Configuration) -> None:
            config.api_key["authorization"] = f"sts-token-for-{self._role_arn}"
            config.api_key_prefix["authorization"] = "Bearer"

    creds = STSCredentials(role_arn="arn:aws:iam::123:role/ml-training")
    api = load_kubernetes_config(
        KubernetesBackendConfig(server="https://eks.us-east-1/", credentials=creds)
    )
    conf = api.configuration
    conf.refresh_api_key_hook(conf)
    assert conf.api_key["authorization"] == "sts-token-for-arn:aws:iam::123:role/ml-training"


# ---------------------------------------------------------------------------
# Resolution priority — full conflict test
# ---------------------------------------------------------------------------


def test_full_priority_credentials_wins_over_token_and_env(
    clear_kubeflow_env, monkeypatch
) -> None:
    """When credentials=, token=, AND env vars are all set, credentials wins."""
    monkeypatch.setenv("KUBEFLOW_TOKEN", "env-token")
    monkeypatch.setenv("KUBEFLOW_API_HOST", "https://env-host/")

    creds = _DummyTokenCreds()
    cfg = KubernetesBackendConfig(
        token="explicit-token",
        server="https://explicit-server/",
        credentials=creds,
    )
    api = load_kubernetes_config(cfg)
    conf = api.configuration
    conf.refresh_api_key_hook(conf)
    assert conf.api_key["authorization"] == "dummy-access-token"
    assert conf.host == "https://explicit-server"


def test_prebuilt_wins_over_everything(clear_kubeflow_env, monkeypatch) -> None:
    """Pre-built client_configuration wins over credentials, token, and env."""
    monkeypatch.setenv("KUBEFLOW_TOKEN", "env-token")
    monkeypatch.setenv("KUBEFLOW_API_HOST", "https://env/")

    prebuilt = client.Configuration()
    prebuilt.host = "https://prebuilt-wins/"
    prebuilt.api_key["authorization"] = "prebuilt-token"

    cfg = KubernetesBackendConfig(
        client_configuration=prebuilt,
        token="explicit-token",
        server="https://explicit/",
        credentials=_DummyTokenCreds(),
    )
    api = load_kubernetes_config(cfg)
    assert api.configuration.host == "https://prebuilt-wins/"
    assert api.configuration.api_key["authorization"] == "prebuilt-token"


# ---------------------------------------------------------------------------
# Backend wiring tests — Trainer, Spark, Optimizer use load_kubernetes_config
# ---------------------------------------------------------------------------


def test_trainer_backend_uses_load_kubernetes_config(clear_kubeflow_env) -> None:
    """TrainerClient's KubernetesBackend calls load_kubernetes_config with the config."""
    creds = _DummyTokenCreds()
    mock_client = client.ApiClient()

    with patch("kubeflow.common.auth_utils.load_kubernetes_config", return_value=mock_client) as m:
        from kubeflow.trainer.backends.kubernetes.backend import KubernetesBackend

        cfg = KubernetesBackendConfig(
            server="https://trainer-api/",
            credentials=creds,
            namespace="test-ns",
        )
        KubernetesBackend(cfg)

        m.assert_called_once()
        call_cfg = m.call_args[0][0]
        assert call_cfg.server == "https://trainer-api/"
        assert call_cfg.credentials is creds


def test_spark_backend_uses_load_kubernetes_config(clear_kubeflow_env) -> None:
    """SparkClient's KubernetesBackend calls load_kubernetes_config with the config."""
    creds = _DummyTokenCreds()
    mock_client = client.ApiClient()

    with patch("kubeflow.common.auth_utils.load_kubernetes_config", return_value=mock_client) as m:
        from kubeflow.spark.backends.kubernetes.backend import KubernetesBackend as SparkBackend

        cfg = KubernetesBackendConfig(
            server="https://spark-api/",
            credentials=creds,
            namespace="spark-ns",
        )
        SparkBackend(cfg)

        m.assert_called_once()
        call_cfg = m.call_args[0][0]
        assert call_cfg.server == "https://spark-api/"
        assert call_cfg.credentials is creds


def test_optimizer_backend_uses_load_kubernetes_config(clear_kubeflow_env) -> None:
    """OptimizerClient's KubernetesBackend calls load_kubernetes_config with the config.

    Optimizer creates an internal TrainerBackend too, so load_kubernetes_config is
    called twice (once for optimizer, once for the embedded trainer).
    """
    creds = _DummyTokenCreds()
    mock_client = client.ApiClient()

    with patch("kubeflow.common.auth_utils.load_kubernetes_config", return_value=mock_client) as m:
        from kubeflow.optimizer.backends.kubernetes.backend import (
            KubernetesBackend as OptimizerBackend,
        )

        cfg = KubernetesBackendConfig(
            server="https://optimizer-api/",
            credentials=creds,
            namespace="opt-ns",
        )
        OptimizerBackend(cfg)

        assert m.call_count == 2
        for call in m.call_args_list:
            call_cfg = call[0][0]
            assert call_cfg.server == "https://optimizer-api/"
            assert call_cfg.credentials is creds

