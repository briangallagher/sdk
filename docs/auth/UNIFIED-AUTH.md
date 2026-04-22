# Kubeflow SDK — Unified Authentication

The Kubeflow SDK provides a unified authentication layer that lets users configure credentials once and use them across every SDK client: Trainer (Kubernetes API), Pipelines (REST API), Model Registry (REST API), Spark (Kubernetes API), and Optimizer (Kubernetes API). The system is built in two layers — an SDK-level orchestration layer that resolves credentials through a deterministic chain, and a generic OIDC protocol layer that handles discovery, token exchange, refresh, and all standard grant types. Together, they give every Kubeflow component a single, consistent authentication interface with zero additional dependencies beyond the `requests` library that is already part of the SDK dependency tree.

---

## Table of Contents

1. [What the Unified Auth System Is](#1-what-the-unified-auth-system-is)
2. [Design Strategy](#2-design-strategy)
3. [How It Works](#3-how-it-works)
4. [The OIDC Subpackage](#4-the-oidc-subpackage)
5. [Dual Auth Design](#5-dual-auth-design)
6. [What This Doesn't Cover](#6-what-this-doesnt-cover)
7. [Error Handling](#7-error-handling)
8. [Security Considerations](#8-security-considerations)
9. [Future Enhancement: Token Provider Callable for REST Clients](#9-future-enhancement-token-provider-callable-for-rest-clients)

---

## 1. What the Unified Auth System Is

The unified auth system lives in two packages inside the SDK:

| Package | Purpose | Coupling |
|---------|---------|----------|
| `kubeflow.common.auth` (top level: `types.py`, `resolution.py`, `errors.py`, `identity.py`) | SDK auth orchestration — credential resolution (`resolve_credentials`), K8s client construction (`load_kubernetes_config`), environment variable handling, identity propagation, error hierarchy | Kubeflow-specific |
| `kubeflow.common.auth.oidc` (subpackage: `discovery.py`, `base.py`, `client_credentials.py`, `password.py`, `device_flow.py`, `browser_flow.py`, `keyring.py`) | OIDC protocol implementation — discovery, token exchange, refresh, all grant types | Generic, zero Kubeflow imports |
| `kubeflow.common.types` | `KubernetesBackendConfig` Pydantic model used by Trainer and other K8s backends | Kubeflow-specific |

### Key Types

#### `TokenCredentialsBase`

The abstract base class that defines the contract for pluggable credentials. Any object that implements this protocol can be passed as `credentials=` on `KubernetesBackendConfig`:

```python
# kubeflow/common/auth/types.py
@runtime_checkable
class TokenCredentialsBase(Protocol):
    def refresh_api_key_hook(self, config: Configuration) -> None: ...
    def get_token(self) -> str: ...
```

`TokenCredentialsBase` is a `typing.Protocol` with `@runtime_checkable`, not an ABC. This means OIDC credential classes don't need to inherit from it — they just need to implement the two methods. This is critical for keeping the `oidc/` subpackage free of Kubeflow imports.

The `refresh_api_key_hook` method is called by the Kubernetes Python client before every API request. Implementations must write a valid bearer token into `config.api_key["authorization"]`.

#### `KubernetesBackendConfig`

A Pydantic model that holds the full set of options for connecting to a Kubernetes cluster. Every SDK client that targets the Kubernetes API accepts this configuration:

```python
# kubeflow/common/types.py
class KubernetesBackendConfig(BaseModel):
    namespace: str | None = None
    config_file: str | None = None
    context: str | None = None
    client_configuration: client.Configuration | None = None
    server: str | None = None
    token: str | None = None
    credentials: TokenCredentialsBase | None = None
    verify_ssl: bool = True
    ca_cert: str | None = None

    class Config:
        arbitrary_types_allowed = True
```

Fields are evaluated in a specific order by `load_kubernetes_config()` (detailed in section 3). Users supply only what they need — the resolution chain fills in the rest.

#### OIDC Credential Classes

All four OIDC credential classes live in `kubeflow.common.auth` and implement `TokenCredentialsBase`:

| Class | Grant Type | RFC | Primary Use Case |
|-------|-----------|-----|-----------------|
| `OIDCClientCredentials` | `client_credentials` | [RFC 6749 §4.4](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) | CI/CD pipelines, service-to-service |
| `OIDCPasswordCredentials` | `password` | [RFC 6749 §4.3](https://datatracker.ietf.org/doc/html/rfc6749#section-4.3) | Testing, legacy systems |
| `OIDCDeviceFlowCredentials` | `urn:ietf:params:oauth:grant-type:device_code` | [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) | Headless notebooks, remote CLI |
| `OIDCBrowserFlowCredentials` | `authorization_code` + PKCE | [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | Local development with browser |

Every credential class provides two ways to obtain a token:

1. **`refresh_api_key_hook(config)`** — writes the bearer token into a Kubernetes `Configuration` object. Used by Kubernetes-backed clients (Trainer, Spark, Optimizer).
2. **`get_token() -> str`** — returns the raw access token as a string. Used by REST-backed clients (Pipelines, Model Registry).

Both interfaces share the same internal state: the same token, the same expiry tracking, and the same refresh logic. A refresh triggered through either interface updates both.

#### `OIDCProviderMetadata`

A frozen dataclass returned by OIDC discovery that holds the provider endpoints:

```python
# kubeflow/common/auth/oidc/discovery.py
@dataclass(frozen=True)
class OIDCProviderMetadata:
    token_endpoint: str
    authorization_endpoint: str | None = None
    device_authorization_endpoint: str | None = None
    issuer: str | None = None
```

#### `resolve_credentials()`

The shared credential resolution function used by **both** K8s and REST wrappers:

```python
# kubeflow/common/auth/resolution.py
def resolve_credentials(
    *,
    credentials: TokenCredentialsBase | None = None,
    token: str | None = None,
    verify_ssl: bool = True,
    ca_cert: str | None = None,
) -> TokenCredentialsBase | None:
```

Resolution order:

1. Explicit `credentials` object (returned as-is)
2. Explicit `token` → wrapped in a static credentials object
3. `KUBEFLOW_OIDC_*` env vars → `OIDCClientCredentials`
4. `KUBEFLOW_TOKEN` env var → static credentials object
5. `None` (nothing found)

K8s wrappers pass the result to `load_kubernetes_config(credentials=...)`. REST wrappers call `creds.get_token()`. This is the function that makes "configure once, use everywhere" work — including for REST clients that don't know about the Kubernetes API.

#### `load_kubernetes_config()`

Builds a Kubernetes `ApiClient`. Calls `resolve_credentials()` internally, then falls back to kubeconfig and in-cluster service account:

```python
# kubeflow/common/auth/resolution.py
def load_kubernetes_config(
    *,
    config_file: str | None = None,
    context: str | None = None,
    client_configuration: client.Configuration | None = None,
    token: str | None = None,
    server: str | None = None,
    credentials: TokenCredentialsBase | None = None,
    verify_ssl: bool = True,
    ca_cert: str | None = None,
) -> client.ApiClient:
```

This function is called by every Kubernetes-backed backend (Trainer, Spark, Optimizer) during initialization.

---

## 2. Design Strategy

### Two-Layer Architecture

The auth system is deliberately split into two layers with different responsibilities and different levels of coupling:

**Layer 1: SDK Auth Orchestration** (`kubeflow.common.auth.resolution`, `kubeflow.common.auth.types`, `kubeflow.common.auth.identity`, `kubeflow.common.auth.errors`)

This layer is Kubeflow-specific. It understands the Kubeflow SDK's conventions, environment variables, and client structure. It answers the question: *given the user's configuration, which authentication method should be used?* The resolution chain, the `KUBEFLOW_OIDC_*` and `KUBEFLOW_TOKEN` environment variables, and the `KubernetesBackendConfig` model all live here.

**Layer 2: OIDC Protocol Implementation** (`kubeflow.common.auth.oidc`)

This layer is generic. It implements the OIDC specification — discovery, token exchange, token refresh, and all four standard grant types — without importing anything from `kubeflow.*`. The OIDC classes implement the `refresh_api_key_hook` and `get_token` methods that `TokenCredentialsBase` requires, but they don't inherit from it (it's a Protocol, not an ABC). This means the `oidc/` subpackage has zero Kubeflow imports and can be used by any Python project that needs OIDC authentication against a Kubernetes API server.

### Why Two Layers?

The split exists because OIDC protocol mechanics are not Kubeflow-specific. Any Kubernetes user authenticating against an OIDC provider needs the same discovery, exchange, and refresh logic. By isolating the protocol implementation, the SDK gains:

1. **Testability** — OIDC classes can be unit-tested against mock HTTP responses without any Kubeflow infrastructure.
2. **Reusability** — other projects (CodeFlare SDK, standalone KFP client, etc.) can reuse the OIDC layer without depending on the full Kubeflow SDK.
3. **Extractability** — the OIDC subpackage can be lifted into a standalone PyPI package (`kubernetes-oidc`) when demand warrants, without changing any of its internal code.

### Why Not In-Tree in the Kubernetes Python Client?

The Kubernetes Python client is auto-generated from the OpenAPI spec and deliberately minimal in its auth handling. It provides the `refresh_api_key_hook` extension point but does not implement OIDC itself. Adding OIDC to the generated client would require:

- Manual code in an auto-generated project
- Agreement from all Kubernetes client maintainers
- A dependency on `requests` that the K8s client currently doesn't have

The Kubeflow SDK's approach is to use the existing extension point (`refresh_api_key_hook`) and implement OIDC externally. This is the same pattern used by `google-auth` for GKE authentication — an external library that plugs into the K8s client's auth hooks.

### Zero Additional Dependencies

All four credential classes require nothing beyond `requests`, which is already a transitive dependency of the Kubeflow SDK. The interactive flows (device code, browser PKCE) use only the Python standard library (`http.server`, `webbrowser`, `hashlib`, `secrets`, `threading`). This eliminates dependency conflicts and keeps the install lightweight.

Optional keyring integration (for persistent token storage across sessions) is available via `pip install kubeflow[oidc-keyring]`.

---

## 3. How It Works

### 3.1 Client Credentials Flow — End to End

This is the most common flow for CI/CD and automated environments. Here is every step from credential construction to API call:

```python
from kubeflow.trainer import TrainerClient
from kubeflow.common.auth import OIDCClientCredentials

# Step 1: Construct credentials.
# This immediately performs OIDC discovery against the issuer.
creds = OIDCClientCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-sdk",
    client_secret="my-client-secret",
)

# Step 2: Pass credentials to a client.
# The TrainerClient creates a KubernetesBackendConfig internally.
client = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.mycluster.example.com:6443",
})

# Step 3: Use the client normally.
# On the first API call, refresh_api_key_hook fires, which triggers
# a client_credentials token exchange. Subsequent calls reuse the
# cached token until it expires.
client.list_jobs()
```

**What happens during construction (`OIDCClientCredentials.__init__`):**

1. The `issuer_url` is normalized (trailing slash stripped).
2. An HTTP GET is sent to `{issuer_url}/.well-known/openid-configuration`.
3. The response is parsed to extract `token_endpoint`, `authorization_endpoint`, and `device_authorization_endpoint`.
4. The response's `issuer` field is compared against the requested `issuer_url`. If they don't match, a `ValueError` is raised (see [Security Considerations](#8-security-considerations)).
5. The credentials object is ready but has not yet obtained a token. `_access_token` is `None`, `_expires_at` is `0.0`.

**What happens on the first API call:**

1. The Kubernetes Python client calls `refresh_api_key_hook(config)` before sending the HTTP request.
2. The hook sees `_access_token is None` and calls `_do_token_exchange()`.
3. `_do_token_exchange()` POSTs to the token endpoint with `grant_type=client_credentials`, `client_id`, and `client_secret`.
4. The response provides `access_token`, optionally `refresh_token`, and `expires_in`.
5. The token is cached. `_expires_at` is set to `time.monotonic() + expires_in - 30` (the 30-second buffer ensures the token is refreshed before actual expiry).
6. The hook writes the token into `config.api_key["authorization"]` and sets `config.api_key_prefix["authorization"]` to `"Bearer"`.
7. The Kubernetes client proceeds with the now-authenticated request.

### 3.2 Token Refresh Lifecycle

Token refresh is automatic and transparent. The credential classes track expiry using a monotonic clock and refresh proactively:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Token Lifecycle                              │
│                                                                  │
│  ┌──────────┐   Token     ┌──────────┐  Expired?  ┌──────────┐ │
│  │  No Token │──exchange──▶│  Cached  │───yes─────▶│ Refresh  │ │
│  │  (_access │             │  Token   │            │  Token   │ │
│  │  _token   │             │          │───no──┐    │          │ │
│  │  is None) │             │          │◀──────┘    │          │ │
│  └──────────┘              └──────────┘            └─────┬────┘ │
│                                                          │      │
│                              ┌──────────┐                │      │
│                              │ Fall back│◀──refresh──────┘      │
│                              │ to full  │   failed              │
│                              │ exchange │                       │
│                              └──────────┘                       │
└─────────────────────────────────────────────────────────────────┘
```

**Expiry tracking:**

```python
# After every successful token exchange or refresh:
self._expires_at = time.monotonic() + token_data.get("expires_in", 300) - _EXPIRY_BUFFER_SECONDS
```

The 30-second buffer (`_EXPIRY_BUFFER_SECONDS = 30`) means the SDK considers a token expired 30 seconds before the server does. This prevents race conditions where a token expires in transit.

**Refresh logic (`_do_refresh`):**

```python
def _do_refresh(self) -> dict[str, Any]:
    if self._refresh_token:
        try:
            return self._exchange({
                "grant_type": "refresh_token",
                "client_id": self._client_id,
                "refresh_token": self._refresh_token,
            })
        except requests.HTTPError:
            pass
    return self._do_token_exchange()
```

The refresh strategy is:
1. If a `refresh_token` is available, attempt a refresh token exchange.
2. If the refresh fails (token revoked, expired, etc.), fall back to a full token exchange using the original credentials.
3. The fallback ensures that transient refresh failures don't cause permanent auth failures.

**Expiry check (`_is_expired`):**

```python
def _is_expired(self) -> bool:
    return time.monotonic() >= self._expires_at
```

`time.monotonic()` is used instead of `time.time()` because it is immune to system clock changes (NTP adjustments, manual clock setting, daylight saving time). This is critical in long-running notebook sessions and CI/CD jobs where system clock drift is common.

### 3.3 Dual-Interface Wiring

The credential classes expose two interfaces for obtaining tokens. Both share the same internal state:

**Interface 1: `refresh_api_key_hook(config)` — for Kubernetes clients**

```python
def refresh_api_key_hook(self, config: Configuration) -> None:
    if self._access_token is None or self._is_expired():
        if self._access_token is None:
            self._do_token_exchange()
        else:
            self._do_refresh()

    config.api_key["authorization"] = self._access_token
    config.api_key_prefix["authorization"] = "Bearer"
```

This method is assigned to `Configuration.refresh_api_key_hook` when `load_kubernetes_config()` wires up credentials:

```python
def _build_client_with_credentials(credentials, server, *, verify_ssl=True, ca_cert=None):
    k8s_config = client.Configuration()
    k8s_config.host = server
    k8s_config.verify_ssl = verify_ssl
    if ca_cert:
        k8s_config.ssl_ca_cert = ca_cert

    k8s_config.api_key["authorization"] = "placeholder"
    k8s_config.api_key_prefix["authorization"] = "Bearer"
    k8s_config.refresh_api_key_hook = credentials.refresh_api_key_hook

    return client.ApiClient(configuration=k8s_config)
```

**Interface 2: `get_token() -> str` — for REST clients**

```python
def get_token(self) -> str:
    if self._access_token is None:
        self._do_token_exchange()
    elif self._is_expired():
        self._do_refresh()
    return self._access_token
```

REST clients call this to get a raw token string:

```python
# Pipelines client
from kfp import Client as KFPClient
token = creds.get_token()
kfp_client = KFPClient(existing_token=token)

# Model Registry client
from model_registry import ModelRegistry
token = creds.get_token()
mr_client = ModelRegistry(user_token=token)
```

**Why both interfaces matter:**

Both methods read and write the same `_access_token`, `_refresh_token`, and `_expires_at` fields. A refresh triggered by `refresh_api_key_hook` updates the token that `get_token()` returns, and vice versa. This means a single credential object can serve both Kubernetes and REST clients simultaneously:

```python
from kubeflow.trainer import TrainerClient
from kubeflow.common.auth import OIDCClientCredentials
from kfp import Client as KFPClient

creds = OIDCClientCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-sdk",
    client_secret="my-client-secret",
)

# Same creds object, different clients, different protocols
trainer = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.cluster:6443",
})

kfp = KFPClient(existing_token=creds.get_token())

# Both clients share the same token and refresh state
trainer.list_jobs()         # Uses refresh_api_key_hook
kfp.list_experiments()      # Uses the token from get_token()
```

### 3.4 Auth Resolution Chain

`load_kubernetes_config()` tries authentication methods in a fixed, deterministic order. The first method that succeeds produces the `ApiClient`. If nothing works, a `RuntimeError` is raised.

```
Priority  │ Method                              │ Source
──────────┼─────────────────────────────────────┼───────────────────────────
  1       │ Explicit client_configuration        │ Programmatic
  2       │ Pluggable credentials object          │ Programmatic
  3       │ Explicit token + server               │ Programmatic
  4       │ KUBEFLOW_OIDC_* env vars              │ Environment
  5       │ KUBEFLOW_TOKEN + KUBEFLOW_API_HOST    │ Environment
  6       │ Kubeconfig file                       │ File system
  7       │ In-cluster service account             │ Kubernetes runtime
```

**Priority 1 — Explicit `client_configuration`:**

If a fully constructed `kubernetes.client.Configuration` object is provided, it is used directly. No other resolution is attempted. This is the escape hatch for users who need full control over the Kubernetes client configuration:

```python
from kubernetes import client
k8s_config = client.Configuration()
k8s_config.host = "https://api.cluster:6443"
k8s_config.api_key["authorization"] = "my-token"
k8s_config.api_key_prefix["authorization"] = "Bearer"

trainer = TrainerClient(backend_config={
    "client_configuration": k8s_config,
})
```

**Priority 2 — Pluggable `credentials` object:**

Any object implementing `TokenCredentialsBase` (i.e., providing `refresh_api_key_hook`). This is the primary integration point for the OIDC credential classes:

```python
creds = OIDCClientCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="my-client",
    client_secret="my-secret",
)
trainer = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.cluster:6443",
})
```

The `server` parameter is required when using `credentials`. If not provided directly, `load_kubernetes_config()` falls back to the `KUBEFLOW_API_HOST` environment variable.

**Priority 3 — Explicit `token` + `server`:**

A static bearer token. Useful for short-lived scripts or when a token is obtained externally:

```python
trainer = TrainerClient(backend_config={
    "token": "eyJhbGciOiJSUzI1NiIs...",
    "server": "https://api.cluster:6443",
})
```

**Priority 4 — `KUBEFLOW_OIDC_*` environment variables:**

When **all four** of the following environment variables are set, `load_kubernetes_config()` automatically constructs `OIDCClientCredentials`. If any of the three `KUBEFLOW_OIDC_*` variables or `KUBEFLOW_API_HOST` is missing, this strategy is skipped and resolution continues to the next priority:

```bash
export KUBEFLOW_OIDC_ISSUER="https://keycloak.example.com/realms/kubeflow"
export KUBEFLOW_OIDC_CLIENT_ID="kubeflow-sdk"
export KUBEFLOW_OIDC_CLIENT_SECRET="my-client-secret"
export KUBEFLOW_API_HOST="https://api.cluster:6443"
```

With these set, no code-level auth configuration is needed:

```python
# Reads KUBEFLOW_OIDC_* and KUBEFLOW_API_HOST from environment
trainer = TrainerClient()
trainer.list_jobs()  # Authenticated via OIDC client credentials
```

**Priority 5 — `KUBEFLOW_TOKEN` + `KUBEFLOW_API_HOST`:**

A static token from the environment. Simpler than OIDC but the token won't refresh:

```bash
export KUBEFLOW_TOKEN="eyJhbGciOiJSUzI1NiIs..."
export KUBEFLOW_API_HOST="https://api.cluster:6443"
```

**Priority 6 — Kubeconfig file:**

Standard kubeconfig resolution. Uses `config_file` and `context` if provided, otherwise the default `~/.kube/config`:

```python
# Uses default kubeconfig
trainer = TrainerClient()

# Uses specific kubeconfig file and context
trainer = TrainerClient(backend_config={
    "config_file": "/path/to/kubeconfig",
    "context": "my-cluster",
})
```

**Priority 7 — In-cluster service account:**

When running inside a Kubernetes pod, the service account token is mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`. This is the fallback for workloads running within the cluster:

```python
# Inside a Kubernetes pod — no configuration needed
trainer = TrainerClient()
```

### 3.5 Environment Variable Configuration

The SDK recognizes the following environment variables:

| Variable | Description | Used By |
|----------|-------------|---------|
| `KUBEFLOW_OIDC_ISSUER` | OIDC provider issuer URL | Resolution chain priority 4 |
| `KUBEFLOW_OIDC_CLIENT_ID` | OIDC client ID | Resolution chain priority 4 |
| `KUBEFLOW_OIDC_CLIENT_SECRET` | OIDC client secret | Resolution chain priority 4 |
| `KUBEFLOW_TOKEN` | Static bearer token | Resolution chain priority 5 |
| `KUBEFLOW_API_HOST` | Kubernetes API server URL | Priorities 2–5 (fallback for `server`) |

**Example — CI/CD pipeline with environment-based auth:**

```yaml
# GitHub Actions example
jobs:
  train:
    runs-on: ubuntu-latest
    env:
      KUBEFLOW_OIDC_ISSUER: https://keycloak.example.com/realms/kubeflow
      KUBEFLOW_OIDC_CLIENT_ID: ci-bot
      KUBEFLOW_OIDC_CLIENT_SECRET: ${{ secrets.OIDC_SECRET }}
      KUBEFLOW_API_HOST: https://api.mycluster.example.com:6443
    steps:
      - run: |
          python -c "
          from kubeflow.trainer import TrainerClient
          client = TrainerClient()
          client.train(...)
          "
```

### 3.6 Device Flow and Browser Flow

**Device code flow** (`OIDCDeviceFlowCredentials`):

Designed for headless environments — remote notebooks, SSH sessions, CI/CD with interactive approval. The user authenticates on a separate device:

```python
from kubeflow.common.auth import OIDCDeviceFlowCredentials

creds = OIDCDeviceFlowCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-cli",
)

# On first use (e.g., when get_token() or refresh_api_key_hook is called):
# Prints to stderr:
#
#   To authenticate, visit:
#
#     https://keycloak.example.com/device
#
#   and enter code: ABCD-EFGH
#
#   Waiting for authentication...

token = creds.get_token()  # Blocks until user authenticates
```

The device flow supports:
- Custom `prompt_callback` for non-terminal UIs (e.g., Jupyter widget)
- Configurable `output` stream (defaults to `sys.stderr`)
- Automatic polling with back-off (respects the provider's `interval` and `slow_down` responses)

```python
def my_notebook_prompt(verification_uri, user_code, verification_uri_complete):
    from IPython.display import display, HTML
    display(HTML(f'<a href="{verification_uri_complete}">{user_code}</a>'))

creds = OIDCDeviceFlowCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-notebook",
    prompt_callback=my_notebook_prompt,
)
```

**Browser flow** (`OIDCBrowserFlowCredentials`):

Designed for local development where the user has a browser. Uses authorization code with PKCE (Proof Key for Code Exchange):

```python
from kubeflow.common.auth import OIDCBrowserFlowCredentials

creds = OIDCBrowserFlowCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-dev",
    redirect_port=8400,  # localhost callback port
)

# On first use:
# 1. Generates PKCE code verifier + S256 challenge
# 2. Starts a temporary HTTP server on localhost:8400
# 3. Opens the browser to the IDP's authorization endpoint
# 4. User logs in; IDP redirects to localhost:8400/callback
# 5. Callback server captures the authorization code
# 6. Exchanges the code for tokens at the token endpoint
token = creds.get_token()
```

The browser flow validates the `state` parameter on the callback to prevent CSRF attacks, and uses PKCE to prevent authorization code interception.

### 3.7 Identity Propagation

When a user authenticates via OIDC, the access token is a JWT that contains identity claims. The SDK can extract these claims and propagate them as Kubernetes annotations on submitted resources.

The `extract_jwt_claims(token)` function decodes the JWT payload without cryptographic verification (the token was already validated by the OIDC provider during the token exchange). It extracts standard claims:

- `sub` — Subject identifier
- `email` — User's email address
- `preferred_username` — Human-readable username
- `groups` — Group memberships

The `identity_annotations(token)` function formats these claims as Kubernetes-safe annotation key-value pairs for CRD metadata. This allows controllers and audit systems to trace which user submitted a training job, pipeline run, or other resource, even when the workload itself runs under a different service account.

```python
from kubeflow.common.auth import OIDCClientCredentials

creds = OIDCClientCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-sdk",
    client_secret="my-secret",
)

token = creds.get_token()

# The SDK internally decodes the JWT to extract user identity
# and attaches it as annotations on submitted Kubernetes resources:
#
#   metadata:
#     annotations:
#       kubeflow.org/user-id: "f47ac10b-58cc-4372-a567-0e02b2c3d479"
#       kubeflow.org/user-email: "user@example.com"
#       kubeflow.org/user-name: "alice"
#       kubeflow.org/user-groups: "platform-admins,ml-engineers"
```

---

## 4. The OIDC Subpackage

### Current Structure

```
kubeflow/common/auth/
├── __init__.py              # Public API — re-exports everything
├── types.py                 # TokenCredentialsBase (runtime_checkable Protocol)
├── resolution.py            # Auth resolution chain (load_kubernetes_config)
├── errors.py                # Re-exports from oidc/errors.py for convenience
├── identity.py              # JWT claim extraction → CRD annotations
│
└── oidc/                    # ← Extractable. Zero Kubeflow imports.
    ├── __init__.py          # Re-exports all credential classes
    ├── discovery.py         # OIDCProviderMetadata, discover()
    ├── base.py              # _OIDCBaseCredentials (lifecycle, exchange, hook, get_token)
    ├── client_credentials.py # OIDCClientCredentials
    ├── password.py          # OIDCPasswordCredentials
    ├── device_flow.py       # OIDCDeviceFlowCredentials
    ├── browser_flow.py      # OIDCBrowserFlowCredentials
    ├── errors.py            # AuthenticationError hierarchy (self-contained)
    └── keyring.py           # Optional keyring-backed token persistence
```

### Internal Dependencies

The OIDC subpackage's import graph is deliberately minimal:

- `oidc/discovery.py` → `requests` (standard HTTP client), `oidc/errors`
- `oidc/base.py` → `kubernetes.client.Configuration` (type-checking only, behind `TYPE_CHECKING` guard), `requests`, `oidc/discovery`, `oidc/errors`
- `oidc/client_credentials.py` → `oidc/base`
- `oidc/password.py` → `oidc/base`
- `oidc/device_flow.py` → `requests`, `oidc/base`
- `oidc/browser_flow.py` → `oidc/base`, Python stdlib only (`http.server`, `webbrowser`, `hashlib`, `secrets`, `threading`)
- `oidc/keyring.py` → `keyring` (optional, lazy-imported)
- `oidc/errors.py` → no external dependencies (pure Python exceptions)

No file in `oidc/` imports from `kubeflow.*`. The only external dependency beyond stdlib is `requests` (for HTTP). The `kubernetes.client.Configuration` import in `base.py` is behind `TYPE_CHECKING` — it is used only for type annotations and is not loaded at runtime. This means the OIDC subpackage can be extracted without a hard dependency on the `kubernetes` package.

The `oidc/` subpackage has zero coupling to `kubeflow.*`. The `TokenCredentialsBase` Protocol lives in `kubeflow.common.auth.types` and is matched structurally — OIDC classes don't import or inherit from it.

### Extractability

The OIDC subpackage is designed to be extractable into a standalone PyPI package. The extraction path requires no code changes to the OIDC classes themselves:

**Step 1: Move to a new repository.**
Copy `kubeflow/common/auth/oidc/` to a new `kubernetes-oidc` repository. No import changes needed — the subpackage already has zero Kubeflow imports.

**Step 2: Publish as a standalone package.**
```bash
pip install kubernetes-oidc
```

**Step 3: Add as an optional dependency of the Kubeflow SDK.**
```toml
# pyproject.toml
[project.optional-dependencies]
oidc = ["kubernetes-oidc>=1.0"]
```
```bash
pip install kubeflow[oidc]
```

**Step 4: Re-export for backward compatibility.**
```python
# kubeflow/common/auth/__init__.py
from kubernetes_oidc import (
    OIDCClientCredentials,
    OIDCPasswordCredentials,
    OIDCDeviceFlowCredentials,
    OIDCBrowserFlowCredentials,
    OIDCProviderMetadata,
    discover,
)
```

**Step 5: Nothing else changes.**
All existing user code, environment variable handling, and `KubernetesBackendConfig` wiring continues to work identically. The extraction is invisible to SDK users.

### When to Extract

Extraction should happen when:

- Other SDKs (CodeFlare, KFP standalone CLI, etc.) want OIDC auth without depending on the full Kubeflow SDK.
- Upstream Kubernetes community interest develops for a shared OIDC auth package.
- The `kubernetes-client` GitHub organization is ready to host or endorse an auth extension package.

Until then, the OIDC code lives inside the Kubeflow SDK where it can iterate quickly without the overhead of a separate release cycle.

---

## 5. Dual Auth Design

### The Problem

The Kubeflow SDK targets five components that use two fundamentally different API protocols:

| Client | API Type | Auth Mechanism |
|--------|----------|---------------|
| Trainer | Kubernetes API | `kubernetes.client.Configuration.refresh_api_key_hook` |
| Spark | Kubernetes API | `kubernetes.client.Configuration.refresh_api_key_hook` |
| Optimizer | Kubernetes API | `kubernetes.client.Configuration.refresh_api_key_hook` |
| Pipelines | REST API | `kfp.Client(existing_token=str)` |
| Model Registry | REST API | `ModelRegistry(user_token=str)` |

Kubernetes-backed clients use the Kubernetes Python client, which expects auth to be wired through a `Configuration` object's `refresh_api_key_hook`. REST-backed clients expect a raw token string passed at construction time.

Without a dual-interface design, users would need to create separate credential objects for each protocol — one for the K8s hook, one for the token string — and manually keep them synchronized. This would defeat the entire purpose of "configure once, use everywhere."

### The Solution

Every OIDC credential class implements both interfaces on a single object:

```python
class _OIDCBaseCredentials(TokenCredentialsBase):

    def refresh_api_key_hook(self, config: Configuration) -> None:
        """Interface 1: Called by kubernetes.client before every K8s API request."""
        if self._access_token is None or self._is_expired():
            if self._access_token is None:
                self._do_token_exchange()
            else:
                self._do_refresh()
        config.api_key["authorization"] = self._access_token
        config.api_key_prefix["authorization"] = "Bearer"

    def get_token(self) -> str:
        """Interface 2: Returns the raw token string for REST clients."""
        if self._access_token is None:
            self._do_token_exchange()
        elif self._is_expired():
            self._do_refresh()
        return self._access_token
```

Both methods:
- Check the same `_access_token` and `_expires_at` fields
- Call the same `_do_token_exchange()` and `_do_refresh()` methods
- Update the same internal state

### K8s Clients — Deep Integration

All three Kubernetes-backed clients (Trainer, Spark, Optimizer) share the same wiring path. Their backend classes accept a `KubernetesBackendConfig` and call `load_kubernetes_config()`:

```python
# kubeflow/trainer/backends/kubernetes/backend.py
class KubernetesBackend(RuntimeBackend):
    def __init__(self, cfg: KubernetesBackendConfig):
        if cfg.client_configuration is not None:
            k8s_client = client.ApiClient(cfg.client_configuration)
        else:
            k8s_client = load_kubernetes_config(
                config_file=cfg.config_file,
                context=cfg.context,
                credentials=cfg.credentials,
                token=cfg.token,
                server=cfg.server,
                verify_ssl=cfg.verify_ssl,
                ca_cert=cfg.ca_cert,
            )
        self.custom_api = client.CustomObjectsApi(k8s_client)
        self.core_api = client.CoreV1Api(k8s_client)
```

The `refresh_api_key_hook` is called automatically by the Kubernetes Python client before every HTTP request. The SDK doesn't need to manage refresh timing — the K8s client handles the callback scheduling.

### REST Clients — Wrap and Re-Export

The Kubeflow SDK doesn't own its REST clients. It wraps upstream libraries (`kfp`, `model-registry`, and eventually `kserve`, `feast`) and re-exports them with a consistent constructor signature. The critical constraint is that the SDK does not control the upstream auth interfaces:

| Component | Upstream Client | Auth Parameter | Type |
|-----------|----------------|----------------|------|
| Pipelines | `kfp.Client` | `existing_token` | `str` |
| Model Registry | `model_registry.ModelRegistry` | `user_token` | `str` |
| KServe | `kserve.KServeClient` | likely `token` | `str` / K8s config |
| Feast | `feast.FeatureStore` | registry-specific | varies |

Every upstream REST client takes a **static token string**. None of them accept a credentials object or a refresh hook. That's the hard constraint.

The auth wiring per REST wrapper is ~5 lines:

```python
class PipelinesClient:
    def __init__(self, *, base_url: str, user_token: str | None = None,
                 credentials: TokenCredentialsBase | None = None, ...):
        if user_token is None:
            creds = resolve_credentials(credentials=credentials)
            if creds:
                user_token = creds.get_token()
        self._client = kfp.Client(host=base_url, existing_token=user_token)
```

`resolve_credentials()` gives every REST wrapper env-var-based OIDC auth for free. This does not need a framework — it's a convention. Future wrappers (KServe, Feast) follow the same pattern: accept `user_token` and `credentials`, call `resolve_credentials()`, pass the token to the upstream client.

### Token Refresh for Long-Lived REST Sessions

Upstream REST clients receive a token at construction time. If the wrapper calls `creds.get_token()` at the start of each public method (not just at construction), it gets a fresh token every time. This is a per-wrapper implementation choice.

For upstream clients that hold persistent connections (like KFP's `wait_for_run` polling loop), token expiry is a problem for the upstream client to solve — the SDK wrapper cannot intercept HTTP calls it doesn't make. In practice, OIDC tokens last 5–30 minutes and most SDK operations complete in seconds, so this is a pragmatic non-issue for most real usage.

**Future improvement:** Propose a `Callable[[], str]` token provider interface to upstream REST clients. Instead of `existing_token=str`, the client would accept a callable it invokes before each HTTP request:

```python
# Future upstream API
kfp_client = kfp.Client(token_provider=creds.get_token)
```

---

## 6. What This Doesn't Cover

The unified auth system has a deliberately scoped boundary. The following are explicitly out of scope, with rationale for each exclusion:

### 6.1 OpenShift OAuth

OpenShift's native OAuth server uses a non-standard protocol that is not OIDC-compliant. Supporting it requires OpenShift-specific code for the OAuth discovery, token exchange, and refresh flows. This is a platform-specific concern, not a generic OIDC concern.

**How to add it:** Implement an `OpenShiftOAuthCredentials` class that extends `TokenCredentialsBase`. It would use OpenShift's `.well-known/oauth-authorization-server` endpoint instead of OIDC's `.well-known/openid-configuration`. The class would plug into the existing resolution chain via `credentials=`:

```python
# Hypothetical — not implemented
creds = OpenShiftOAuthCredentials(server="https://api.ocp.example.com:6443")
trainer = TrainerClient(backend_config={"credentials": creds, "server": "..."})
```

### 6.2 Auto-Detection Factory

A "try everything until something works" factory that probes the environment and guesses the right auth method is deliberately excluded. Auth detection precedence is an SDK-level decision, not a credential library concern. Different SDKs and different deployment contexts may have different precedence orders.

The `load_kubernetes_config()` resolution chain is the Kubeflow SDK's opinionated answer to this question. Its priority order is fixed and deterministic. Users who need a different order should construct credentials explicitly.

### 6.3 Per-Job Identity / Service Account Mapping

Mapping an OIDC user identity to a Kubernetes service account (e.g., "user alice@example.com should run jobs as ServiceAccount `alice-sa`") requires controller-side admission logic. The SDK submits resources with the user's identity in annotations, but the actual mapping to a service account is an admission webhook or policy controller concern.

### 6.4 Multi-Step Pipeline Identity Delegation

Propagating a user's OIDC identity through multiple pipeline steps — where step 2 should run with step 1's user context — requires orchestration-level token forwarding and impersonation. This is a platform-level concern that spans the pipeline controller, the container runtime, and potentially the service mesh. It is beyond the scope of client-side SDK auth.

### 6.5 KFP Cookie-Based Auth / IAP Auth

Legacy Kubeflow Pipelines authentication mechanisms (Dex cookies, GCP IAP tokens) are component-specific, not cross-cutting. They exist to support older deployment patterns where KFP had its own authentication layer separate from the Kubernetes API server. The unified auth system works at the Kubernetes and OIDC level, which is where modern Kubeflow deployments authenticate.

### 6.6 RESTBackendConfig / Shared REST Session Adapter

A shared configuration model for REST wrappers (analogous to `KubernetesBackendConfig`) is deliberately excluded. Each upstream REST client has different fields (`namespace` for KFP, `port` for Model Registry, etc.). A shared model would be a lowest-common-denominator that adds indirection without value.

Similarly, a `requests.Session` adapter with automatic token refresh is not feasible: the SDK does not control the upstream HTTP clients. KFP uses its own generated API client, Model Registry uses its internal HTTP client. The SDK cannot inject a session into clients it doesn't own.

The correct pattern is `resolve_credentials()` + ~5 lines of wiring per wrapper. This is simple enough to not need a framework.

### 6.7 Cryptographic JWT Verification

The SDK decodes JWTs for claim extraction only (using base64 decoding of the payload segment). It does not perform cryptographic signature verification. This is a deliberate design choice:

- The API server already verifies token signatures using the provider's JWKS (JSON Web Key Set).
- Client-side verification would require fetching the JWKS, managing key rotation, and handling multiple signing algorithms.
- The token was obtained directly from the OIDC provider's token endpoint over TLS — its authenticity is guaranteed by the transport.
- Duplicating verification at the client adds complexity and latency without improving security.

---

## 7. Error Handling

### Exception Hierarchy

The auth system uses a custom exception hierarchy to provide actionable error messages:

```
AuthenticationError (base)
├── DiscoveryError          — OIDC discovery failed
├── TokenExchangeError      — Token exchange or refresh failed
├── TokenExpiredError        — Token expired and could not be refreshed
├── ProviderUnreachableError — Cannot reach the identity provider
└── InvalidCredentialsError  — Credentials were rejected by the provider
```

### What Each Error Means

**`AuthenticationError`**

The base exception for all auth failures. Catching this catches any auth-related error:

```python
from kubeflow.common.auth import OIDCClientCredentials

try:
    creds = OIDCClientCredentials(
        issuer_url="https://keycloak.example.com/realms/kubeflow",
        client_id="my-client",
        client_secret="wrong-secret",
    )
    creds.get_token()
except Exception as e:
    # Handle any auth failure
    print(f"Auth failed: {e}")
```

**`DiscoveryError`**

Raised when OIDC discovery (`/.well-known/openid-configuration`) fails. This can happen because:
- The issuer URL is wrong
- The OIDC provider is down
- The discovery document is malformed (e.g., missing `token_endpoint`)
- The issuer in the discovery response doesn't match the requested URL (security check)

**`TokenExchangeError`**

Raised when a token exchange or refresh request fails. The provider returned an HTTP error (4xx/5xx) during the token endpoint POST. Common causes:
- Invalid client credentials (wrong `client_id` or `client_secret`)
- Invalid password (for password grant)
- Expired or revoked authorization code (for browser flow)
- Expired device code (for device flow)

**`TokenExpiredError`**

Raised when the current token has expired and all refresh attempts have failed. This indicates the user needs to re-authenticate. Most commonly occurs with interactive flows (device, browser) when the refresh token itself has expired.

**`ProviderUnreachableError`**

Raised when the identity provider cannot be reached at all — network errors, DNS failures, TLS errors. Distinct from `DiscoveryError` because the issue is connectivity, not the response content.

**`InvalidCredentialsError`**

Raised when the provider explicitly rejects the credentials. The request was well-formed but the credentials are wrong. This gives users a clear signal to check their `client_id`, `client_secret`, username, or password.

### Resolution Chain Error

When no authentication method in the resolution chain succeeds, `load_kubernetes_config()` raises a `RuntimeError` that lists every method that was attempted:

```
RuntimeError: Could not configure Kubernetes client. Tried: credentials,
token, KUBEFLOW_OIDC_* env vars, KUBEFLOW_TOKEN env var, kubeconfig,
in-cluster config. None succeeded.
```

---

## 8. Security Considerations

### Secret Redaction

All credential classes override `__repr__()` to redact sensitive fields. This prevents secrets from appearing in logs, tracebacks, or notebook output:

```python
>>> creds = OIDCClientCredentials(
...     issuer_url="https://keycloak.example.com/realms/kubeflow",
...     client_id="my-client",
...     client_secret="super-secret-value",
... )
>>> repr(creds)
"OIDCClientCredentials(client_id='my-client', token_endpoint='...', client_secret=<REDACTED>, has_token=False)"
```

```python
>>> creds = OIDCPasswordCredentials(
...     issuer_url="https://keycloak.example.com/realms/kubeflow",
...     client_id="my-client",
...     username="user",
...     password="secret-password",
... )
>>> repr(creds)
"OIDCPasswordCredentials(client_id='my-client', username='user', token_endpoint='...', password=<REDACTED>, has_token=False)"
```

Client secrets and passwords never appear in `repr()`, `str()`, or any log output. The `has_token` field indicates whether a token has been obtained without revealing the token itself.

### Issuer Validation

During OIDC discovery, the issuer URL in the response is compared against the requested issuer URL. If they don't match, a `ValueError` is raised immediately:

```python
response_issuer = data.get("issuer")
if response_issuer is not None and response_issuer.rstrip("/") != normalised_issuer:
    raise ValueError(
        f"OIDC issuer mismatch: requested {normalised_issuer!r} but "
        f"discovery document returned {response_issuer!r}. "
        f"This may indicate a misconfigured or compromised provider."
    )
```

This prevents a class of attack where a DNS hijack or proxy misconfiguration redirects the discovery request to a different OIDC provider. Without this check, the SDK could silently obtain tokens from an attacker-controlled provider.

### Monotonic Clock for Expiry Tracking

Token expiry is tracked using `time.monotonic()` instead of `time.time()`:

```python
self._expires_at = time.monotonic() + token_data.get("expires_in", 300) - _EXPIRY_BUFFER_SECONDS

def _is_expired(self) -> bool:
    return time.monotonic() >= self._expires_at
```

`time.monotonic()` is:
- **Immune to system clock changes.** NTP step adjustments, manual clock setting, and daylight saving time changes don't affect it.
- **Strictly non-decreasing.** The clock never goes backward, which prevents a token from being incorrectly considered "not expired" after a clock adjustment.

This is critical for long-running notebook sessions and CI/CD jobs where system time may be adjusted during execution.

### PKCE (Proof Key for Code Exchange)

The browser flow uses PKCE (RFC 7636) with S256 code challenges to prevent authorization code interception attacks:

```python
def _generate_pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge
```

The flow works as follows:
1. Generate a random `code_verifier` (256 bits of entropy from `os.urandom`).
2. Compute `code_challenge = BASE64URL(SHA256(code_verifier))`.
3. Send `code_challenge` with the authorization request.
4. Send `code_verifier` with the token exchange request.
5. The provider verifies that `SHA256(code_verifier) == code_challenge`.

Even if an attacker intercepts the authorization code (e.g., via a malicious browser extension or local process), they cannot exchange it for tokens without the `code_verifier`, which never leaves the SDK process.

### State Parameter and CSRF Prevention

The browser flow generates a cryptographically random `state` parameter for each authentication request:

```python
state = secrets.token_urlsafe(32)
```

The callback server validates that the `state` returned by the provider matches the expected value:

```python
if state != self.server.state_expected:
    self.server.callback_error = "state_mismatch"
```

This prevents Cross-Site Request Forgery (CSRF) attacks where an attacker tricks the user's browser into completing an OAuth flow initiated by the attacker.

### Localhost-Only Callback Server

The browser flow's callback server binds to `127.0.0.1` (not `0.0.0.0`), accepting connections only from the local machine:

```python
super().__init__(("127.0.0.1", port), _CallbackHandler)
```

Additionally, the callback handler validates the `Host` header to prevent DNS rebinding attacks:

```python
host = self.headers.get("Host", "")
allowed = {
    f"localhost:{self.server.server_address[1]}",
    f"127.0.0.1:{self.server.server_address[1]}",
}
if host not in allowed:
    self.send_error(400, "Invalid Host header")
```

### TLS Verification

All credential classes accept a `verify` parameter that controls TLS certificate verification:

```python
# Default: system CA bundle (verify=True)
creds = OIDCClientCredentials(issuer_url="...", client_id="...", client_secret="...")

# Custom CA bundle (for self-signed certs or private CAs)
creds = OIDCClientCredentials(
    issuer_url="...",
    client_id="...",
    client_secret="...",
    verify="/path/to/ca-bundle.crt",
)

# Disable verification (NOT recommended for production)
creds = OIDCClientCredentials(
    issuer_url="...",
    client_id="...",
    client_secret="...",
    verify=False,
)
```

The `verify` parameter is passed through to `requests.get()` and `requests.post()` for all HTTP calls (discovery, token exchange, refresh). Custom CA support is essential for enterprise environments where OIDC providers use internal certificate authorities.

### Expiry Buffer

Tokens are considered expired 30 seconds before their actual expiry time:

```python
_EXPIRY_BUFFER_SECONDS = 30

self._expires_at = time.monotonic() + token_data.get("expires_in", 300) - _EXPIRY_BUFFER_SECONDS
```

This buffer prevents race conditions where a token is valid when the SDK checks but expires by the time the API server receives and validates the request. The 30-second window accounts for network latency, clock skew between the client and server, and request processing time.

### Keyring Integration

For interactive flows (device code, browser), persistent token storage avoids requiring re-authentication on every SDK invocation. The optional keyring integration stores refresh tokens in the operating system's credential manager:

- **macOS:** Keychain
- **Linux:** GNOME Keyring / KDE Wallet
- **Windows:** Windows Credential Manager

```python
# Requires: pip install kubeflow[oidc-keyring]
from kubeflow.common.auth._keyring import save_refresh_token, load_refresh_token

save_refresh_token(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-dev",
    refresh_token="eyJhbGciOi...",
)

token = load_refresh_token(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-dev",
)
```

Tokens stored in the system keyring are protected by the OS-level credential manager's own security model (encrypted storage, access control, biometric unlocks on macOS). The `keyring` dependency is optional and lazy-imported — it is never loaded unless explicitly used.

---

## 9. Future Enhancement: Token Provider Callable for REST Clients

### The problem today

REST clients in the Kubeflow ecosystem accept a static token string at construction time:

```python
kfp.Client(existing_token="eyJhbG...")
ModelRegistry(user_token="eyJhbG...")
```

The SDK works around this by calling `creds.get_token()` at wrapper construction or per-method. This is sufficient for short-lived operations, but it cannot solve the case where the upstream client itself makes a long-running series of HTTP calls internally (e.g. KFP's `wait_for_run` polling loop). The SDK wrapper cannot intercept HTTP requests it doesn't own.

### The recommendation: `Callable[[], str]`

Upstream REST clients should accept an **optional** callable alongside the existing static token parameter:

```python
# Backward-compatible — str still works exactly as before
class PipelinesClient:
    def __init__(
        self,
        *,
        existing_token: str | Callable[[], str] | None = None,
    ): ...
```

If the client receives a callable, it invokes it before each HTTP request to get a fresh token. If it receives a string, it uses it directly. The callable is optional — existing code that passes a static string continues to work with zero changes.

### Why the upstream client should own refresh

The SDK should not try to manage token refresh on behalf of REST clients. Each client has its own HTTP lifecycle — its own session management, connection pooling, retry logic, and request timing. The client is the right place to decide when to call for a fresh token:

- **Before each HTTP request** — the simplest and most robust strategy
- **On 401 retry** — useful for clients with long-lived connections
- **On a timer** — for clients that batch requests

The SDK's role is to provide the refresh *function* (`creds.get_token`), not to prescribe when or how the client uses it. This is the same separation of concerns the Kubernetes Python client uses: it calls `refresh_api_key_hook` before each API request, without knowing anything about OIDC or token exchange.

### What `Callable[[], str]` gets right

The interface is deliberately minimal:

- **No Kubeflow imports.** The upstream client doesn't need to know about `TokenCredentialsBase`, OIDC, or the Kubeflow SDK. It's a plain Python callable.
- **Any token source works.** OIDC refresh, Vault token exchange, `gcloud auth print-access-token`, AWS STS, a literal string wrapped in a lambda — anything that returns a string satisfies the contract.
- **Backward-compatible.** `str | Callable[[], str]` is a type union. Existing callers passing a string see no change.
- **Trivial to implement.** The upstream client adds ~5 lines: check if the token is callable, call it if so, use the result.

### How the SDK wires it

When an upstream client supports `Callable[[], str]`, the SDK wrapper passes the method reference — not the result:

```python
class PipelinesClient:
    def __init__(self, *, base_url: str, user_token: str | None = None,
                 credentials: TokenCredentialsBase | None = None, ...):
        token = user_token
        if token is None:
            creds = resolve_credentials(credentials=credentials)
            if creds:
                token = creds.get_token  # pass the method, not the result
        self._client = kfp.PipelinesClient(
            base_url=base_url, existing_token=token,
        )
```

Note: `creds.get_token` (no parentheses). The SDK passes the function itself. The upstream client calls it when it needs a token. Token exchange, refresh, and expiry management all happen inside `get_token()` transparently.

When the upstream client only supports `str`, the wrapper falls back to calling `creds.get_token()` (with parentheses) to get a snapshot token.

### What the upstream client implementation looks like

For a client that wants to support `Callable[[], str]`:

```python
from typing import Callable

class PipelinesClient:
    def __init__(self, *, existing_token: str | Callable[[], str] | None = None):
        self._token = existing_token

    def _get_token(self) -> str | None:
        if self._token is None:
            return None
        if callable(self._token):
            return self._token()
        return self._token

    def list_runs(self, ...):
        headers = {}
        token = self._get_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        # ... make HTTP request with headers ...
```

The `_get_token()` method is the only change. Every HTTP-making method calls it instead of reading `self._token` directly.

### Where we have influence

| Client | Influence | Timing |
|--------|-----------|--------|
| KFP `PipelinesClient` (KEP-125) | High — active design review | Now |
| SDK-specific clients (Feast, KServe) | Full — we define the interface | When built |
| Model Registry | Moderate — client is still evolving | When SDK wrapper is built |
| Existing `kfp.Client` | Low — mature, wide adoption | Not a priority |

The highest-leverage opportunity is the KFP `PipelinesClient` being designed in KEP-125 (PR #343). The `Callable` support is a design-time decision — trivial to include now, harder to retrofit later.
