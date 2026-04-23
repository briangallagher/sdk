# Unified Authentication Architecture (kube-authkit)

This document describes how the Kubeflow SDK handles authentication using
[kube-authkit](https://github.com/opendatahub-io/kube-authkit) as the underlying
auth engine, wrapped behind the SDK's `TokenCredentialsBase` protocol.

## Two-Layer Design

```
┌─────────────────────────────────────────────┐
│  SDK Orchestration Layer                    │
│  (kubeflow.common.auth)                     │
│                                             │
│  ┌───────────────┐  ┌────────────────────┐  │
│  │ resolve_      │  │ load_kubernetes_   │  │
│  │ credentials() │  │ config()           │  │
│  └───────┬───────┘  └────────┬───────────┘  │
│          │                   │              │
│  ┌───────▼───────────────────▼───────────┐  │
│  │ TokenCredentialsBase Protocol         │  │
│  │  - refresh_api_key_hook(config)       │  │
│  │  - get_token() -> str                 │  │
│  └───────────────────┬───────────────────┘  │
│                      │                      │
│  ┌───────────────────▼───────────────────┐  │
│  │ _KubeAuthkitAdapter                   │  │
│  │  wraps kube-authkit AuthStrategy      │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│  kube-authkit  (external dependency)        │
│                                             │
│  AuthFactory → strategy selection           │
│  ├── OIDCStrategy (client_credentials,      │
│  │     device flow, browser/PKCE)           │
│  ├── OpenShiftOAuthStrategy                 │
│  ├── KubeConfigStrategy                     │
│  └── InClusterStrategy                      │
│                                             │
│  get_token() auto-refreshes expired tokens  │
└─────────────────────────────────────────────┘
```

### Layer 1: SDK Orchestration (kubeflow.common.auth)

This layer owns:

- **`TokenCredentialsBase`** -- the Protocol that both K8s and REST clients consume
- **`resolve_credentials()`** -- the resolution chain (explicit > token > OIDC > env > None)
- **`load_kubernetes_config()`** -- builds `ApiClient` with `refresh_api_key_hook` wired
- **`_KubeAuthkitAdapter`** -- wraps kube-authkit strategies as `TokenCredentialsBase`
- **`identity_annotations()`** -- extracts JWT claims for Kubernetes annotations
- **Env var conventions** -- `KUBEFLOW_OIDC_*`, `KUBEFLOW_TOKEN`, `KUBEFLOW_API_HOST`

### Layer 2: kube-authkit (auth engine)

kube-authkit handles the actual protocol work:

- OIDC discovery, token exchange, PKCE, device flow
- OpenShift OAuth
- Token refresh (auto-refresh in `get_token()`)
- Keyring persistence

The SDK **never imports kube-authkit types into its public API**. The adapter
pattern means kube-authkit can be swapped for another engine without changing
any SDK consumer code.

## Resolution Priority

When `load_kubernetes_config()` (or `get_kubernetes_client()`) is called:

| Priority | Source | Result |
|----------|--------|--------|
| 1 | `client_configuration=` | Pass-through `ApiClient` |
| 2 | `credentials=` (any `TokenCredentialsBase`) | Wire hook directly |
| 3 | `token=` | Wrap in `_StaticTokenCredentials` |
| 4 | `auth_method="oidc"` + OIDC config | kube-authkit strategy via adapter |
| 5 | `KUBEFLOW_OIDC_*` env vars | kube-authkit client_credentials via adapter |
| 6 | `KUBEFLOW_TOKEN` env var | Static token |
| 7 | kubeconfig file | `load_kube_config()` |
| 8 | In-cluster service account | `load_incluster_config()` |

## Dual-Interface Design

`TokenCredentialsBase` provides two methods for two worlds:

- **`refresh_api_key_hook(config)`** -- Called by the Kubernetes Python client
  before every API request. Enables transparent token refresh for K8s operations.

- **`get_token() -> str`** -- Returns a valid token string for REST clients
  (KFP Pipelines, Model Registry, etc.) or any consumer that needs a raw bearer token.

Both methods auto-refresh expired tokens. The SDK resolves credentials once and
shares the same object across both K8s and REST operations.

## Security

- **Monotonic clock** for token expiry (immune to wall-clock adjustments)
- **30-second buffer** before actual expiry to avoid races
- **PKCE** for all browser flows
- **No secrets in logs** -- `AuthConfig.__repr__` redacts sensitive fields
- **TLS verification** enabled by default

## Environment Variables

| Variable | Description |
|----------|-------------|
| `KUBEFLOW_OIDC_ISSUER` | OIDC issuer URL |
| `KUBEFLOW_OIDC_CLIENT_ID` | OIDC client ID |
| `KUBEFLOW_OIDC_CLIENT_SECRET` | OIDC client secret |
| `KUBEFLOW_TOKEN` | Static bearer token |
| `KUBEFLOW_API_HOST` | Kubernetes API server URL |

Legacy `AUTHKIT_*` variants are also supported for backward compatibility.

## Non-Goals (Current Scope)

- **JWT signature verification** -- the API server validates tokens
- **Auto-detection factory in the SDK** -- kube-authkit owns auto-detection
- **OpenShift OAuth in SDK core** -- handled by kube-authkit as a strategy
- **`KubeflowConfig` distribution object** -- planned for a future release
