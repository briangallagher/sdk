# Auth Use Cases

Real-world authentication scenarios for the Kubeflow SDK unified auth system. Each use case shows:

1. **The scenario** — who you are, what you're doing, and why this auth mode fits
2. **User code** — the minimal code you write
3. **How it works** — what happens under the hood

---

## Table of Contents

- [UC1: CI/CD Pipeline with OIDC Client Credentials](#uc1-cicd-pipeline-with-oidc-client-credentials)
- [UC2: Zero-Code Auth via Environment Variables](#uc2-zero-code-auth-via-environment-variables)
- [UC3: Notebook with Device Flow (Headless)](#uc3-notebook-with-device-flow-headless)
- [UC4: Local Development with Browser Flow](#uc4-local-development-with-browser-flow)
- [UC5: Existing kubeconfig / `oc login`](#uc5-existing-kubeconfig--oc-login)
- [UC6: In-Cluster Service Account](#uc6-in-cluster-service-account)
- [UC7: Static Token from External Source](#uc7-static-token-from-external-source)
- [UC8: Shared Credentials Across K8s and REST Clients](#uc8-shared-credentials-across-k8s-and-rest-clients)
- [UC9: KubeflowConfig — One Config for All Clients](#uc9-kubeflowconfig--one-config-for-all-clients)
- [UC10: REST Client with resolve_credentials()](#uc10-rest-client-with-resolve_credentials)
- [UC11: Custom Token Source (Vault, AWS STS)](#uc11-custom-token-source-vault-aws-sts)
- [UC12: Identity Propagation for Audit](#uc12-identity-propagation-for-audit)
- [UC13: Long-Running Training with Automatic Refresh](#uc13-long-running-training-with-automatic-refresh)
- [UC14: Custom CA / Internal PKI](#uc14-custom-ca--internal-pki)
- [UC15: Password Grant for Test Automation](#uc15-password-grant-for-test-automation)

---

## UC1: CI/CD Pipeline with OIDC Client Credentials

**Scenario:** You're a platform engineer running automated training pipelines in CI/CD (GitHub Actions, Tekton, GitLab CI). You have a service account with a client ID and secret from your IDP (Keycloak, Azure AD, Okta). No human interaction — fully automated.

**User code:**

```python
from kubeflow.trainer import TrainerClient
from kubeflow.common.auth import OIDCClientCredentials

creds = OIDCClientCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="ci-pipeline",
    client_secret="my-client-secret",
)

trainer = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.cluster:6443",
})

trainer.create_job(name="nightly-finetune", ...)
```

**How it works:**

1. `OIDCClientCredentials` performs OIDC discovery — fetches `/.well-known/openid-configuration` from the issuer to find the token endpoint.
2. On the first K8s API call (`create_job`), the `refresh_api_key_hook` fires, POSTs `client_credentials` grant to the token endpoint, and gets an access token.
3. The token is cached. Subsequent calls reuse it until it expires (tracked via `time.monotonic()`).
4. When the token expires, the next API call triggers an automatic re-exchange — no user intervention.

---

## UC2: Zero-Code Auth via Environment Variables

**Scenario:** You're deploying the same training script across dev, staging, and production. You inject auth via environment variables so the code doesn't change between environments. Common in Kubernetes Jobs, Tekton Tasks, and Jupyter notebook server configs.

**User code:**

```python
from kubeflow.trainer import TrainerClient

# No auth configuration in code — reads from environment
trainer = TrainerClient()
trainer.create_job(name="distributed-training", ...)
```

**Environment:**

```bash
export KUBEFLOW_OIDC_ISSUER="https://keycloak.example.com/realms/kubeflow"
export KUBEFLOW_OIDC_CLIENT_ID="kubeflow-sdk"
export KUBEFLOW_OIDC_CLIENT_SECRET="my-client-secret"
export KUBEFLOW_API_HOST="https://api.cluster:6443"
```

**How it works:**

1. `TrainerClient()` calls `load_kubernetes_config()` with no arguments.
2. `load_kubernetes_config()` internally calls `resolve_credentials()`, which checks `KUBEFLOW_OIDC_*` env vars.
3. All four env vars are present → `OIDCClientCredentials` is auto-constructed.
4. OIDC discovery and token exchange happen on first API call.
5. The code is identical in dev, staging, and production — only the env vars change.

---

## UC3: Notebook with Device Flow (Headless)

**Scenario:** You're a data scientist in a remote Jupyter notebook (JupyterHub, RHOAI workbench). There's no browser on the server. You want to authenticate as yourself — not as a service account.

**User code:**

```python
from kubeflow.trainer import TrainerClient
from kubeflow.common.auth import OIDCDeviceFlowCredentials

creds = OIDCDeviceFlowCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-notebook",
)

# Prints: "Visit https://keycloak.example.com/device and enter code: ABCD-EFGH"
trainer = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.cluster:6443",
})

trainer.create_job(name="my-experiment", ...)
```

**How it works:**

1. `OIDCDeviceFlowCredentials` performs OIDC discovery to find the device authorization endpoint.
2. On first use, it POSTs to the device endpoint and receives a `user_code` and `verification_uri`.
3. The code and URL are printed to the notebook output. The user opens the URL on any device (phone, laptop), enters the code, and authenticates.
4. Meanwhile, the SDK polls the token endpoint until the user completes authentication.
5. Once authenticated, the access token and refresh token are stored. Subsequent calls use the cached token with automatic refresh.

---

## UC4: Local Development with Browser Flow

**Scenario:** You're a developer working locally on your laptop. You want to click a link, authenticate in your browser, and be done — like any web app login.

**User code:**

```python
from kubeflow.trainer import TrainerClient
from kubeflow.common.auth import OIDCBrowserFlowCredentials

creds = OIDCBrowserFlowCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-dev",
)

# Opens browser automatically for login
trainer = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.cluster:6443",
})

trainer.list_jobs()
```

**How it works:**

1. `OIDCBrowserFlowCredentials` generates a PKCE code pair (code verifier + code challenge) and a random state parameter for CSRF protection.
2. It starts a local HTTP server on `localhost` to receive the callback.
3. It opens the browser to the IDP's authorization endpoint with the PKCE challenge and redirect URI.
4. The user authenticates in the browser. The IDP redirects back to `localhost` with an authorization code.
5. The callback server validates the state parameter, captures the code, and exchanges it for tokens at the token endpoint.
6. The access token and refresh token are cached. The local server shuts down.

---

## UC5: Existing kubeconfig / `oc login`

**Scenario:** You have existing scripts that use `oc login` or `kubectl` with a kubeconfig file. You don't want OIDC — your existing auth just works and you don't want to change anything.

**User code:**

```python
from kubeflow.trainer import TrainerClient

# Uses default kubeconfig (~/.kube/config)
trainer = TrainerClient()
trainer.list_jobs()

# Or specify a kubeconfig file and context
trainer = TrainerClient(backend_config={
    "config_file": "/path/to/kubeconfig",
    "context": "my-cluster",
})
```

**How it works:**

1. `load_kubernetes_config()` tries the resolution chain. No credentials, no token, no OIDC env vars found.
2. Falls through to priority 6 — kubeconfig. Calls `kubernetes.config.load_kube_config()` (the standard K8s Python client loader).
3. Whatever auth is in the kubeconfig (token, exec plugin, client cert, OIDC provider) is used as-is.
4. This is the existing behavior — adding OIDC support doesn't change or break it.

---

## UC6: In-Cluster Service Account

**Scenario:** Your training script runs inside a Kubernetes pod (a Job, a Tekton Task, a notebook server). The pod has a service account with the right RBAC. No tokens needed — the mounted SA token handles everything.

**User code:**

```python
from kubeflow.trainer import TrainerClient

# Automatically detects in-cluster environment
trainer = TrainerClient()
trainer.create_job(name="batch-training", ...)
```

**How it works:**

1. `load_kubernetes_config()` tries the resolution chain. Nothing found until priority 7.
2. Calls `kubernetes.config.load_incluster_config()`, which reads the mounted SA token from `/var/run/secrets/kubernetes.io/serviceaccount/token` and the API server address from the `KUBERNETES_SERVICE_HOST` env var.
3. The K8s client is configured with the SA token. No OIDC involved.

---

## UC7: Static Token from External Source

**Scenario:** You got a token from somewhere else — `oc whoami -t`, a CI secret, a vault lookup, a curl command. You just want to pass it in directly.

**User code:**

```python
from kubeflow.trainer import TrainerClient

trainer = TrainerClient(backend_config={
    "token": "eyJhbGciOiJSUzI1NiIs...",
    "server": "https://api.cluster:6443",
})

trainer.list_jobs()
```

Or via environment variables:

```bash
export KUBEFLOW_TOKEN="eyJhbGciOiJSUzI1NiIs..."
export KUBEFLOW_API_HOST="https://api.cluster:6443"
```

```python
from kubeflow.trainer import TrainerClient

trainer = TrainerClient()  # reads KUBEFLOW_TOKEN from env
trainer.list_jobs()
```

**How it works:**

1. The static token is wrapped in an internal `_StaticTokenCredentials` object.
2. This implements `refresh_api_key_hook` (sets the bearer token on every call) and `get_token()` (returns the string).
3. No refresh — when the token expires, API calls will fail with 401. This is the expected trade-off for static tokens.

---

## UC8: Shared Credentials Across K8s and REST Clients

**Scenario:** You're building a workflow that uses Trainer (K8s API) and Pipelines (REST API). You don't want to configure auth twice for the same identity.

**User code:**

```python
from kubeflow.trainer import TrainerClient
from kubeflow.pipelines import PipelinesClient
from kubeflow.common.auth import OIDCClientCredentials

creds = OIDCClientCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="my-client",
    client_secret="my-secret",
)

# K8s client — uses refresh_api_key_hook
trainer = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.cluster:6443",
})

# REST client — uses get_token() via the wrapper
pipelines = PipelinesClient(
    base_url="https://kfp.cluster/pipeline",
    credentials=creds,
)

# Both clients share the same identity and token state
trainer.create_job(name="training", ...)
pipelines.list_experiments()
```

**How it works:**

1. A single `OIDCClientCredentials` object is created.
2. `TrainerClient` wires `creds.refresh_api_key_hook` into the K8s `Configuration`. Before every K8s API call, the hook checks token expiry and refreshes if needed.
3. `PipelinesClient` (the SDK wrapper from KEP-125) calls `creds.get_token()` internally and passes the token to the upstream `kfp` client. If the token was already refreshed by the Trainer's hook, `get_token()` returns the cached value (no extra HTTP call).
4. Both interfaces read and write the same internal `_access_token`, `_refresh_token`, and `_expires_at` fields. A refresh from one path is visible to the other.

> **Note:** `KubeflowConfig` (UC9) is not required. Passing `credentials=creds` directly to each client works. `KubeflowConfig` is a convenience for reducing repetition when you have many clients.

---

## UC9: KubeflowConfig — One Config for All Clients

> **Status:** `KubeflowConfig` is a proposed future type, not yet implemented. PR #13 provides the building blocks it would use internally (`resolve_credentials()`, `TokenCredentialsBase`, `load_kubernetes_config()`). This use case shows the intended end state. Everything in UC1–UC8 works today without `KubeflowConfig`.

**Scenario:** You have Trainer, Pipelines, and Model Registry in one workflow. You want one credential object and one TLS configuration shared across all three — the "configure once, use everywhere" pattern. Without `KubeflowConfig`, this works by passing `credentials=creds` to each client individually (see UC8). `KubeflowConfig` is an optional convenience that reduces the repetition.

**User code:**

```python
from kubeflow import KubeflowConfig
from kubeflow.trainer import TrainerClient
from kubeflow.pipelines import PipelinesClient
from kubeflow.hub import ModelRegistryClient
from kubeflow.common.auth import OIDCClientCredentials

config = KubeflowConfig(
    credentials=OIDCClientCredentials(
        issuer_url="https://keycloak.example.com/realms/kubeflow",
        client_id="my-client",
        client_secret="my-secret",
    ),
    k8s_server="https://api.cluster:6443",
    verify_ssl=True,
    ca_cert="/etc/pki/ca.crt",
)

# Each client draws from the same config
trainer = TrainerClient(config=config)
pipelines = PipelinesClient(config=config, base_url="https://kfp.cluster/pipeline")
registry = ModelRegistryClient(config=config, base_url="https://registry.cluster")
```

**Without KubeflowConfig (equivalent, works today):**

```python
from kubeflow.trainer import TrainerClient
from kubeflow.pipelines import PipelinesClient
from kubeflow.hub import ModelRegistryClient
from kubeflow.common.auth import OIDCClientCredentials

creds = OIDCClientCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="my-client",
    client_secret="my-secret",
)

trainer = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.cluster:6443",
    "ca_cert": "/etc/pki/ca.crt",
})
pipelines = PipelinesClient(
    base_url="https://kfp.cluster/pipeline",
    credentials=creds,
)
registry = ModelRegistryClient(
    base_url="https://registry.cluster",
    credentials=creds,
)
```

**How it works:**

1. `KubeflowConfig` holds the credential object, K8s server URL, TLS settings, and any shared defaults. It is a configuration *distribution* object — not a new auth mechanism.
2. `TrainerClient(config=config)` calls `load_kubernetes_config(credentials=config.credentials, server=config.k8s_server, ...)` internally.
3. `PipelinesClient(config=config)` calls `resolve_credentials(credentials=config.credentials)` then `creds.get_token()` to get a token string for the KFP REST API.
4. `ModelRegistryClient(config=config)` does the same — `resolve_credentials()` then `creds.get_token()` for its REST API.
5. One credential object, one OIDC session, one TLS config. All three clients share the same identity. A token refresh from any client's call path is visible to all others.

**When to use `KubeflowConfig` vs. passing credentials directly:**

- **One client** → pass `credentials=creds` directly. `KubeflowConfig` adds nothing.
- **Two or more clients** → `KubeflowConfig` avoids repeating `credentials`, `server`, `ca_cert`, and `verify_ssl` on every constructor. It's purely a convenience.

---

## UC10: REST Client with resolve_credentials()

**Scenario:** You're building an SDK wrapper for a REST component (Pipelines, Model Registry, Feast). You want the wrapper to automatically resolve credentials from the environment — the same way K8s clients do — without duplicating env var logic.

**User code (wrapper author):**

```python
from kubeflow.common.auth import resolve_credentials, TokenCredentialsBase

class FeastClient:
    def __init__(
        self,
        *,
        base_url: str,
        user_token: str | None = None,
        credentials: TokenCredentialsBase | None = None,
    ):
        if user_token is None:
            creds = resolve_credentials(credentials=credentials)
            if creds:
                user_token = creds.get_token()
        self._client = feast.FeatureStore(registry=base_url, token=user_token)
```

**End user code:**

```python
# Explicit credentials
feast = FeastClient(base_url="...", credentials=creds)

# Or zero-code via env vars (KUBEFLOW_OIDC_* or KUBEFLOW_TOKEN)
feast = FeastClient(base_url="...")

# Or explicit token
feast = FeastClient(base_url="...", user_token="eyJhbG...")
```

**How it works:**

1. `resolve_credentials()` checks: explicit `credentials` → explicit `token` → `KUBEFLOW_OIDC_*` env vars → `KUBEFLOW_TOKEN` env var → `None`.
2. If credentials are found, `creds.get_token()` returns a valid token string.
3. The REST wrapper passes this to the upstream client. ~5 lines of auth wiring.
4. This is the same resolution logic that `load_kubernetes_config()` uses internally — extracted as a reusable function for REST wrappers.

---

## UC11: Custom Token Source (Vault, AWS STS)

**Scenario:** Your organization uses HashiCorp Vault or AWS STS for token issuance. You need the SDK to accept your custom token source — not be locked to OIDC.

**User code:**

```python
from kubeflow.trainer import TrainerClient
from kubeflow.common.auth import TokenCredentialsBase
from kubernetes.client import Configuration

class VaultCredentials(TokenCredentialsBase):
    def __init__(self, vault_addr: str, role: str):
        self._vault_addr = vault_addr
        self._role = role
        self._token: str | None = None

    def refresh_api_key_hook(self, config: Configuration) -> None:
        self._token = self._fetch_from_vault()
        config.api_key["authorization"] = self._token
        config.api_key_prefix["authorization"] = "Bearer"

    def get_token(self) -> str:
        if self._token is None:
            self._token = self._fetch_from_vault()
        return self._token

    def _fetch_from_vault(self) -> str:
        # Your Vault integration here
        ...

creds = VaultCredentials(vault_addr="https://vault.internal", role="ml-team")

trainer = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.cluster:6443",
})
```

**How it works:**

1. `TokenCredentialsBase` is a Protocol with two methods: `refresh_api_key_hook` and `get_token`. Any class that implements these can be used as credentials.
2. The SDK doesn't know or care that this is Vault — it calls the same interface as OIDC credentials.
3. This extensibility means the SDK isn't locked to one auth library. OIDC, Vault, AWS STS, corporate token services, or any future auth method can plug in.

---

## UC12: Identity Propagation for Audit

**Scenario:** You're a platform admin. When someone submits a training job, you need to know who submitted it — for compliance, audit, and cost allocation. The job should carry the user's identity from the OIDC token. The user shouldn't have to do anything — identity propagation should be automatic.

**User code:**

```python
from kubeflow.trainer import TrainerClient
from kubeflow.common.auth import OIDCClientCredentials

creds = OIDCClientCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-sdk",
    client_secret="my-secret",
)

trainer = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.cluster:6443",
})

# Identity annotations are added automatically — no extra code needed
trainer.create_job(name="nightly-finetune", ...)
```

The submitted TrainJob CRD will include annotations like:

```yaml
metadata:
  annotations:
    kubeflow.org/user-id: "alice"
    kubeflow.org/user-email: "alice@example.com"
    kubeflow.org/user-name: "Alice Smith"
    kubeflow.org/user-groups: "ml-team,admins"
```

**How it works:**

1. When `create_job()` is called, the SDK checks if the credential object supports `get_token()` (OIDC credentials do; kubeconfig and SA paths don't produce a JWT the SDK can inspect).
2. If a JWT is available, the SDK calls `identity_annotations(token)` internally — base64-decodes the JWT payload and extracts standard claims (`sub`, `email`, `name`, `preferred_username`, `groups`).
3. The resulting annotations are merged into the TrainJob CRD metadata before submission. User-provided annotations are not overwritten.
4. Platform admins and controllers can read these annotations for audit, RBAC decisions, or cost tracking.
5. The user writes zero identity code. If the credential doesn't produce a JWT (e.g., kubeconfig, SA token), annotation is silently skipped — no error, no change in behavior.

**For advanced use (manual control):**

The `identity_annotations()` function is also available as a public API for users who want to inspect or customize claims:

```python
from kubeflow.common.auth import identity_annotations

token = creds.get_token()
annotations = identity_annotations(token)
# {"kubeflow.org/user-id": "alice", "kubeflow.org/user-email": "alice@example.com", ...}
```

---

## UC13: Long-Running Training with Automatic Refresh

**Scenario:** You're running a multi-hour training job from a notebook. You submit the job and poll for status. Your OIDC token expires every 15 minutes. Without automatic refresh, you'd get a 401 at some point.

**User code:**

```python
from kubeflow.trainer import TrainerClient
from kubeflow.common.auth import OIDCClientCredentials

creds = OIDCClientCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-sdk",
    client_secret="my-secret",
)

trainer = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.cluster:6443",
})

trainer.create_job(name="large-finetune", ...)

# Polls for hours — token refreshes automatically
trainer.wait_for_job_status(
    name="large-finetune",
    status={"succeeded", "failed"},
    timeout=86400,  # 24 hours
)
```

**How it works:**

1. `wait_for_job_status` repeatedly calls the K8s API to check job status.
2. Before each API call, the K8s Python client invokes `refresh_api_key_hook`.
3. The hook checks `time.monotonic() >= self._expires_at`. If the token has expired (with a 30-second buffer), it performs a token refresh:
   - First tries a refresh token grant (fast, no re-authentication).
   - If that fails, falls back to a full client credentials exchange.
4. The fresh token is written into the K8s `Configuration`. The API call proceeds.
5. This happens transparently — the user never sees a 401 or has to re-authenticate.

---

## UC14: Custom CA / Internal PKI

**Scenario:** Your cluster and IDP use internal certificate authorities. OIDC discovery and token exchange must use your custom CA bundle.

**User code:**

```python
from kubeflow.trainer import TrainerClient
from kubeflow.common.auth import OIDCClientCredentials

creds = OIDCClientCredentials(
    issuer_url="https://keycloak.internal.corp/realms/kubeflow",
    client_id="kubeflow-sdk",
    client_secret="my-secret",
    verify="/etc/pki/internal-ca-bundle.crt",
)

trainer = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.cluster.internal:6443",
    "ca_cert": "/etc/pki/internal-ca-bundle.crt",
})
```

**How it works:**

1. The `verify` parameter on the credential class is passed through to `requests.get()` and `requests.post()` for all OIDC HTTP calls (discovery, token exchange, refresh).
2. The `ca_cert` parameter on the backend config is set on the K8s `Configuration.ssl_ca_cert`.
3. Both the OIDC provider communication and the K8s API communication use the custom CA bundle.

---

## UC15: Password Grant for Test Automation

**Scenario:** You're running integration tests that need to authenticate as a specific test user. No interactive flows — just a username and password in the test environment.

**User code:**

```python
from kubeflow.trainer import TrainerClient
from kubeflow.common.auth import OIDCPasswordCredentials

creds = OIDCPasswordCredentials(
    issuer_url="https://keycloak.example.com/realms/kubeflow",
    client_id="kubeflow-test",
    username="test-user",
    password="test-password",
)

trainer = TrainerClient(backend_config={
    "credentials": creds,
    "server": "https://api.cluster:6443",
})

trainer.create_job(name="integration-test", ...)
```

**How it works:**

1. `OIDCPasswordCredentials` performs OIDC discovery to find the token endpoint.
2. On first use, it POSTs a `password` grant with the username/password to the token endpoint.
3. The IDP returns an access token and (typically) a refresh token.
4. Subsequent refreshes use the refresh token — the password is not sent again after the initial exchange.
5. Note: The password grant is considered legacy in OAuth 2.1. Use client credentials (UC1) for service-to-service auth and device/browser flow (UC3/UC4) for human users where possible.
