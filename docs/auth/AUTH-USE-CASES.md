# Authentication Use Cases

Practical examples for every authentication scenario supported by the SDK
when backed by kube-authkit.

---

## UC-1: CI/CD with OIDC Client Credentials

```python
from kubeflow.trainer import TrainerClient

client = TrainerClient(backend_config={
    "auth_method": "oidc",
    "oidc_issuer": "https://keycloak.example.com/realms/rhoai",
    "client_id": "training-pipeline",
    "client_secret": "my-secret",
    "use_client_credentials": True,
    "k8s_api_host": "https://api.cluster:6443",
})
```

kube-authkit exchanges client credentials for an access token. The adapter
auto-refreshes via `get_token()` when the token expires.

---

## UC-2: Environment-Only Auth

```bash
export KUBEFLOW_OIDC_ISSUER=https://keycloak.example.com/realms/rhoai
export KUBEFLOW_OIDC_CLIENT_ID=training-pipeline
export KUBEFLOW_OIDC_CLIENT_SECRET=my-secret
export KUBEFLOW_API_HOST=https://api.cluster:6443
```

```python
from kubeflow.trainer import TrainerClient

client = TrainerClient()  # Picks up KUBEFLOW_* env vars automatically
```

---

## UC-3: Device Flow (Headless Notebook)

```python
from kubeflow.trainer import TrainerClient

client = TrainerClient(backend_config={
    "auth_method": "oidc",
    "oidc_issuer": "https://keycloak.example.com/realms/rhoai",
    "client_id": "jupyter-client",
    "use_device_flow": True,
    "k8s_api_host": "https://api.cluster:6443",
})
# Prints: "Visit https://keycloak.example.com/device and enter code: ABCD-EFGH"
```

---

## UC-4: Browser Flow with PKCE

```python
from kubeflow.trainer import TrainerClient

client = TrainerClient(backend_config={
    "auth_method": "oidc",
    "oidc_issuer": "https://keycloak.example.com/realms/rhoai",
    "client_id": "my-app",
    "k8s_api_host": "https://api.cluster:6443",
})
# Opens browser for interactive authentication
```

---

## UC-5: Existing Kubeconfig / `oc login`

```python
from kubeflow.trainer import TrainerClient

# Uses ~/.kube/config automatically (no extra config needed)
client = TrainerClient()
```

Or with an explicit path:

```python
client = TrainerClient(backend_config={
    "config_file": "/custom/path/kubeconfig",
})
```

---

## UC-6: In-Cluster Service Account

```python
from kubeflow.trainer import TrainerClient

# Auto-detected when running inside a Pod (no config needed)
client = TrainerClient()
```

---

## UC-7: Static Token

```python
from kubeflow.trainer import TrainerClient

client = TrainerClient(backend_config={
    "token": "sha256~my-openshift-token",
    "server": "https://api.cluster:6443",
})
```

Or via environment:

```bash
export KUBEFLOW_TOKEN=sha256~my-openshift-token
export KUBEFLOW_API_HOST=https://api.cluster:6443
```

---

## UC-8: Same Credentials for K8s + REST (Dual Interface)

```python
from kubeflow.common.auth import resolve_credentials

creds = resolve_credentials(
    token="my-token",
)

# K8s usage -- hook refreshes automatically
from kubeflow.common.auth import load_kubernetes_config
api_client = load_kubernetes_config(
    credentials=creds,
    server="https://api.cluster:6443",
)

# REST usage -- same credentials object
token = creds.get_token()
# Use token with KFP, Model Registry, etc.
```

---

## UC-9: Pluggable Custom Credentials (e.g. Vault)

```python
class VaultCredentials:
    """Satisfies TokenCredentialsBase protocol."""

    def __init__(self, vault_path: str):
        self._vault_path = vault_path

    def refresh_api_key_hook(self, config):
        config.api_key["authorization"] = self.get_token()
        config.api_key_prefix["authorization"] = "Bearer"

    def get_token(self) -> str:
        # Fetch fresh token from Vault
        return vault_client.read(self._vault_path)["token"]


from kubeflow.trainer import TrainerClient

client = TrainerClient(backend_config={
    "credentials": VaultCredentials("/secret/k8s-token"),
    "server": "https://api.cluster:6443",
})
```

---

## UC-10: Identity Propagation

```python
from kubeflow.common.auth import identity_annotations

token = creds.get_token()
annotations = identity_annotations(token)
# {'kubeflow.org/user-id': 'abc123',
#  'kubeflow.org/user-email': 'user@example.com',
#  'kubeflow.org/user-name': 'jdoe',
#  'kubeflow.org/user-groups': 'team-a,team-b'}
```

These annotations can be set on Jobs/Pods for audit trails.

---

## UC-11: Custom CA / Internal PKI

```python
from kubeflow.trainer import TrainerClient

client = TrainerClient(backend_config={
    "auth_method": "oidc",
    "oidc_issuer": "https://keycloak.internal.corp/realms/rhoai",
    "client_id": "training",
    "client_secret": "secret",
    "use_client_credentials": True,
    "k8s_api_host": "https://api.internal.corp:6443",
    "ca_cert": "/etc/pki/tls/certs/corp-ca-bundle.pem",
    "verify_ssl": True,
})
```

---

## UC-12: Keyring Persistence

```python
from kubeflow.trainer import TrainerClient

client = TrainerClient(backend_config={
    "auth_method": "oidc",
    "oidc_issuer": "https://keycloak.example.com/realms/rhoai",
    "client_id": "jupyter-client",
    "use_device_flow": True,
    "use_keyring": True,
    "k8s_api_host": "https://api.cluster:6443",
})
# First run: interactive authentication
# Subsequent runs: uses stored refresh token from system keyring
```

---

## UC-13: Long-Running Jobs with Automatic Refresh

```python
from kubeflow.trainer import TrainerClient

client = TrainerClient(backend_config={
    "auth_method": "oidc",
    "oidc_issuer": "https://keycloak.example.com/realms/rhoai",
    "client_id": "pipeline",
    "client_secret": "secret",
    "use_client_credentials": True,
    "k8s_api_host": "https://api.cluster:6443",
})

# The K8s client's refresh_api_key_hook ensures every API call
# uses a fresh token, even in multi-hour training jobs.
job = client.train(...)
# Token refreshes transparently during status polling
```

---

## Use Case Coverage Summary

| UC | Description | Covered | How |
|----|-------------|---------|-----|
| 1 | CI/CD client credentials | Yes | `use_client_credentials=True` |
| 2 | Env-only auth | Yes | `KUBEFLOW_OIDC_*` env vars |
| 3 | Device flow | Yes | `use_device_flow=True` |
| 4 | Browser + PKCE | Yes | Default OIDC flow |
| 5 | Kubeconfig | Yes | Auto-detected or `config_file=` |
| 6 | In-cluster SA | Yes | Auto-detected |
| 7 | Static token | Yes | `token=` or `KUBEFLOW_TOKEN` |
| 8 | Dual K8s+REST | Yes | `TokenCredentialsBase` protocol |
| 9 | Pluggable credentials | Yes | `credentials=` field |
| 10 | Identity propagation | Yes | `identity_annotations()` |
| 11 | Custom CA | Yes | `ca_cert=` + `verify_ssl=` |
| 12 | Keyring persistence | Yes | `use_keyring=True` |
| 13 | Long-running refresh | Yes | `refresh_api_key_hook` |
