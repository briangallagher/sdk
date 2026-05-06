# Security and Documentation Standards

## Security Checklist

- [ ] No `eval()`, `exec()`, or `pickle` on user-controlled input
- [ ] Proper exception handling (no bare `except:`) and use descriptive error messages
- [ ] Remove unreachable/commented code before committing
- [ ] Ensure proper resource cleanup (file handles, connections)
- [ ] No secrets in code, logs, or examples

### Bad

```python
def load_config(path):
    with open(path) as f:
        return eval(f.read())  # Never eval user input
```

### Good

```python
import yaml

def load_config(path: str) -> dict:
    """Load configuration from YAML file."""
    with open(path, 'r') as f:
        return yaml.safe_load(f)
```

## Documentation Standards

**Use Google-style docstrings with Args section for all public functions.**

### Bad

```python
def submit_job(name, config):
    """Submit a job."""
```

### Good

```python
def submit_job(name: str, config: dict, *, priority: str = "normal") -> str:
    """Submit a training job with specified configuration.

    Args:
        name: The job name identifier.
        config: Job configuration dictionary.
        priority: Job priority level ('low', 'normal', 'high').

    Returns:
        Job ID string for tracking the submitted job.

    Raises:
        InvalidConfigError: If the configuration is invalid.
        ResourceUnavailableError: If required resources are not available.
    """
```

### Documentation Guidelines

- Types go in function signatures, NOT in docstrings
- Focus on "why" rather than "what" in descriptions
- Document all parameters, return values, and exceptions
- Keep descriptions concise but clear
- Use Pydantic v2 models in `kubeflow.trainer.types` for schemas
