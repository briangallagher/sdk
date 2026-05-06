# Maintain Stable Public Interfaces

**Always preserve function signatures, argument positions, and names for exported/public methods.**

## Bad — Breaking Change

```python
def train_model(id, verbose=False):  # Changed from `model_id`
    pass
```

## Good — Stable Interface

```python
def train_model(model_id: str, verbose: bool = False) -> TrainingResult:
    """Train model with optional verbose output."""
    pass
```

## Before Changing Any Public API

- Check if the function/class is exported in `__init__.py`
- Look for existing usage patterns in tests and examples
- Use keyword-only arguments for new parameters: `*, new_param: str = "default"`
- Mark experimental features clearly with docstring warnings
