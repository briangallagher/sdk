"""
Namespace Shim for `kubeflow.model_registry`

This module acts as a transparent proxy to the external `model_registry` package.
It enables users to access `model_registry` as if it were part of the `kubeflow` namespace.

Examples:
    from kubeflow.model_registry import ModelRegistry
    from kubeflow.model_registry.aws import AwsModelRegistryClient

This is particularly useful when `model_registry` is declared as an **optional dependency**
of the `kubeflow-sdk` project and you're using a unified namespace for user experience.

What this shim does:
    - Imports the installed `model_registry` package.
    - Replaces `sys.modules["kubeflow.model_registry"]` with the `model_registry` module.
    - Ensures that already-imported submodules of `model_registry` are also available under
      the `kubeflow.model_registry.*` namespace (e.g., `kubeflow.model_registry.aws`).

Requirements:
    - `model_registry` must be installed (with extras if needed).
    - You must define `kubeflow` as a namespace package using either:
        - `pkgutil` or `pkg_resources`
        - or a shared `pyproject.toml` layout (PEP 420)

Raises:
    ImportError: If `model_registry` is not installed or cannot be imported.

Maintainer Notes:
    This approach uses `sys.modules` rewiring, which can confuse static analyzers
    and IDEs but behaves correctly at runtime.
"""

import importlib
import sys

try:
    # Dynamically import the actual external package
    _external_pkg = importlib.import_module("model_registry")

    # Replace this shim module with the real one
    sys.modules[__name__] = _external_pkg

    # Also register it under the full dotted name so submodules work
    setattr(sys.modules[__package__], "model_registry", _external_pkg)

    # Mirror already-imported submodules (e.g., model_registry.aws)
    _prefix = _external_pkg.__name__ + "."
    for name, module in list(sys.modules.items()):
        if name.startswith(_prefix):
            alias = __name__ + name[len(_external_pkg.__name__):]
            sys.modules[alias] = module

except ModuleNotFoundError as e:
    raise ImportError(
        "Optional dependency 'model_registry' is not installed.\n"
        "To use `kubeflow.model_registry`, install it with:\n\n"
        "    pip install kubeflow-sdk[model_registry]\n"
        "or directly:\n"
        "    pip install model-registry\n"
        "\n"
        "If you need specific cloud support (e.g. AWS):\n"
        "    pip install model-registry[aws]"
    ) from e
