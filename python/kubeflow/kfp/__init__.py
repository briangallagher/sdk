"""
Namespace Shim for `kubeflow.kfp`

This module acts as a transparent proxy to the external `kfp` package.
It enables users to access `kfp` as if it were part of the `kubeflow` namespace.

Examples:
    from kubeflow.kfp import ModelRegistry
    from kubeflow.kfp.aws import AwsModelRegistryClient

This is particularly useful when `kfp` is declared as an **optional dependency**
of the `kubeflow-sdk` project and you're using a unified namespace for user experience.

What this shim does:
    - Imports the installed `kfp` package.
    - Replaces `sys.modules["kubeflow.kfp"]` with the `kfp` module.
    - Ensures that already-imported submodules of `kfp` are also available under
      the `kubeflow.kfp.*` namespace (e.g., `kubeflow.kfp.aws`).

Requirements:
    - `kfp` must be installed (with extras if needed).
    - You must define `kubeflow` as a namespace package using either:
        - `pkgutil` or `pkg_resources`
        - or a shared `pyproject.toml` layout (PEP 420)

Raises:
    ImportError: If `kfp` is not installed or cannot be imported.

Maintainer Notes:
    This approach uses `sys.modules` rewiring, which can confuse static analyzers
    and IDEs but behaves correctly at runtime.
"""

import importlib
import sys

try:
    # Dynamically import the actual external package
    _external_pkg = importlib.import_module("kfp")

    # Replace this shim module with the real one
    sys.modules[__name__] = _external_pkg

    # Also register it under the full dotted name so submodules work
    setattr(sys.modules[__package__], "kfp", _external_pkg)

    # Mirror already-imported submodules (e.g., kfp.aws)
    _prefix = _external_pkg.__name__ + "."
    for name, module in list(sys.modules.items()):
        if name.startswith(_prefix):
            alias = __name__ + name[len(_external_pkg.__name__):]
            sys.modules[alias] = module

except ModuleNotFoundError as e:
    raise ImportError(
        "Optional dependency 'kfp' is not installed.\n"
        "To use `kubeflow.kfp`, install it with:\n\n"
        "    pip install kubeflow-sdk[kfp]\n"
        "or directly:\n"
        "    pip install kfp\n"
    ) from e
