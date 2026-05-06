# Code Quality Standards

**All Python code MUST include type hints and return types.**

## Bad

```python
def p(u, d):
    return [x for x in u if x not in d]
```

## Good

```python
def filter_completed_jobs(jobs: list[str], completed: set[str]) -> list[str]:
    """Filter out jobs that are already completed.

    Args:
        jobs: List of job identifiers to filter.
        completed: Set of completed job identifiers.

    Returns:
        List of jobs that are not yet completed.
    """
    return [job for job in jobs if job not in completed]
```

## Style Requirements

- Line length 100, Python 3.10 target, double quotes, spaces indent
- Imports: isort via ruff; first-party is `kubeflow`; prefer absolute imports
- Naming: pep8-naming; functions/vars `snake_case`, classes `PascalCase`, constants `UPPER_SNAKE_CASE`; prefix private with `_`
- Use descriptive, self-explanatory variable names — avoid overly short or cryptic identifiers
- Break up complex functions (>20 lines) into smaller, focused functions where it makes sense
- Follow existing patterns in the codebase you're modifying
