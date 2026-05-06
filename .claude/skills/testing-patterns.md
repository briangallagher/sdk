# Testing Requirements

**Every new feature or bugfix MUST be covered by unit tests.**

## Test Organization

- Unit tests: `kubeflow/trainer/**/*_test.py` (no network calls allowed)
- Use `pytest` as the testing framework
- See `kubeflow/trainer/test/common.py` for fixtures and patterns
- Unit test structure must be consistent between each other (see `kubeflow/trainer/backends/kubernetes/backend_test.py` for reference)

## Test Structure Pattern

Following `backend_test.py`:

- Use `TestCase` dataclass for parametrized tests
- Include `name`, `expected_status`, `config`, `expected_output/error` fields
- Print test execution status for debugging
- Handle both success and exception cases in the same test function
- Use `pytest.mark.parametrize` with `TestCase` dataclass for multiple test scenarios:

```python
@pytest.mark.parametrize(
    "test_case",
    [
        TestCase(
            name="valid flow with all defaults",
            expected_status=SUCCESS,
            config={"name": "job-1"},
            expected_output=["job-1"],
        ),
        TestCase(
            name="empty jobs list",
            expected_status=SUCCESS,
            config={"name": "empty"},
            expected_output=[],
        ),
    ],
)
def test_filter_jobs_parametrized(test_case):
    """Test job filtering with multiple scenarios."""
    result = filter_jobs(**test_case.config)
    assert result == test_case.expected_output
```
