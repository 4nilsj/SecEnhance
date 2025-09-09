# Testing Guide

This guide provides comprehensive information about testing the API Security Scanner application.

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Test Types](#test-types)
- [Test Configuration](#test-configuration)
- [Writing Tests](#writing-tests)
- [Test Fixtures](#test-fixtures)
- [Mocking and Stubbing](#mocking-and-stubbing)
- [Coverage](#coverage)
- [Continuous Integration](#continuous-integration)
- [Troubleshooting](#troubleshooting)

## Overview

The API Security Scanner includes a comprehensive test suite with:

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions and workflows
- **Container Tests**: Test Docker/Podman compatibility
- **Plugin Tests**: Test custom security plugins
- **End-to-End Tests**: Test complete scanning workflows

## Test Structure

```
tests/
├── __init__.py                 # Test package initialization
├── conftest.py                 # Pytest configuration and fixtures
├── test_utils.py               # Tests for utils modules
├── test_src.py                 # Tests for src modules
├── test_plugins.py             # Tests for plugin modules
├── test_container.py           # Tests for container configuration
├── test_integration.py         # Integration tests
├── fixtures.py                 # Test fixtures and mock data
├── test_runners.py             # Test runner utilities
└── test_config.py              # Test configuration utilities
```

## Running Tests

### Quick Start

```bash
# Run quick tests (excludes slow/integration tests)
python run_tests.py --quick

# Run full test suite with coverage
python run_tests.py --full

# Run unit tests only
python run_tests.py --unit

# Run integration tests only
python run_tests.py --integration

# Validate test environment
python run_tests.py --validate
```

### Using pytest directly

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov=utils --cov=plugins

# Run specific test file
pytest tests/test_utils.py

# Run specific test function
pytest tests/test_utils.py::TestLogger::test_get_logger

# Run tests with specific markers
pytest -m unit
pytest -m integration
pytest -m "not slow"
```

### Test Runners

```bash
# Using test runners
python tests/test_runners.py --quick
python tests/test_runners.py --full
python tests/test_runners.py --unit
python tests/test_runners.py --integration
```

## Test Types

### Unit Tests

Unit tests test individual components in isolation:

- **Utils Tests** (`test_utils.py`):
  - Logger functionality
  - Authentication handlers
  - Input parsers (Postman, OpenAPI, curl)

- **Source Tests** (`test_src.py`):
  - Database manager
  - ZAP manager
  - Plugin manager
  - Report generator

- **Plugin Tests** (`test_plugins.py`):
  - CORS checker
  - Rate limiting checker
  - Security headers checker
  - Enhanced security checker

- **Container Tests** (`test_container.py`):
  - Container configuration
  - Environment detection
  - Docker/Podman compatibility

### Integration Tests

Integration tests (`test_integration.py`) test component interactions:

- End-to-end scanning workflows
- Database operations
- ZAP integration
- Plugin integration
- Input parsing integration
- Container integration

### Test Markers

Tests are organized using pytest markers:

- `@pytest.mark.unit` - Unit tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.slow` - Slow running tests
- `@pytest.mark.network` - Tests requiring network access
- `@pytest.mark.docker` - Tests requiring Docker
- `@pytest.mark.zap` - Tests requiring ZAP
- `@pytest.mark.database` - Tests requiring database

## Test Configuration

### pytest.ini

```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py *_test.py
python_classes = Test*
python_functions = test_*

addopts = 
    --verbose
    --tb=short
    --strict-markers
    --disable-warnings
    --cov=src
    --cov=utils
    --cov=plugins
    --cov-report=term-missing
    --cov-report=html:htmlcov
    --cov-report=xml:coverage.xml
    --cov-fail-under=80

markers =
    unit: Unit tests
    integration: Integration tests
    slow: Slow running tests
    network: Tests requiring network access
    docker: Tests requiring Docker
    zap: Tests requiring ZAP
    database: Tests requiring database

timeout = 300
```

### Environment Variables

Test environment variables:

- `PYTHONPATH` - Project root path
- `TESTING` - Set to "true" during tests
- `LOG_LEVEL` - Logging level (DEBUG, INFO, WARNING, ERROR)

## Writing Tests

### Test Structure

```python
import pytest
from unittest.mock import Mock, patch

class TestComponent:
    """Test component functionality."""
    
    def test_basic_functionality(self):
        """Test basic functionality."""
        # Arrange
        component = Component()
        
        # Act
        result = component.method()
        
        # Assert
        assert result is not None
    
    def test_with_fixtures(self, sample_data):
        """Test with fixtures."""
        # Use fixture data
        assert len(sample_data) > 0
    
    def test_with_mocking(self, mock_external_service):
        """Test with mocking."""
        mock_external_service.return_value = "mocked_response"
        
        result = component.call_external_service()
        
        assert result == "mocked_response"
        mock_external_service.assert_called_once()
    
    @pytest.mark.parametrize("input,expected", [
        ("input1", "output1"),
        ("input2", "output2"),
    ])
    def test_parametrized(self, input, expected):
        """Test with parameters."""
        result = component.process(input)
        assert result == expected
```

### Test Fixtures

Use fixtures for common test data:

```python
@pytest.fixture
def sample_data():
    """Sample data for testing."""
    return {"key": "value"}

@pytest.fixture
def mock_service():
    """Mock external service."""
    with patch('module.external_service') as mock:
        yield mock
```

### Assertions

Use appropriate assertions:

```python
# Basic assertions
assert result is not None
assert result == expected_value
assert result in collection

# Exception assertions
with pytest.raises(ValueError):
    component.invalid_operation()

# Collection assertions
assert len(results) == 3
assert "item" in results
assert all(item > 0 for item in results)
```

## Test Fixtures

### Common Fixtures

Available in `conftest.py`:

- `temp_dir` - Temporary directory
- `sample_postman_collection` - Sample Postman collection
- `sample_openapi_spec` - Sample OpenAPI specification
- `sample_curl_command` - Sample curl command
- `sample_zap_alerts` - Sample ZAP alerts
- `sample_vulnerability` - Sample vulnerability
- `mock_zap_manager` - Mock ZAP manager
- `mock_database_manager` - Mock database manager
- `mock_plugin_manager` - Mock plugin manager
- `mock_requests` - Mock HTTP requests
- `mock_subprocess` - Mock subprocess calls

### Custom Fixtures

Create custom fixtures in test files:

```python
@pytest.fixture
def custom_data():
    """Custom test data."""
    return {"custom": "data"}

@pytest.fixture
def setup_environment():
    """Setup test environment."""
    # Setup code
    yield
    # Cleanup code
```

## Mocking and Stubbing

### Mocking External Services

```python
@patch('requests.get')
def test_http_request(mock_get):
    """Test HTTP request with mocking."""
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"data": "value"}
    
    result = component.make_request()
    
    assert result["data"] == "value"
    mock_get.assert_called_once_with("https://api.example.com")
```

### Mocking File Operations

```python
@patch('builtins.open', new_callable=mock_open)
def test_file_operation(mock_file):
    """Test file operation with mocking."""
    mock_file.return_value.read.return_value = "file content"
    
    result = component.read_file("test.txt")
    
    assert result == "file content"
    mock_file.assert_called_once_with("test.txt", "r")
```

### Mocking Database Operations

```python
@patch('sqlite3.connect')
def test_database_operation(mock_connect):
    """Test database operation with mocking."""
    mock_cursor = Mock()
    mock_connect.return_value.cursor.return_value = mock_cursor
    mock_cursor.fetchall.return_value = [("data1",), ("data2",)]
    
    result = component.query_database()
    
    assert len(result) == 2
    mock_connect.assert_called_once()
```

## Coverage

### Coverage Configuration

Coverage is configured in `pytest.ini`:

```ini
--cov=src
--cov=utils
--cov=plugins
--cov-report=term-missing
--cov-report=html:htmlcov
--cov-report=xml:coverage.xml
--cov-fail-under=80
```

### Coverage Reports

Generate coverage reports:

```bash
# HTML report
pytest --cov=src --cov-report=html

# XML report
pytest --cov=src --cov-report=xml

# Terminal report
pytest --cov=src --cov-report=term-missing
```

### Coverage Exclusions

Exclude files from coverage:

```python
# In test files
@pytest.mark.no_cover
def test_function():
    pass

# In source files
# pragma: no cover
def debug_function():
    pass
```

## Continuous Integration

### GitHub Actions

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, 3.10, 3.11]
    
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v3
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    
    - name: Run tests
      run: |
        python run_tests.py --full --coverage
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

### GitLab CI

```yaml
test:
  stage: test
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - python run_tests.py --full --coverage
  coverage: '/TOTAL.*\s+(\d+%)$/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml
```

## Troubleshooting

### Common Issues

#### Import Errors

```bash
# Add project root to Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Or use the test runner
python run_tests.py --validate
```

#### Missing Dependencies

```bash
# Install test dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

#### Test Failures

```bash
# Run with verbose output
pytest -v

# Run specific failing test
pytest tests/test_utils.py::TestLogger::test_get_logger -v

# Run with debugging
pytest --pdb
```

#### Coverage Issues

```bash
# Check coverage configuration
pytest --cov=src --cov-report=term-missing

# Generate HTML report for detailed analysis
pytest --cov=src --cov-report=html
```

### Debug Mode

Run tests in debug mode:

```bash
# Drop into debugger on failure
pytest --pdb

# Drop into debugger on first failure
pytest -x --pdb

# Show local variables on failure
pytest -l
```

### Test Isolation

Ensure test isolation:

```python
@pytest.fixture(autouse=True)
def clean_environment():
    """Clean environment before each test."""
    # Store original environment
    original_env = os.environ.copy()
    
    # Clean up test environment
    for key in ['TEST_VAR']:
        if key in os.environ:
            del os.environ[key]
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)
```

## Best Practices

1. **Test Naming**: Use descriptive test names that explain what is being tested
2. **Test Structure**: Follow Arrange-Act-Assert pattern
3. **Test Isolation**: Each test should be independent and not affect others
4. **Mocking**: Mock external dependencies to ensure test reliability
5. **Fixtures**: Use fixtures for common test data and setup
6. **Coverage**: Aim for high test coverage but focus on critical paths
7. **Performance**: Keep unit tests fast, use markers for slow tests
8. **Documentation**: Document complex test scenarios and edge cases

## Test Data

Test data is managed in `tests/fixtures.py`:

- Sample API collections and specifications
- Mock ZAP alerts and vulnerabilities
- Test scan data and performance statistics
- Sample authentication data
- Mock HTTP responses and database records

## Contributing

When adding new tests:

1. Follow the existing test structure and naming conventions
2. Add appropriate test markers
3. Include both positive and negative test cases
4. Mock external dependencies
5. Update test documentation if needed
6. Ensure tests pass in CI/CD pipeline

For more information, see the main project documentation and the test source code.
