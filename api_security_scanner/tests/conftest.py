"""
Pytest configuration and shared fixtures for API Security Scanner tests.
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest
import json
import yaml

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def sample_postman_collection():
    """Sample Postman collection for testing."""
    return {
        "info": {
            "name": "Test API Collection",
            "description": "Test collection for unit tests",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": [
            {
                "name": "Get Users",
                "request": {
                    "method": "GET",
                    "header": [
                        {
                            "key": "Content-Type",
                            "value": "application/json"
                        }
                    ],
                    "url": {
                        "raw": "https://api.example.com/users",
                        "protocol": "https",
                        "host": ["api", "example", "com"],
                        "path": ["users"]
                    }
                }
            },
            {
                "name": "Create User",
                "request": {
                    "method": "POST",
                    "header": [
                        {
                            "key": "Content-Type",
                            "value": "application/json"
                        }
                    ],
                    "body": {
                        "mode": "raw",
                        "raw": "{\"name\": \"John Doe\", \"email\": \"john@example.com\"}"
                    },
                    "url": {
                        "raw": "https://api.example.com/users",
                        "protocol": "https",
                        "host": ["api", "example", "com"],
                        "path": ["users"]
                    }
                }
            }
        ]
    }


@pytest.fixture
def sample_openapi_spec():
    """Sample OpenAPI specification for testing."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0",
            "description": "Test API for unit tests"
        },
        "servers": [
            {
                "url": "https://api.example.com",
                "description": "Test server"
            }
        ],
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "type": "object"
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Create user",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "User created"
                        }
                    }
                }
            }
        }
    }


@pytest.fixture
def sample_curl_command():
    """Sample curl command for testing."""
    return 'curl -X GET "https://api.example.com/users" -H "Content-Type: application/json"'


@pytest.fixture
def sample_zap_alerts():
    """Sample ZAP alerts for testing."""
    return [
        {
            "id": "10011",
            "name": "X-Frame-Options Header Scanner",
            "risk": "Informational",
            "confidence": "Medium",
            "description": "This checks if the X-Frame-Options header is present.",
            "solution": "Configure your web server to include an X-Frame-Options header.",
            "reference": "http://blogs.msdn.com/b/ieinternals/archive/2010/03/30/combating-clickjacking-with-x-frame-options.aspx",
            "cweid": "1021",
            "wascid": "15",
            "url": "https://api.example.com/users",
            "parameter": "",
            "evidence": "",
            "attack": "",
            "other": ""
        },
        {
            "id": "10020",
            "name": "X-Content-Type-Options Header Missing",
            "risk": "Low",
            "confidence": "Medium",
            "description": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'.",
            "solution": "Ensure that the application/web server sets the Content-Type header appropriately.",
            "reference": "http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx",
            "cweid": "16",
            "wascid": "15",
            "url": "https://api.example.com/users",
            "parameter": "",
            "evidence": "",
            "attack": "",
            "other": ""
        }
    ]


@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability for testing."""
    return {
        "vuln_id": "test-001",
        "name": "Test Vulnerability",
        "description": "This is a test vulnerability",
        "risk": "High",
        "cvss_score": 8.5,
        "solution": "Fix the vulnerability",
        "references": ["https://example.com/reference"],
        "cwe_id": "CWE-79",
        "wasc_id": "WASC-15",
        "url": "https://api.example.com/users",
        "parameter": "name",
        "evidence": "Test evidence",
        "scan_id": "test-scan-123",
        "request": "GET /users HTTP/1.1",
        "response": "HTTP/1.1 200 OK"
    }


@pytest.fixture
def mock_zap_manager():
    """Mock ZAP manager for testing."""
    mock_zap = Mock()
    mock_zap.start_zap.return_value = True
    mock_zap.stop_zap.return_value = True
    mock_zap.is_zap_running.return_value = True
    mock_zap.spider_target.return_value = (True, "spider-123")
    mock_zap.active_scan_target.return_value = (True, "scan-123")
    mock_zap.get_alerts.return_value = []
    mock_zap.get_performance_stats.return_value = {}
    return mock_zap


@pytest.fixture
def mock_database_manager():
    """Mock database manager for testing."""
    mock_db = Mock()
    mock_db.create_scan.return_value = True
    mock_db.save_zap_alerts.return_value = True
    mock_db.save_custom_alerts.return_value = True
    mock_db.get_scan.return_value = None
    mock_db.list_scans.return_value = []
    mock_db.get_scan_stats.return_value = {}
    return mock_db


@pytest.fixture
def mock_plugin_manager():
    """Mock plugin manager for testing."""
    mock_plugins = Mock()
    mock_plugins.loaded_plugins = []
    mock_plugins.run_plugins.return_value = []
    return mock_plugins


@pytest.fixture
def mock_requests():
    """Mock requests for testing HTTP calls."""
    with patch('requests.get') as mock_get, patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "OK"}
        mock_response.text = "OK"
        mock_get.return_value = mock_response
        mock_post.return_value = mock_response
        yield {"get": mock_get, "post": mock_post}


@pytest.fixture
def mock_subprocess():
    """Mock subprocess for testing process execution."""
    with patch('subprocess.Popen') as mock_popen:
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.wait.return_value = 0
        mock_process.terminate.return_value = None
        mock_process.kill.return_value = None
        mock_popen.return_value = mock_process
        yield mock_popen


@pytest.fixture
def sample_scan_data():
    """Sample scan data for testing."""
    return {
        "scan_id": "test-scan-123",
        "target_url": "https://api.example.com",
        "input_type": "file",
        "input_source": "test-collection.json",
        "auth_type": "header",
        "start_time": "2024-01-01T10:00:00Z",
        "end_time": "2024-01-01T10:05:00Z",
        "status": "completed",
        "zap_alerts_count": 2,
        "custom_alerts_count": 1,
        "total_requests": 5
    }


@pytest.fixture
def temp_db_path(temp_dir):
    """Temporary database path for testing."""
    return os.path.join(temp_dir, "test_scan_results.db")


@pytest.fixture
def temp_log_dir(temp_dir):
    """Temporary log directory for testing."""
    log_dir = os.path.join(temp_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    return log_dir


@pytest.fixture
def temp_reports_dir(temp_dir):
    """Temporary reports directory for testing."""
    reports_dir = os.path.join(temp_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir


@pytest.fixture
def mock_file_system(temp_dir):
    """Mock file system operations."""
    with patch('pathlib.Path.exists') as mock_exists, \
         patch('pathlib.Path.mkdir') as mock_mkdir, \
         patch('builtins.open', create=True) as mock_open:
        
        mock_exists.return_value = True
        mock_mkdir.return_value = None
        
        # Mock file content
        mock_file = Mock()
        mock_file.__enter__ = Mock(return_value=mock_file)
        mock_file.__exit__ = Mock(return_value=None)
        mock_file.read.return_value = "test content"
        mock_file.write.return_value = None
        mock_open.return_value = mock_file
        
        yield {
            "exists": mock_exists,
            "mkdir": mock_mkdir,
            "open": mock_open
        }


@pytest.fixture(autouse=True)
def clean_environment():
    """Clean environment variables before each test."""
    # Store original environment
    original_env = os.environ.copy()
    
    # Clean up test environment variables
    test_env_vars = [
        'ZAP_HOST', 'ZAP_PORT', 'SCAN_DB_PATH', 
        'LOG_DIR', 'REPORTS_DIR', 'WORKSPACE_DIR'
    ]
    
    for var in test_env_vars:
        if var in os.environ:
            del os.environ[var]
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mock_container_config():
    """Mock container configuration for testing."""
    mock_config = Mock()
    mock_config.is_container = False
    mock_config.get_zap_config.return_value = {
        'zap_path': None,
        'zap_host': 'localhost',
        'zap_port': 8080,
        'use_external_zap': False,
        'network_mode': 'host'
    }
    mock_config.get_paths_config.return_value = {
        'scan_db_path': '/app/data/scan_results.db',
        'log_dir': '/app/logs',
        'reports_dir': '/app/reports',
        'workspace_dir': '/workspace'
    }
    return mock_config


# Test markers
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow running tests")
    config.addinivalue_line("markers", "network: Tests requiring network access")
    config.addinivalue_line("markers", "docker: Tests requiring Docker")
