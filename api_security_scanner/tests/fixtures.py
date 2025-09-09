"""
Test fixtures and mock data for API Security Scanner tests.
"""

import json
import yaml
from pathlib import Path


def create_sample_postman_collection():
    """Create a sample Postman collection for testing."""
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
            },
            {
                "name": "Update User",
                "request": {
                    "method": "PUT",
                    "header": [
                        {
                            "key": "Content-Type",
                            "value": "application/json"
                        },
                        {
                            "key": "Authorization",
                            "value": "Bearer {{token}}"
                        }
                    ],
                    "body": {
                        "mode": "raw",
                        "raw": "{\"name\": \"Jane Doe\", \"email\": \"jane@example.com\"}"
                    },
                    "url": {
                        "raw": "https://api.example.com/users/1",
                        "protocol": "https",
                        "host": ["api", "example", "com"],
                        "path": ["users", "1"]
                    }
                }
            },
            {
                "name": "Delete User",
                "request": {
                    "method": "DELETE",
                    "header": [
                        {
                            "key": "Authorization",
                            "value": "Bearer {{token}}"
                        }
                    ],
                    "url": {
                        "raw": "https://api.example.com/users/1",
                        "protocol": "https",
                        "host": ["api", "example", "com"],
                        "path": ["users", "1"]
                    }
                }
            }
        ]
    }


def create_sample_openapi_spec():
    """Create a sample OpenAPI specification for testing."""
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
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "integer"},
                                                "name": {"type": "string"},
                                                "email": {"type": "string"}
                                            }
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
                                    },
                                    "required": ["name", "email"]
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
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User found"
                        }
                    }
                },
                "put": {
                    "summary": "Update user",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"}
                        }
                    ],
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
                        "200": {
                            "description": "User updated"
                        }
                    }
                },
                "delete": {
                    "summary": "Delete user",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"}
                        }
                    ],
                    "responses": {
                        "204": {
                            "description": "User deleted"
                        }
                    }
                }
            }
        }
    }


def create_sample_zap_alerts():
    """Create sample ZAP alerts for testing."""
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
        },
        {
            "id": "10021",
            "name": "X-XSS-Protection Header Missing",
            "risk": "Low",
            "confidence": "Medium",
            "description": "The X-XSS-Protection header was not set.",
            "solution": "Ensure that the application/web server sets the X-XSS-Protection header.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
            "cweid": "693",
            "wascid": "14",
            "url": "https://api.example.com/users",
            "parameter": "",
            "evidence": "",
            "attack": "",
            "other": ""
        },
        {
            "id": "10038",
            "name": "Content Security Policy (CSP) Header Not Set",
            "risk": "Medium",
            "confidence": "Medium",
            "description": "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks.",
            "solution": "Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            "cweid": "693",
            "wascid": "15",
            "url": "https://api.example.com/users",
            "parameter": "",
            "evidence": "",
            "attack": "",
            "other": ""
        },
        {
            "id": "10054",
            "name": "Cross-Domain JavaScript Source File Inclusion",
            "risk": "High",
            "confidence": "Medium",
            "description": "The page includes one or more script files from a third-party domain.",
            "solution": "Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/Security/Types_of_attacks#Cross-site_scripting_(XSS)",
            "cweid": "829",
            "wascid": "8",
            "url": "https://api.example.com/users",
            "parameter": "",
            "evidence": "",
            "attack": "",
            "other": ""
        }
    ]


def create_sample_vulnerabilities():
    """Create sample vulnerabilities for testing."""
    return [
        {
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
        },
        {
            "vuln_id": "test-002",
            "name": "Another Test Vulnerability",
            "description": "This is another test vulnerability",
            "risk": "Medium",
            "cvss_score": 6.2,
            "solution": "Fix this vulnerability too",
            "references": ["https://example.com/reference2"],
            "cwe_id": "CWE-89",
            "wasc_id": "WASC-19",
            "url": "https://api.example.com/users/1",
            "parameter": "id",
            "evidence": "Another test evidence",
            "scan_id": "test-scan-123",
            "request": "GET /users/1 HTTP/1.1",
            "response": "HTTP/1.1 200 OK"
        }
    ]


def create_sample_scan_data():
    """Create sample scan data for testing."""
    return {
        "scan_id": "test-scan-123",
        "target_url": "https://api.example.com",
        "input_type": "file",
        "input_source": "test-collection.json",
        "auth_type": "header",
        "start_time": "2024-01-01T10:00:00Z",
        "end_time": "2024-01-01T10:05:00Z",
        "status": "completed",
        "zap_alerts_count": 5,
        "custom_alerts_count": 2,
        "total_requests": 4
    }


def create_sample_curl_commands():
    """Create sample curl commands for testing."""
    return [
        'curl -X GET "https://api.example.com/users" -H "Content-Type: application/json"',
        'curl -X POST "https://api.example.com/users" -H "Content-Type: application/json" -d \'{"name": "John", "email": "john@example.com"}\'',
        'curl -X PUT "https://api.example.com/users/1" -H "Content-Type: application/json" -H "Authorization: Bearer token123" -d \'{"name": "Jane"}\'',
        'curl -X DELETE "https://api.example.com/users/1" -H "Authorization: Bearer token123"',
        'curl -X GET "https://api.example.com/users?page=1&limit=10" -H "Accept: application/json"',
        'curl -X POST "https://api.example.com/auth/login" -H "Content-Type: application/json" -d \'{"username": "admin", "password": "password"}\''
    ]


def create_sample_requests_data():
    """Create sample requests data for testing."""
    return [
        {
            "url": "https://api.example.com/users",
            "method": "GET",
            "headers": {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        },
        {
            "url": "https://api.example.com/users",
            "method": "POST",
            "headers": {
                "Content-Type": "application/json"
            },
            "body": '{"name": "John Doe", "email": "john@example.com"}'
        },
        {
            "url": "https://api.example.com/users/1",
            "method": "PUT",
            "headers": {
                "Content-Type": "application/json",
                "Authorization": "Bearer token123"
            },
            "body": '{"name": "Jane Doe", "email": "jane@example.com"}'
        },
        {
            "url": "https://api.example.com/users/1",
            "method": "DELETE",
            "headers": {
                "Authorization": "Bearer token123"
            }
        }
    ]


def create_sample_authentication_data():
    """Create sample authentication data for testing."""
    return {
        "header": {
            "type": "header",
            "name": "X-API-Key",
            "value": "test-api-key-123"
        },
        "bearer": {
            "type": "token",
            "name": "Authorization",
            "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        },
        "cookie": {
            "type": "cookie",
            "name": "session",
            "value": "session-id-123456"
        }
    }


def create_sample_performance_stats():
    """Create sample performance statistics for testing."""
    return {
        "scan_duration": 300.5,
        "zap_startup_time": 15.2,
        "spider_duration": 120.3,
        "active_scan_duration": 150.8,
        "plugin_execution_time": 14.2,
        "total_requests_processed": 4,
        "zap_alerts_found": 5,
        "custom_alerts_found": 2,
        "memory_usage_mb": 256.7,
        "cpu_usage_percent": 45.2
    }


def create_sample_error_logs():
    """Create sample error logs for testing."""
    return [
        {
            "timestamp": "2024-01-01T10:00:00Z",
            "level": "ERROR",
            "message": "Failed to connect to ZAP",
            "module": "zap_manager",
            "scan_id": "test-scan-123"
        },
        {
            "timestamp": "2024-01-01T10:01:00Z",
            "level": "WARNING",
            "message": "Plugin execution failed",
            "module": "plugin_manager",
            "scan_id": "test-scan-123"
        },
        {
            "timestamp": "2024-01-01T10:02:00Z",
            "level": "INFO",
            "message": "Scan completed successfully",
            "module": "cli",
            "scan_id": "test-scan-123"
        }
    ]


def create_test_files(temp_dir):
    """Create test files in the specified directory."""
    files = {}
    
    # Create Postman collection file
    postman_file = Path(temp_dir) / "test-collection.json"
    with open(postman_file, 'w') as f:
        json.dump(create_sample_postman_collection(), f, indent=2)
    files['postman'] = str(postman_file)
    
    # Create OpenAPI spec file
    openapi_file = Path(temp_dir) / "test-spec.yaml"
    with open(openapi_file, 'w') as f:
        yaml.dump(create_sample_openapi_spec(), f, default_flow_style=False)
    files['openapi'] = str(openapi_file)
    
    # Create curl commands file
    curl_file = Path(temp_dir) / "test-commands.txt"
    with open(curl_file, 'w') as f:
        f.write('\n'.join(create_sample_curl_commands()))
    files['curl'] = str(curl_file)
    
    # Create invalid JSON file
    invalid_json_file = Path(temp_dir) / "invalid.json"
    with open(invalid_json_file, 'w') as f:
        f.write('{ invalid json content }')
    files['invalid_json'] = str(invalid_json_file)
    
    # Create invalid YAML file
    invalid_yaml_file = Path(temp_dir) / "invalid.yaml"
    with open(invalid_yaml_file, 'w') as f:
        f.write('invalid: yaml: content: [')
    files['invalid_yaml'] = str(invalid_yaml_file)
    
    return files


def create_mock_zap_responses():
    """Create mock ZAP API responses for testing."""
    return {
        "version": {
            "status_code": 200,
            "json": {"version": "2.12.0"}
        },
        "spider_start": {
            "status_code": 200,
            "json": {"scan": "spider-123"}
        },
        "spider_status": {
            "status_code": 200,
            "json": {"status": "100"}
        },
        "ascan_start": {
            "status_code": 200,
            "json": {"scan": "scan-123"}
        },
        "ascan_status": {
            "status_code": 200,
            "json": {"status": "100"}
        },
        "alerts": {
            "status_code": 200,
            "json": {"alerts": create_sample_zap_alerts()}
        },
        "error": {
            "status_code": 500,
            "json": {"error": "Internal server error"}
        }
    }


def create_mock_database_records():
    """Create mock database records for testing."""
    return {
        "scans": [
            {
                "scan_id": "scan-001",
                "target_url": "https://api1.example.com",
                "input_type": "file",
                "input_source": "collection1.json",
                "auth_type": "header",
                "start_time": "2024-01-01T10:00:00Z",
                "end_time": "2024-01-01T10:05:00Z",
                "status": "completed"
            },
            {
                "scan_id": "scan-002",
                "target_url": "https://api2.example.com",
                "input_type": "curl",
                "input_source": "curl commands",
                "auth_type": "token",
                "start_time": "2024-01-01T11:00:00Z",
                "end_time": "2024-01-01T11:03:00Z",
                "status": "completed"
            }
        ],
        "zap_alerts": create_sample_zap_alerts(),
        "custom_alerts": create_sample_vulnerabilities()
    }
