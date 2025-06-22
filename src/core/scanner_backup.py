#!/usr/bin/env python3
"""
API Security Scanner with OWASP API Top 10 2023 Compliance
Comprehensive API security testing and vulnerability assessment
"""

import requests
import json
import yaml
import time
import os
import re
import hashlib
import base64
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import tempfile
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import statistics
from collections import defaultdict

# Import debugging framework
try:
    from src.config.debug_config import (
        debug_logger, debug_decorator, debug_method, DebugContext,
        track_request, track_scan, track_auth, track_api,
        debug_log, info_log, error_log
    )
except ImportError:
    try:
        from config.debug_config import (
            debug_logger, debug_decorator, debug_method, DebugContext,
            track_request, track_scan, track_auth, track_api,
            debug_log, info_log, error_log
        )
    except ImportError:
        # Fallback to basic logging if debug_config is not available
        import logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)
        
        # Create dummy functions for compatibility
        def debug_logger(func):
            return func
        
        def debug_decorator(func):
            return func
        
        def debug_method(func):
            return func
        
        class DebugContext:
            def __init__(self, *args, **kwargs):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
        
        def track_request(*args, **kwargs):
            pass
        
        def track_scan(*args, **kwargs):
            pass
        
        def track_auth(*args, **kwargs):
            pass
        
        def track_api(*args, **kwargs):
            pass
        
        def debug_log(*args, **kwargs):
            logger.debug(*args)
        
        def info_log(*args, **kwargs):
            logger.info(*args)
        
        def error_log(*args, **kwargs):
            logger.error(*args)

# Import performance optimization module
try:
    from src.utils.performance_optimizer import (
        PerformanceOptimizer, create_optimized_scanner, benchmark_scanner_performance,
        ScanMetrics, ResponseCache, RateLimiter, IntelligentTestSelector
    )
except ImportError:
    try:
        from utils.performance_optimizer import (
            PerformanceOptimizer, create_optimized_scanner, benchmark_scanner_performance,
            ScanMetrics, ResponseCache, RateLimiter, IntelligentTestSelector
        )
    except ImportError:
        # Fallback to basic performance classes if module is not available
        class PerformanceOptimizer:
            def __init__(self, *args, **kwargs):
                pass
        
        def create_optimized_scanner(*args, **kwargs):
            return None
        
        def benchmark_scanner_performance(*args, **kwargs):
            return {}
        
        class ScanMetrics:
            def __init__(self):
                pass
        
        class ResponseCache:
            def __init__(self, *args, **kwargs):
                pass
        
        class RateLimiter:
            def __init__(self, *args, **kwargs):
                pass
        
        class IntelligentTestSelector:
            def __init__(self, *args, **kwargs):
                pass

# Import error handling module
try:
    from src.core.error_handler import ErrorHandler
except ImportError:
    try:
        from error_handler import ErrorHandler
    except ImportError:
        # Fallback to basic error handling if module is not available
        class ErrorHandler:
            def __init__(self):
                self.errors = []
            
            def add_error(self, error_type, message, details=None):
                self.errors.append({
                    'type': error_type,
                    'message': message,
                    'details': details,
                    'timestamp': datetime.now().isoformat()
                })
            
            def get_errors(self):
                return self.errors
            
            def clear_errors(self):
                self.errors = []

class APISecurityScanner:
    """Comprehensive API security scanner with Swagger/OpenAPI support and performance optimization"""
    
    @debug_decorator
    def __init__(self, session: requests.Session = None, auth_config: Dict[str, Any] = None, 
                 enable_optimization: bool = True, max_workers: int = 10):
        debug_log("Initializing APISecurityScanner", session=bool(session), auth_config=bool(auth_config))
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Authentication configuration
        self.auth_config = auth_config or {}
        self.apply_auth_config()
        
        # API security test configurations
        self.api_tests = self.load_api_security_tests()
        self.swagger_parsers = self.init_swagger_parsers()
        self.scan_results = {}
        
        # Performance optimization
        self.enable_optimization = enable_optimization
        if enable_optimization:
            self.performance_optimizer = create_optimized_scanner(
                max_workers=max_workers,
                max_connections=100,
                cache_size=1000,
                max_requests_per_second=10
            )
            self.scan_metrics = ScanMetrics()
        else:
            self.performance_optimizer = None
            self.scan_metrics = None
        
        debug_log("APISecurityScanner initialized successfully", optimization_enabled=enable_optimization)
    
    @debug_method
    def apply_auth_config(self):
        """Apply authentication configuration to session"""
        if not self.auth_config:
            debug_log("No auth config to apply")
            return
        
        # Apply global headers
        if 'headers' in self.auth_config:
            self.session.headers.update(self.auth_config['headers'])
            debug_log("Applied global headers", headers_count=len(self.auth_config['headers']))
        
        # Apply authentication
        auth_type = self.auth_config.get('type', '')
        debug_log("Applying auth config", auth_type=auth_type)
        
        if auth_type == 'bearer':
            token = self.auth_config.get('token', '')
            if token:
                self.session.headers['Authorization'] = f'Bearer {token}'
                debug_log("Applied Bearer token")
        
        elif auth_type == 'apikey':
            key = self.auth_config.get('key', '')
            value = self.auth_config.get('value', '')
            location = self.auth_config.get('location', 'header')
            
            if location == 'header':
                self.session.headers[key] = value
                debug_log("Applied API key in header", key=key)
            elif location == 'query':
                debug_log("API key configured for query params", key=key)
        
        elif auth_type == 'basic':
            username = self.auth_config.get('username', '')
            password = self.auth_config.get('password', '')
            if username and password:
                self.session.auth = (username, password)
                debug_log("Applied Basic auth", username=username)
        
        elif auth_type == 'oauth2':
            token = self.auth_config.get('access_token', '')
            if token:
                self.session.headers['Authorization'] = f'Bearer {token}'
                debug_log("Applied OAuth2 token")
        
        track_auth(auth_type, True, auth_type=auth_type)
    
    @debug_method
    def set_auth_config(self, auth_config: Dict[str, Any]):
        """Set authentication configuration for scanning"""
        debug_log("Setting auth config", auth_type=auth_config.get('type', 'none'))
        self.auth_config = auth_config
        self.apply_auth_config()
        info_log("Authentication configured", auth_type=auth_config.get('type', 'none'))
    
    def add_auth_header(self, key: str, value: str):
        """Add custom authentication header"""
        self.session.headers[key] = value
        print(f"✅ Added auth header: {key}")
    
    def set_bearer_token(self, token: str):
        """Set Bearer token authentication"""
        self.auth_config = {
            'type': 'bearer',
            'token': token
        }
        self.session.headers['Authorization'] = f'Bearer {token}'
        print(f"✅ Bearer token configured")
    
    def set_api_key(self, key: str, value: str, location: str = 'header'):
        """Set API key authentication"""
        self.auth_config = {
            'type': 'apikey',
            'key': key,
            'value': value,
            'location': location
        }
        if location == 'header':
            self.session.headers[key] = value
        print(f"✅ API key configured: {key} in {location}")
    
    def set_basic_auth(self, username: str, password: str):
        """Set Basic authentication"""
        self.auth_config = {
            'type': 'basic',
            'username': username,
            'password': password
        }
        self.session.auth = (username, password)
        print(f"✅ Basic auth configured: {username}")
    
    def set_oauth2_token(self, access_token: str):
        """Set OAuth2 access token"""
        self.auth_config = {
            'type': 'oauth2',
            'access_token': access_token
        }
        self.session.headers['Authorization'] = f'Bearer {access_token}'
        print(f"✅ OAuth2 token configured")
    
    def clear_auth(self):
        """Clear all authentication"""
        self.auth_config = {}
        self.session.auth = None
        # Remove common auth headers
        auth_headers = ['Authorization', 'X-API-Key', 'X-Auth-Token', 'X-Key']
        for header in auth_headers:
            if header in self.session.headers:
                del self.session.headers[header]
        print("✅ Authentication cleared")
    
    def get_auth_info(self) -> Dict[str, Any]:
        """Get current authentication information"""
        return {
            'type': self.auth_config.get('type', 'none'),
            'headers': dict(self.session.headers),
            'auth': self.session.auth,
            'config': self.auth_config
        }
    
    def generate_deep_nested_json(self, depth: int) -> dict:
        """Generate a deeply nested JSON object for testing parser/resource exhaustion."""
        result = value = {}
        for i in range(depth):
            value["level_{}".format(i)] = {}
            value = value["level_{}".format(i)]
        value["end"] = "test"
        return result
    
    def load_api_security_tests(self) -> Dict[str, Any]:
        """Load comprehensive API security test configurations including OWASP API Top 10"""
        return {
            # OWASP API Top 10 - 2023
            'api1_broken_object_property_level_authorization': {
                'name': 'API1:2023 - Broken Object Property Level Authorization',
                'description': 'Test for unauthorized access to object properties',
                'owasp_category': 'API1:2023',
                'severity': 'Critical',
                'tests': [
                    {
                        'name': 'Property Enumeration',
                        'method': 'GET',
                        'params': {'fields': 'id,name,email,password,ssn,credit_card'},
                        'json': {'fields': 'id,name,email,password,ssn,credit_card'}
                    },
                    {
                        'name': 'Mass Assignment',
                        'method': 'POST',
                        'json': {'id': 1, 'role': 'admin', 'is_admin': True, 'permissions': 'all'}
                    },
                    {
                        'name': 'Property Override',
                        'method': 'PUT',
                        'json': {'id': 1, 'owner_id': 999, 'created_by': 'attacker'}
                    },
                    {
                        'name': 'Nested Property Access',
                        'method': 'GET',
                        'params': {'include': 'user.password,user.ssn,user.credit_card'}
                    }
                ]
            },
            'api2_broken_authentication': {
                'name': 'API2:2023 - Broken Authentication',
                'description': 'Test for authentication bypass and weak authentication',
                'owasp_category': 'API2:2023',
                'severity': 'Critical',
                'tests': [
                    {
                        'name': 'No Authentication',
                        'method': 'GET',
                        'headers': {},
                        'expected_failure': True
                    },
                    {
                        'name': 'Weak JWT',
                        'method': 'GET',
                        'headers': {'Authorization': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.'},
                        'expected_failure': True
                    },
                    {
                        'name': 'JWT Algorithm Confusion',
                        'method': 'GET',
                        'headers': {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'},
                        'expected_failure': True
                    },
                    {
                        'name': 'API Key in URL',
                        'method': 'GET',
                        'params': {'api_key': 'test_key'},
                        'expected_failure': True
                    },
                    {
                        'name': 'Weak Password Policy',
                        'method': 'POST',
                        'json': {'username': 'admin', 'password': '123'},
                        'expected_failure': True
                    }
                ]
            },
            'api3_broken_object_property_level_authorization': {
                'name': 'API3:2023 - Broken Object Property Level Authorization',
                'description': 'Test for unauthorized access to object properties',
                'owasp_category': 'API3:2023',
                'severity': 'Critical',
                'tests': [
                    {
                        'name': 'IDOR in Object Access',
                        'method': 'GET',
                        'path_params': {'id': '1'},
                        'expected_failure': True
                    },
                    {
                        'name': 'IDOR in Object Update',
                        'method': 'PUT',
                        'path_params': {'id': '1'},
                        'json': {'name': 'hacked', 'email': 'hacker@evil.com'},
                        'expected_failure': True
                    },
                    {
                        'name': 'IDOR in Object Delete',
                        'method': 'DELETE',
                        'path_params': {'id': '1'},
                        'expected_failure': True
                    },
                    {
                        'name': 'Predictable Object IDs',
                        'method': 'GET',
                        'path_params': {'id': '12345'},
                        'expected_failure': True
                    }
                ]
            },
            'api4_unrestricted_resource_consumption': {
                'name': 'API4:2023 - Unrestricted Resource Consumption',
                'description': 'Test for resource exhaustion attacks',
                'owasp_category': 'API4:2023',
                'severity': 'High',
                'tests': [
                    {
                        'name': 'Large Payload',
                        'method': 'POST',
                        'headers': {'Content-Type': 'application/json'},
                        'json': {'data': 'A' * 1000000},
                        'expected_failure': True
                    },
                    {
                        'name': 'Rapid Requests',
                        'method': 'GET',
                        'count': 100,
                        'delay': 0.01,
                        'expected_failure': True
                    },
                    {
                        'name': 'Large File Upload',
                        'method': 'POST',
                        'headers': {'Content-Type': 'multipart/form-data'},
                        'files': {'file': ('large.txt', 'A' * 10000000)},
                        'expected_failure': True
                    },
                    {
                        'name': 'Deep JSON Nesting',
                        'method': 'POST',
                        'json': self.generate_deep_nested_json(20),
                        'expected_failure': True
                    }
                ]
            },
            'api5_broken_function_level_authorization': {
                'name': 'API5:2023 - Broken Function Level Authorization',
                'description': 'Test for unauthorized function access',
                'owasp_category': 'API5:2023',
                'severity': 'Critical',
                'tests': [
                    {
                        'name': 'Admin Function Access',
                        'method': 'POST',
                        'path_suffixes': ['/admin', '/manage', '/config'],
                        'json': {'action': 'delete_all_users'},
                        'expected_failure': True
                    },
                    {
                        'name': 'Privileged Function Access',
                        'method': 'POST',
                        'json': {'function': 'reset_database', 'confirm': True},
                        'expected_failure': True
                    },
                    {
                        'name': 'Role-Based Function Access',
                        'method': 'GET',
                        'path_suffixes': ['/users', '/admin/users', '/system'],
                        'expected_failure': True
                    }
                ]
            },
            'api6_unrestricted_access_to_sensitive_business_flows': {
                'name': 'API6:2023 - Unrestricted Access to Sensitive Business Flows',
                'description': 'Test for business logic bypasses',
                'owasp_category': 'API6:2023',
                'severity': 'High',
                'tests': [
                    {
                        'name': 'Purchase Flow Bypass',
                        'method': 'POST',
                        'json': {'item_id': 1, 'quantity': 1, 'skip_payment': True},
                        'expected_failure': True
                    },
                    {
                        'name': 'Registration Flow Bypass',
                        'method': 'POST',
                        'json': {'email': 'test@test.com', 'skip_verification': True},
                        'expected_failure': True
                    },
                    {
                        'name': 'Password Reset Bypass',
                        'method': 'POST',
                        'json': {'email': 'admin@company.com', 'new_password': 'hacked'},
                        'expected_failure': True
                    },
                    {
                        'name': 'Verification Bypass',
                        'method': 'POST',
                        'json': {'user_id': 1, 'verified': True, 'verification_code': 'bypass'},
                        'expected_failure': True
                    }
                ]
            },
            'api7_server_side_request_forgery': {
                'name': 'API7:2023 - Server-Side Request Forgery',
                'description': 'Test for SSRF vulnerabilities',
                'owasp_category': 'API7:2023',
                'severity': 'High',
                'tests': [
                    {
                        'name': 'Internal Network Access',
                        'method': 'GET',
                        'params': {'url': 'http://192.168.1.1'},
                        'json': {'url': 'http://192.168.1.1'},
                        'expected_failure': True
                    },
                    {
                        'name': 'Localhost Access',
                        'method': 'GET',
                        'params': {'url': 'http://localhost:8080'},
                        'json': {'url': 'http://localhost:8080'},
                        'expected_failure': True
                    },
                    {
                        'name': 'Cloud Metadata Access',
                        'method': 'GET',
                        'params': {'url': 'http://169.254.169.254/latest/meta-data/'},
                        'json': {'url': 'http://169.254.169.254/latest/meta-data/'},
                        'expected_failure': True
                    },
                    {
                        'name': 'File Protocol Access',
                        'method': 'GET',
                        'params': {'url': 'file:///etc/passwd'},
                        'json': {'url': 'file:///etc/passwd'},
                        'expected_failure': True
                    }
                ]
            },
            'api8_security_misconfiguration': {
                'name': 'API8:2023 - Security Misconfiguration',
                'description': 'Test for security configuration issues',
                'owasp_category': 'API8:2023',
                'severity': 'Medium',
                'tests': [
                    {
                        'name': 'CORS Misconfiguration',
                        'method': 'GET',
                        'headers': {'Origin': 'https://evil.com'},
                        'expected_failure': True
                    },
                    {
                        'name': 'Debug Endpoints',
                        'method': 'GET',
                        'path_suffixes': ['/debug', '/test', '/dev', '/admin'],
                        'expected_failure': True
                    },
                    {
                        'name': 'Version Information',
                        'method': 'GET',
                        'path_suffixes': ['/version', '/info', '/status', '/health'],
                        'expected_failure': True
                    },
                    {
                        'name': 'Error Information Disclosure',
                        'method': 'GET',
                        'params': {'id': 'invalid'},
                        'expected_patterns': ['stack trace', 'error details', 'exception']
                    },
                    {
                        'name': 'Default Credentials',
                        'method': 'POST',
                        'json': {'username': 'admin', 'password': 'admin'},
                        'expected_failure': True
                    }
                ]
            },
            'api9_improper_inventory_management': {
                'name': 'API9:2023 - Improper Inventory Management',
                'description': 'Test for API version and endpoint management issues',
                'owasp_category': 'API9:2023',
                'severity': 'Medium',
                'tests': [
                    {
                        'name': 'Deprecated API Version',
                        'method': 'GET',
                        'path_prefixes': ['/v1/', '/api/v1/'],
                        'expected_failure': True
                    },
                    {
                        'name': 'Beta API Access',
                        'method': 'GET',
                        'path_prefixes': ['/beta/', '/experimental/'],
                        'expected_failure': True
                    },
                    {
                        'name': 'Internal API Access',
                        'method': 'GET',
                        'path_prefixes': ['/internal/', '/private/'],
                        'expected_failure': True
                    },
                    {
                        'name': 'Shadow API Detection',
                        'method': 'GET',
                        'path_suffixes': ['/backup', '/old', '/legacy'],
                        'expected_failure': True
                    }
                ]
            },
            'api10_unsafe_consumption_of_apis': {
                'name': 'API10:2023 - Unsafe Consumption of APIs',
                'description': 'Test for unsafe API consumption patterns',
                'owasp_category': 'API10:2023',
                'severity': 'Medium',
                'tests': [
                    {
                        'name': 'Untrusted Data Processing',
                        'method': 'POST',
                        'json': {'data': '<script>alert("XSS")</script>'},
                        'expected_failure': True
                    },
                    {
                        'name': 'Unvalidated Redirect',
                        'method': 'GET',
                        'params': {'redirect': 'https://evil.com'},
                        'json': {'redirect': 'https://evil.com'},
                        'expected_failure': True
                    },
                    {
                        'name': 'Unsafe File Upload',
                        'method': 'POST',
                        'files': {'file': ('test.php', '<?php system($_GET["cmd"]); ?>')},
                        'expected_failure': True
                    },
                    {
                        'name': 'Unvalidated External API Call',
                        'method': 'POST',
                        'json': {'external_url': 'https://evil.com/api/data'},
                        'expected_failure': True
                    }
                ]
            },
            # Additional comprehensive tests
            'authentication_tests': {
                'name': 'Authentication Bypass Tests',
                'description': 'Test for authentication bypass vulnerabilities',
                'owasp_category': 'API2:2023',
                'severity': 'Critical',
                'tests': [
                    {
                        'name': 'No Authentication',
                        'method': 'GET',
                        'headers': {},
                        'expected_failure': True
                    },
                    {
                        'name': 'Null Authentication',
                        'method': 'GET',
                        'headers': {'Authorization': 'null'},
                        'expected_failure': True
                    },
                    {
                        'name': 'Empty Authentication',
                        'method': 'GET',
                        'headers': {'Authorization': ''},
                        'expected_failure': True
                    },
                    {
                        'name': 'Invalid Token',
                        'method': 'GET',
                        'headers': {'Authorization': 'Bearer invalid_token'},
                        'expected_failure': True
                    },
                    {
                        'name': 'Expired Token',
                        'method': 'GET',
                        'headers': {'Authorization': 'Bearer expired_token'},
                        'expected_failure': True
                    },
                    {
                        'name': 'Malformed JWT',
                        'method': 'GET',
                        'headers': {'Authorization': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.'},
                        'expected_failure': True
                    }
                ]
            },
            'authorization_tests': {
                'name': 'Authorization Tests',
                'description': 'Test for authorization bypass vulnerabilities',
                'owasp_category': 'API1:2023, API3:2023, API5:2023',
                'severity': 'Critical',
                'tests': [
                    {
                        'name': 'Role Manipulation',
                        'method': 'GET',
                        'headers': {'X-Role': 'admin'},
                        'params': {'role': 'admin'}
                    },
                    {
                        'name': 'User ID Manipulation',
                        'method': 'GET',
                        'params': {'user_id': '1'},
                        'path_params': {'id': '1'}
                    },
                    {
                        'name': 'Privilege Escalation',
                        'method': 'POST',
                        'headers': {'X-User-Level': 'admin'},
                        'json': {'role': 'admin', 'privileges': 'all'}
                    }
                ]
            },
            'input_validation_tests': {
                'name': 'Input Validation Tests',
                'description': 'Test for input validation vulnerabilities',
                'owasp_category': 'API10:2023',
                'severity': 'High',
                'tests': [
                    {
                        'name': 'SQL Injection',
                        'method': 'GET',
                        'params': {'id': "' OR '1'='1"},
                        'json': {'id': "' OR '1'='1"}
                    },
                    {
                        'name': 'XSS in Parameters',
                        'method': 'GET',
                        'params': {'search': '<script>alert("XSS")</script>'},
                        'json': {'search': '<script>alert("XSS")</script>'}
                    },
                    {
                        'name': 'NoSQL Injection',
                        'method': 'POST',
                        'json': {'username': {'$ne': ''}, 'password': {'$ne': ''}}
                    },
                    {
                        'name': 'Command Injection',
                        'method': 'POST',
                        'json': {'command': '; ls -la'},
                        'params': {'cmd': '; ls -la'}
                    },
                    {
                        'name': 'Path Traversal',
                        'method': 'GET',
                        'params': {'file': '../../../etc/passwd'},
                        'path_params': {'filename': '../../../etc/passwd'}
                    },
                    {
                        'name': 'Template Injection',
                        'method': 'POST',
                        'json': {'template': '{{7*7}}'},
                        'params': {'template': '{{7*7}}'}
                    }
                ]
            },
            'rate_limiting_tests': {
                'name': 'Rate Limiting Tests',
                'description': 'Test for rate limiting bypasses',
                'owasp_category': 'API4:2023',
                'severity': 'Medium',
                'tests': [
                    {
                        'name': 'Rapid Requests',
                        'method': 'GET',
                        'count': 20,
                        'delay': 0.1
                    },
                    {
                        'name': 'Header Manipulation',
                        'method': 'GET',
                        'headers': {
                            'X-Forwarded-For': '127.0.0.1',
                            'X-Real-IP': '127.0.0.1',
                            'X-Originating-IP': '127.0.0.1'
                        }
                    },
                    {
                        'name': 'IP Spoofing',
                        'method': 'GET',
                        'headers': {'X-Forwarded-For': '192.168.1.1'}
                    }
                ]
            },
            'injection_tests': {
                'name': 'Injection Tests',
                'description': 'Test for various injection vulnerabilities',
                'owasp_category': 'API10:2023',
                'severity': 'High',
                'tests': [
                    {
                        'name': 'XML Injection',
                        'method': 'POST',
                        'headers': {'Content-Type': 'application/xml'},
                        'data': '<?xml version="1.0"?><root><user>admin</user></root>'
                    },
                    {
                        'name': 'JSON Injection',
                        'method': 'POST',
                        'headers': {'Content-Type': 'application/json'},
                        'json': {'user': 'admin", "role": "admin'}
                    },
                    {
                        'name': 'Header Injection',
                        'method': 'GET',
                        'headers': {
                            'X-Custom-Header': 'admin',
                            'X-User': 'admin',
                            'X-Role': 'admin'
                        }
                    }
                ]
            },
            'information_disclosure_tests': {
                'name': 'Information Disclosure Tests',
                'description': 'Test for information disclosure vulnerabilities',
                'owasp_category': 'API8:2023',
                'severity': 'Medium',
                'tests': [
                    {
                        'name': 'Error Messages',
                        'method': 'GET',
                        'params': {'id': 'invalid_id'},
                        'expected_patterns': ['error', 'exception', 'stack trace']
                    },
                    {
                        'name': 'Debug Endpoints',
                        'method': 'GET',
                        'path_suffixes': ['/debug', '/test', '/dev', '/admin']
                    },
                    {
                        'name': 'Version Information',
                        'method': 'GET',
                        'path_suffixes': ['/version', '/info', '/status', '/health']
                    }
                ]
            },
            'business_logic_tests': {
                'name': 'Business Logic Tests',
                'description': 'Test for business logic vulnerabilities',
                'owasp_category': 'API6:2023',
                'severity': 'High',
                'tests': [
                    {
                        'name': 'Price Manipulation',
                        'method': 'POST',
                        'json': {'price': -100, 'quantity': 1}
                    },
                    {
                        'name': 'Quantity Manipulation',
                        'method': 'POST',
                        'json': {'quantity': 999999, 'price': 0.01}
                    },
                    {
                        'name': 'Discount Abuse',
                        'method': 'POST',
                        'json': {'discount': 100, 'coupon': 'FREE'}
                    },
                    {
                        'name': 'Race Condition',
                        'method': 'POST',
                        'json': {'action': 'withdraw', 'amount': 100},
                        'concurrent_requests': 5
                    }
                ]
            }
        }
    
    def init_swagger_parsers(self) -> Dict[str, Any]:
        """Initialize Swagger/OpenAPI parsers"""
        return {
            'swagger_2_0': self.parse_swagger_2_0,
            'openapi_3_0': self.parse_openapi_3_0,
            'openapi_3_1': self.parse_openapi_3_1
        }
    
    @debug_method
    def scan_from_swagger_url(self, swagger_url: str, base_url: str = None, auth_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Scan API from Swagger/OpenAPI URL"""
        scan_id = f"swagger_scan_{int(time.time())}"
        track_scan(scan_id, "swagger_url", "started", url=swagger_url)
        
        with DebugContext("swagger_url_scan", url=swagger_url, base_url=base_url):
            try:
                debug_log("Starting Swagger URL scan", url=swagger_url, base_url=base_url)
                
                # Set authentication if provided
                if auth_config:
                    self.set_auth_config(auth_config)
                
                # Fetch Swagger specification
                start_time = time.time()
                response = self.session.get(swagger_url, timeout=30)
                duration = time.time() - start_time
                
                track_request("GET", swagger_url, response.status_code, duration)
                
                if response.status_code != 200:
                    error_msg = f"Failed to fetch Swagger spec: {response.status_code}"
                    track_scan(scan_id, "swagger_url", "failed", error=error_msg)
                    return {'error': error_msg}
                
                # Parse specification
                try:
                    spec = response.json()
                except json.JSONDecodeError:
                    error_msg = "Invalid JSON in Swagger specification"
                    track_scan(scan_id, "swagger_url", "failed", error=error_msg)
                    return {'error': error_msg}
                
                # Extract base URL if not provided
                if not base_url:
                    base_url = self.extract_base_url(spec, swagger_url)
                
                # Parse endpoints
                endpoints = self.parse_swagger_spec(spec, base_url)
                debug_log("Parsed endpoints", endpoint_count=len(endpoints))
                
                # Scan endpoints
                scan_results = self.scan_api_endpoints(endpoints)
                scan_results['scan_type'] = 'swagger_url'
                scan_results['source_url'] = swagger_url
                scan_results['base_url'] = base_url
                scan_results['endpoints_found'] = len(endpoints)
                
                track_scan(scan_id, "swagger_url", "completed", 
                          endpoint_count=len(endpoints), 
                          vulnerability_count=len(scan_results.get('vulnerabilities', [])))
                
                error_handler = ErrorHandler()
                scan_results['error_summary'] = error_handler.get_error_summary()
                return scan_results
                
            except Exception as e:
                error_log("Error in Swagger URL scan", exception=e, url=swagger_url)
                track_scan(scan_id, "swagger_url", "failed", error=str(e))
                return {'error': str(e)}
    
    @debug_method
    def scan_from_json_file(self, json_file_path: str, base_url: str, auth_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Scan API from JSON specification file"""
        scan_id = f"json_scan_{int(time.time())}"
        track_scan(scan_id, "json_file", "started", file=json_file_path)
        
        with DebugContext("json_file_scan", file=json_file_path, base_url=base_url):
            try:
                debug_log("Starting JSON file scan", file=json_file_path, base_url=base_url)
                
                # Set authentication if provided
                if auth_config:
                    self.set_auth_config(auth_config)
                
                # Read JSON file
                if not os.path.exists(json_file_path):
                    error_msg = f"JSON file not found: {json_file_path}"
                    track_scan(scan_id, "json_file", "failed", error=error_msg)
                    return {'error': error_msg}
                
                with open(json_file_path, 'r', encoding='utf-8') as f:
                    spec = json.load(f)
                
                # Detect if this is a Swagger/OpenAPI spec or a collection
                is_swagger_spec = (
                    'openapi' in spec or 
                    'swagger' in spec or 
                    'paths' in spec
                )
                
                debug_log("JSON file analysis", 
                         has_openapi='openapi' in spec,
                         has_swagger='swagger' in spec,
                         has_paths='paths' in spec,
                         is_swagger_spec=is_swagger_spec,
                         top_level_keys=list(spec.keys()))
                
                if is_swagger_spec:
                    # Parse as Swagger/OpenAPI specification
                    debug_log("Detected Swagger/OpenAPI specification")
                    endpoints = self.parse_swagger_spec(spec, base_url)
                else:
                    # Parse as API collection
                    debug_log("Detected API collection")
                    format_type = self.detect_collection_format(spec)
                    endpoints = self.parse_api_collection(spec, format_type, base_url)
                
                debug_log("Parsed endpoints", endpoint_count=len(endpoints))
                
                # Scan endpoints
                scan_results = self.scan_api_endpoints(endpoints)
                scan_results['scan_type'] = 'json_file'
                scan_results['source_file'] = json_file_path
                scan_results['base_url'] = base_url
                scan_results['endpoints_found'] = len(endpoints)
                
                track_scan(scan_id, "json_file", "completed", 
                          endpoint_count=len(endpoints), 
                          vulnerability_count=len(scan_results.get('vulnerabilities', [])))
                
                error_handler = ErrorHandler()
                scan_results['error_summary'] = error_handler.get_error_summary()
                return scan_results
                
            except Exception as e:
                error_log("Error in JSON file scan", exception=e, file=json_file_path)
                track_scan(scan_id, "json_file", "failed", error=str(e))
                return {'error': str(e)}
    
    @debug_method
    def upload_and_scan_collection(self, file_path: str, base_url: str = None, auth_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Upload and scan API collection file"""
        scan_id = f"collection_scan_{int(time.time())}"
        track_scan(scan_id, "collection", "started", file=file_path)
        
        with DebugContext("collection_scan", file=file_path, base_url=base_url):
            try:
                debug_log("Starting collection scan", file=file_path, base_url=base_url)
                
                # Set authentication if provided
                if auth_config:
                    self.set_auth_config(auth_config)
                
                # Read collection file
                if not os.path.exists(file_path):
                    error_msg = f"Collection file not found: {file_path}"
                    track_scan(scan_id, "collection", "failed", error=error_msg)
                    return {'error': error_msg}
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    if file_path.endswith('.json'):
                        collection_data = json.load(f)
                    elif file_path.endswith('.yaml') or file_path.endswith('.yml'):
                        collection_data = yaml.safe_load(f)
                    else:
                        error_msg = f"Unsupported file format: {file_path}"
                        track_scan(scan_id, "collection", "failed", error=error_msg)
                        return {'error': error_msg}
                
                # Detect collection format
                format_type = self.detect_collection_format(collection_data)
                debug_log("Detected collection format", format=format_type)
                
                # Parse collection
                endpoints = self.parse_api_collection(collection_data, format_type, base_url)
                debug_log("Parsed collection endpoints", endpoint_count=len(endpoints))
                
                # Scan endpoints
                scan_results = self.scan_api_endpoints(endpoints)
                scan_results['scan_type'] = 'collection'
                scan_results['source_file'] = file_path
                scan_results['collection_format'] = format_type
                scan_results['base_url'] = base_url
                scan_results['endpoints_found'] = len(endpoints)
                
                track_scan(scan_id, "collection", "completed", 
                          endpoint_count=len(endpoints), 
                          format=format_type,
                          vulnerability_count=len(scan_results.get('vulnerabilities', [])))
                
                error_handler = ErrorHandler()
                scan_results['error_summary'] = error_handler.get_error_summary()
                return scan_results
                
            except Exception as e:
                error_log("Error in collection scan", exception=e, file=file_path)
                track_scan(scan_id, "collection", "failed", error=str(e))
                return {'error': str(e)}
    
    @debug_method
    def scan_api_endpoints(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan multiple API endpoints for security vulnerabilities"""
        debug_log("Starting API endpoints scan", endpoint_count=len(endpoints))
        
        if not endpoints:
            debug_log("No endpoints provided for scanning!")
            return {
                'scan_timestamp': datetime.now().isoformat(),
                'total_endpoints': 0,
                'scanned_endpoints': 0,
                'vulnerabilities': [],
                'test_results': {},
                'summary': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                },
                'error': 'No endpoints found to scan'
            }
        
        scan_results = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_endpoints': len(endpoints),
            'scanned_endpoints': 0,
            'vulnerabilities': [],
            'test_results': {},
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'status': 'in_progress'
        }
        
        # Track unique tests to avoid duplicates
        executed_tests = set()
        
        for i, endpoint in enumerate(endpoints):
            debug_log(f"Scanning endpoint {i+1}/{len(endpoints)}", 
                     method=endpoint.get('method'), 
                     path=endpoint.get('path'),
                     base_url=endpoint.get('base_url'))
            
            try:
                endpoint_result = self.scan_single_endpoint(endpoint, executed_tests)
                scan_results['scanned_endpoints'] += 1
                
                if endpoint_result.get('vulnerabilities'):
                    scan_results['vulnerabilities'].extend(endpoint_result['vulnerabilities'])
                
                # Update summary
                for vuln in endpoint_result.get('vulnerabilities', []):
                    severity = vuln.get('severity', 'info').lower()
                    if severity in scan_results['summary']:
                        scan_results['summary'][severity] += 1
                
            except Exception as e:
                error_log(f"Error scanning endpoint {endpoint.get('path')}", exception=e)
                continue
        
        # Mark scan as completed
        scan_results['status'] = 'completed'
        
        debug_log("API endpoints scan completed", 
                 scanned=scan_results['scanned_endpoints'],
                 vulnerabilities=len(scan_results['vulnerabilities']))
        
        return scan_results

    @debug_method
    def scan_single_endpoint(self, endpoint: Dict[str, Any], executed_tests: set = None) -> Dict[str, Any]:
        """Scan a single API endpoint for security vulnerabilities"""
        debug_log("Starting single endpoint scan", 
                 method=endpoint.get('method'), 
                 path=endpoint.get('path'))
        
        if executed_tests is None:
            executed_tests = set()
        
        result = {
            'endpoint': endpoint,
            'vulnerabilities': [],
            'test_results': {},
            'connectivity': False,
            'error': None
        }
        
        # Build full URL
        base_url = endpoint.get('base_url', '')
        path = endpoint.get('path', '')
        method = endpoint.get('method', 'GET').upper()
        
        if not base_url or not path:
            result['error'] = 'Missing base_url or path'
            debug_log("Missing URL components", base_url=base_url, path=path)
            return result
        
        # Handle different URL formats
        if path.startswith('http'):
            full_url = path
        else:
            # Remove leading slash if base_url ends with one
            if base_url.endswith('/') and path.startswith('/'):
                path = path[1:]
            full_url = urljoin(base_url, path)
        
        debug_log("Testing connectivity", full_url=full_url, method=method)
        
        # First, test basic connectivity
        try:
            # Test with HEAD request first (faster)
            head_response = self.session.head(full_url, timeout=10, allow_redirects=False)
            result['connectivity'] = True
            debug_log("HEAD request successful", status_code=head_response.status_code)
        except requests.exceptions.RequestException as e:
            debug_log("HEAD request failed, trying GET", error=str(e))
            try:
                # Try GET request as fallback
                get_response = self.session.get(full_url, timeout=10, allow_redirects=False)
                result['connectivity'] = True
                debug_log("GET request successful", status_code=get_response.status_code)
            except requests.exceptions.RequestException as e2:
                result['error'] = f'Endpoint not accessible: {str(e2)}'
                debug_log("Endpoint not accessible", error=str(e2))
                return result
        
        # Now perform security tests with deduplication
        debug_log("Starting security tests", test_count=len(self.api_tests))
        
        if not self.api_tests:
            debug_log("No security tests configured!")
            result['error'] = 'No security tests configured'
            return result
        
        for test_category, test_config in self.api_tests.items():
            debug_log(f"Testing category: {test_category}")
            
            try:
                test_result = self._run_security_test(full_url, method, test_category, test_config, executed_tests)
                if test_result:
                    result['test_results'][test_category] = test_result
                    
                    # Check for vulnerabilities in test results
                    if test_result.get('vulnerabilities'):
                        result['vulnerabilities'].extend(test_result['vulnerabilities'])
                        
            except Exception as e:
                error_log(f"Error in test category {test_category}", exception=e)
                continue
        
        debug_log("Single endpoint scan completed", 
                 vulnerabilities=len(result['vulnerabilities']),
                 test_categories=len(result['test_results']))
        
        return result

    @debug_method
    def _run_security_test(self, url: str, method: str, test_category: str, test_config: Dict[str, Any], executed_tests: set) -> Dict[str, Any]:
        """Run a specific security test category against an endpoint with deduplication"""
        debug_log(f"Running security test", category=test_category, url=url, method=method)
        
        test_result = {
            'category': test_category,
            'name': test_config.get('name', test_category),
            'description': test_config.get('description', ''),
            'severity': test_config.get('severity', 'medium'),
            'tests_run': 0,
            'tests_skipped': 0,
            'vulnerabilities': [],
            'responses': []
        }
        
        tests = test_config.get('tests', [])
        debug_log(f"Found {len(tests)} tests for category {test_category}")
        
        for test in tests:
            # Create a unique test identifier to avoid duplicates
            test_id = self._create_test_id(url, method, test)
            
            if test_id in executed_tests:
                test_result['tests_skipped'] += 1
                debug_log(f"Skipping duplicate test", test_name=test.get('name', 'Unknown'), test_id=test_id)
                continue
            
            executed_tests.add(test_id)
            test_result['tests_run'] += 1
            debug_log(f"Running test {test_result['tests_run']}/{len(tests)}", test_name=test.get('name', 'Unknown'))
            
            try:
                test_response = self._execute_single_test(url, method, test)
                test_result['responses'].append(test_response)
                
                # Analyze response for vulnerabilities
                vulnerabilities = self._analyze_response_for_vulnerabilities(test_response, test_category, test)
                if vulnerabilities:
                    test_result['vulnerabilities'].extend(vulnerabilities)
                    
            except Exception as e:
                error_log(f"Error in test {test.get('name', 'Unknown')}", exception=e)
                continue
        
        debug_log(f"Security test completed", 
                 category=test_category, 
                 tests_run=test_result['tests_run'],
                 tests_skipped=test_result['tests_skipped'],
                 vulnerabilities=len(test_result['vulnerabilities']))
        
        return test_result

    def _create_test_id(self, url: str, method: str, test: Dict[str, Any]) -> str:
        """Create a unique identifier for a test to avoid duplicates"""
        # Create a hash based on URL, method, and test parameters
        test_params = {
            'url': url,
            'method': method,
            'headers': test.get('headers', {}),
            'params': test.get('params', {}),
            'json': test.get('json', {}),
            'data': test.get('data', ''),
            'name': test.get('name', '')
        }
        
        # Convert to a consistent string representation
        import hashlib
        test_str = json.dumps(test_params, sort_keys=True)
        return hashlib.md5(test_str.encode()).hexdigest()

    @debug_method
    def _execute_single_test(self, url: str, method: str, test: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single security test"""
        test_name = test.get('name', 'Unknown')
        debug_log(f"Executing test", test_name=test_name, url=url, method=method)
        
        # Prepare request data
        headers = {}
        params = {}
        json_data = None
        data = None
        
        # Add test-specific headers
        if 'headers' in test:
            headers.update(test['headers'])
        
        # Add test-specific parameters
        if 'params' in test:
            params.update(test['params'])
        
        # Add test-specific JSON data
        if 'json' in test:
            json_data = test['json']
        
        # Add test-specific form data
        if 'data' in test:
            data = test['data']
        
        # Execute request
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json_data,
                data=data,
                timeout=15,
                allow_redirects=False
            )
            
            debug_log(f"Test response received", 
                     test_name=test_name, 
                     status_code=response.status_code,
                     response_size=len(response.content))
            
            return {
                'test_name': test_name,
                'request': {
                    'method': method,
                    'url': url,
                    'headers': dict(headers),
                    'params': params,
                    'json': json_data,
                    'data': data
                },
                'response': {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'content': response.text[:10000],  # Limit content size
                    'content_length': len(response.content),
                    'response_time': response.elapsed.total_seconds()
                },
                'timestamp': datetime.now().isoformat()
            }
            
        except requests.exceptions.RequestException as e:
            debug_log(f"Test request failed", test_name=test_name, error=str(e))
            return {
                'test_name': test_name,
                'request': {
                    'method': method,
                    'url': url,
                    'headers': dict(headers),
                    'params': params,
                    'json': json_data,
                    'data': data
                },
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    @debug_method
    def _analyze_response_for_vulnerabilities(self, test_response: Dict[str, Any], test_category: str, test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze test response for potential vulnerabilities"""
        vulnerabilities = []
        
        if 'error' in test_response:
            # Connection error - might indicate network issues
            vulnerabilities.append({
                'type': 'connectivity_error',
                'severity': 'info',
                'description': f'Connection failed: {test_response["error"]}',
                'test_name': test_response.get('test_name', 'Unknown'),
                'category': test_category
            })
            return vulnerabilities
        
        response = test_response.get('response', {})
        status_code = response.get('status_code', 0)
        content = response.get('content', '')
        headers = response.get('headers', {})
        
        # Analyze based on test category
        if 'injection' in test_category.lower():
            vulnerabilities.extend(self._check_injection_vulnerabilities(test_response, test_category, test))
        
        elif 'authentication' in test_category.lower():
            vulnerabilities.extend(self._check_auth_vulnerabilities(test_response, test_category, test))
        
        elif 'authorization' in test_category.lower():
            vulnerabilities.extend(self._check_authz_vulnerabilities(test_response, test_category, test))
        
        elif 'information_disclosure' in test_category.lower():
            vulnerabilities.extend(self._check_info_disclosure_vulnerabilities(test_response, test_category, test))
        
        elif 'rate_limiting' in test_category.lower():
            vulnerabilities.extend(self._check_rate_limiting_vulnerabilities(test_response, test_category, test))
        
        # Generic vulnerability checks
        vulnerabilities.extend(self._check_generic_vulnerabilities(test_response, test_category, test))
        
        return vulnerabilities

    def _check_injection_vulnerabilities(self, test_response: Dict[str, Any], test_category: str, test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for injection vulnerabilities"""
        vulnerabilities = []
        response = test_response.get('response', {})
        content = response.get('content', '').lower()
        
        # SQL Injection indicators
        sql_errors = [
            'sql syntax', 'mysql error', 'oracle error', 'postgresql error',
            'sqlite error', 'microsoft ole db provider', 'unclosed quotation mark',
            'syntax error or access violation', 'mysql_fetch_array', 'mysql_num_rows'
        ]
        
        for error in sql_errors:
            if error in content:
                vulnerabilities.append({
                    'type': 'sql_injection',
                    'severity': 'critical',
                    'description': f'Potential SQL injection detected: {error}',
                    'test_name': test_response.get('test_name', 'Unknown'),
                    'category': test_category,
                    'evidence': error
                })
                break
        
        # XSS indicators
        xss_indicators = [
            '<script>', 'javascript:', 'onerror=', 'onload=', 'onclick=',
            'alert(', 'confirm(', 'prompt(', 'eval('
        ]
        
        for indicator in xss_indicators:
            if indicator in content:
                vulnerabilities.append({
                    'type': 'xss',
                    'severity': 'high',
                    'description': f'Potential XSS detected: {indicator}',
                    'test_name': test_response.get('test_name', 'Unknown'),
                    'category': test_category,
                    'evidence': indicator
                })
                break
        
        return vulnerabilities

    def _check_auth_vulnerabilities(self, test_response: Dict[str, Any], test_category: str, test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for authentication vulnerabilities"""
        vulnerabilities = []
        response = test_response.get('response', {})
        status_code = response.get('status_code', 0)
        
        # Check if authentication bypass is possible
        if status_code == 200 and 'auth' in test_category.lower():
            vulnerabilities.append({
                'type': 'auth_bypass',
                'severity': 'critical',
                'description': 'Authentication bypass possible - endpoint accessible without proper auth',
                'test_name': test_response.get('test_name', 'Unknown'),
                'category': test_category,
                'evidence': f'Status code: {status_code}'
            })
        
        return vulnerabilities

    def _check_authz_vulnerabilities(self, test_response: Dict[str, Any], test_category: str, test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for authorization vulnerabilities"""
        vulnerabilities = []
        response = test_response.get('response', {})
        status_code = response.get('status_code', 0)
        
        # Check if authorization bypass is possible
        if status_code == 200 and 'authz' in test_category.lower():
            vulnerabilities.append({
                'type': 'authz_bypass',
                'severity': 'high',
                'description': 'Authorization bypass possible - endpoint accessible without proper permissions',
                'test_name': test_response.get('test_name', 'Unknown'),
                'category': test_category,
                'evidence': f'Status code: {status_code}'
            })
        
        return vulnerabilities

    def _check_info_disclosure_vulnerabilities(self, test_response: Dict[str, Any], test_category: str, test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for information disclosure vulnerabilities"""
        vulnerabilities = []
        response = test_response.get('response', {})
        content = response.get('content', '')
        headers = response.get('headers', {})
        
        # Check for sensitive information in response
        sensitive_patterns = [
            r'password["\']?\s*[:=]\s*["\']?[^"\']+["\']?',
            r'api_key["\']?\s*[:=]\s*["\']?[^"\']+["\']?',
            r'token["\']?\s*[:=]\s*["\']?[^"\']+["\']?',
            r'secret["\']?\s*[:=]\s*["\']?[^"\']+["\']?',
            r'private_key["\']?\s*[:=]\s*["\']?[^"\']+["\']?'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'information_disclosure',
                    'severity': 'high',
                    'description': 'Sensitive information disclosed in response',
                    'test_name': test_response.get('test_name', 'Unknown'),
                    'category': test_category,
                    'evidence': f'Pattern matched: {pattern}'
                })
                break
        
        # Check for verbose error messages
        if any(keyword in content.lower() for keyword in ['stack trace', 'exception', 'error details', 'debug info']):
            vulnerabilities.append({
                'type': 'verbose_errors',
                'severity': 'medium',
                'description': 'Verbose error messages may disclose sensitive information',
                'test_name': test_response.get('test_name', 'Unknown'),
                'category': test_category,
                'evidence': 'Verbose error messages detected'
            })
        
        return vulnerabilities

    def _check_rate_limiting_vulnerabilities(self, test_response: Dict[str, Any], test_category: str, test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for rate limiting vulnerabilities"""
        vulnerabilities = []
        response = test_response.get('response', {})
        status_code = response.get('status_code', 0)
        
        # If we get a 200 response for rate limiting tests, it might indicate no rate limiting
        if status_code == 200 and 'rate' in test_category.lower():
            vulnerabilities.append({
                'type': 'no_rate_limiting',
                'severity': 'medium',
                'description': 'No rate limiting detected on endpoint',
                'test_name': test_response.get('test_name', 'Unknown'),
                'category': test_category,
                'evidence': f'Status code: {status_code}'
            })
        
        return vulnerabilities

    def _check_generic_vulnerabilities(self, test_response: Dict[str, Any], test_category: str, test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for generic vulnerabilities"""
        vulnerabilities = []
        response = test_response.get('response', {})
        status_code = response.get('status_code', 0)
        headers = response.get('headers', {})
        
        # Check for missing security headers
        security_headers = {
            'X-Frame-Options': 'Missing clickjacking protection',
            'X-Content-Type-Options': 'Missing MIME type protection',
            'X-XSS-Protection': 'Missing XSS protection header',
            'Strict-Transport-Security': 'Missing HSTS header',
            'Content-Security-Policy': 'Missing CSP header'
        }
        
        for header, description in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    'type': 'missing_security_header',
                    'severity': 'low',
                    'description': description,
                    'test_name': test_response.get('test_name', 'Unknown'),
                    'category': test_category,
                    'evidence': f'Missing header: {header}'
                })
        
        # Check for server information disclosure
        server_header = headers.get('Server', '')
        if server_header and len(server_header) > 0:
            vulnerabilities.append({
                'type': 'server_info_disclosure',
                'severity': 'low',
                'description': 'Server information disclosed in headers',
                'test_name': test_response.get('test_name', 'Unknown'),
                'category': test_category,
                'evidence': f'Server header: {server_header}'
            })
        
        return vulnerabilities

    def parse_swagger_2_0(self, spec: dict, base_url: str = None) -> list:
        """Parse Swagger 2.0 (OpenAPI 2.0) spec and extract endpoints."""
        endpoints = []
        paths = spec.get('paths', {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                    endpoint = {
                        'method': method.upper(),
                        'path': path,
                        'summary': details.get('summary', ''),
                        'description': details.get('description', ''),
                        'parameters': details.get('parameters', []),
                        'base_url': base_url
                    }
                    endpoints.append(endpoint)
        return endpoints

    def parse_openapi_3_0(self, spec: dict, base_url: str = None) -> list:
        """Parse OpenAPI 3.0 spec and extract endpoints."""
        endpoints = []
        paths = spec.get('paths', {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                    endpoint = {
                        'method': method.upper(),
                        'path': path,
                        'summary': details.get('summary', ''),
                        'description': details.get('description', ''),
                        'parameters': details.get('parameters', []),
                        'base_url': base_url
                    }
                    endpoints.append(endpoint)
        return endpoints

    def parse_openapi_3_1(self, spec: dict, base_url: str = None) -> list:
        """Parse OpenAPI 3.1 spec and extract endpoints."""
        endpoints = []
        paths = spec.get('paths', {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                    endpoint = {
                        'method': method.upper(),
                        'path': path,
                        'summary': details.get('summary', ''),
                        'description': details.get('description', ''),
                        'parameters': details.get('parameters', []),
                        'base_url': base_url
                    }
                    endpoints.append(endpoint)
        return endpoints

    def parse_swagger_spec(self, spec: dict, base_url: str = None) -> list:
        """Parse Swagger/OpenAPI specification and extract endpoints"""
        # Determine OpenAPI version
        openapi_version = spec.get('openapi', '')
        swagger_version = spec.get('swagger', '')
        
        if openapi_version.startswith('3.1'):
            return self.parse_openapi_3_1(spec, base_url)
        elif openapi_version.startswith('3.0'):
            return self.parse_openapi_3_0(spec, base_url)
        elif swagger_version.startswith('2.0'):
            return self.parse_swagger_2_0(spec, base_url)
        else:
            # Default to OpenAPI 3.0 parser
            return self.parse_openapi_3_0(spec, base_url)

    def extract_base_url(self, spec: dict, swagger_url: str = None) -> str:
        """Extract base URL from Swagger/OpenAPI specification"""
        # Try to get from servers (OpenAPI 3.x)
        servers = spec.get('servers', [])
        if servers:
            return servers[0].get('url', '')
        
        # Try to get from host and schemes (Swagger 2.0)
        host = spec.get('host', '')
        schemes = spec.get('schemes', ['https'])
        if host:
            scheme = schemes[0] if schemes else 'https'
            return f"{scheme}://{host}"
        
        # Try to extract from swagger_url
        if swagger_url:
            parsed = urlparse(swagger_url)
            return f"{parsed.scheme}://{parsed.netloc}"
        
        return ''

    def detect_collection_format(self, collection_data: dict) -> str:
        """Detect the format of API collection"""
        debug_log("Detecting collection format", keys=list(collection_data.keys()))
        
        if 'info' in collection_data and 'item' in collection_data:
            debug_log("Detected Postman collection format")
            return 'postman'
        elif 'requests' in collection_data:
            debug_log("Detected Insomnia collection format")
            return 'insomnia'
        elif 'log' in collection_data:
            debug_log("Detected HAR format")
            return 'har'
        elif 'curl' in str(collection_data).lower():
            debug_log("Detected curl commands format")
            return 'curl'
        else:
            debug_log("Using generic format")
            return 'generic'

    def parse_api_collection(self, collection_data: dict, format_type: str, base_url: str = None) -> list:
        """Parse API collection and extract endpoints"""
        endpoints = []
        debug_log("Starting collection parsing", format=format_type, base_url=base_url)
        
        if format_type == 'postman':
            # Parse Postman collection
            debug_log("Parsing Postman collection")
            items = collection_data.get('item', [])
            debug_log("Found items in collection", item_count=len(items))
            
            for i, item in enumerate(items):
                debug_log(f"Processing item {i+1}/{len(items)}", item_name=item.get('name', 'Unknown'))
                
                if 'item' in item:  # Folder
                    debug_log("Found folder, recursing", folder_name=item.get('name'))
                    sub_endpoints = self.parse_api_collection(item, format_type, base_url)
                    endpoints.extend(sub_endpoints)
                    debug_log("Added sub-endpoints from folder", count=len(sub_endpoints))
                else:  # Request
                    debug_log("Found request", request_name=item.get('name'))
                    request = item.get('request', {})
                    method = request.get('method', 'GET')
                    url = request.get('url', {})
                    
                    if isinstance(url, dict):
                        path = url.get('raw', '')
                        debug_log("URL is dict", raw_url=path)
                    else:
                        path = url
                        debug_log("URL is string", url=path)
                    
                    if path:  # Only add if we have a valid path
                        endpoint = {
                            'method': method.upper(),
                            'path': path,
                            'summary': item.get('name', ''),
                            'description': request.get('description', ''),
                            'base_url': base_url
                        }
                        endpoints.append(endpoint)
                        debug_log("Added endpoint", method=method.upper(), path=path)
                    else:
                        debug_log("Skipping endpoint - no valid path")
        
        elif format_type == 'insomnia':
            # Parse Insomnia collection
            debug_log("Parsing Insomnia collection")
            requests = collection_data.get('requests', [])
            for req in requests:
                endpoints.append({
                    'method': req.get('method', 'GET').upper(),
                    'path': req.get('url', ''),
                    'summary': req.get('name', ''),
                    'description': req.get('description', ''),
                    'base_url': base_url
                })
        
        elif format_type == 'har':
            # Parse HAR file
            debug_log("Parsing HAR file")
            entries = collection_data.get('log', {}).get('entries', [])
            for entry in entries:
                request = entry.get('request', {})
                endpoints.append({
                    'method': request.get('method', 'GET').upper(),
                    'path': request.get('url', ''),
                    'summary': f"HAR Entry - {request.get('method', 'GET')}",
                    'description': '',
                    'base_url': base_url
                })
        
        else:
            # Generic parsing
            debug_log("Using generic parsing")
            if isinstance(collection_data, list):
                for item in collection_data:
                    if isinstance(item, dict):
                        endpoints.append({
                            'method': item.get('method', 'GET').upper(),
                            'path': item.get('url', item.get('path', '')),
                            'summary': item.get('name', item.get('summary', '')),
                            'description': item.get('description', ''),
                            'base_url': base_url
                        })
        
        debug_log("Collection parsing completed", total_endpoints=len(endpoints))
        return endpoints

    def generate_api_security_report(self, scan_results: Dict[str, Any], format: str = 'json') -> str:
        """Generate API security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == 'json':
            filename = f"api_security_report_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(scan_results, f, indent=2)
        else:
            filename = f"api_security_report_{timestamp}.html"
            # Simple HTML report
            html_content = f"""
            <html>
            <head><title>API Security Report</title></head>
            <body>
                <h1>API Security Scan Report</h1>
                <p>Scan completed at: {datetime.now().isoformat()}</p>
                <p>Total vulnerabilities: {len(scan_results.get('vulnerabilities', []))}</p>
                <pre>{json.dumps(scan_results, indent=2)}</pre>
            </body>
            </html>
            """
            with open(filename, 'w') as f:
                f.write(html_content)
        
        return filename

    def generate_owasp_report(self, scan_results: Dict[str, Any], format: str = 'html') -> str:
        """Generate OWASP API Top 10 report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == 'json':
            filename = f"owasp_api_report_{timestamp}.json"
            owasp_results = {
                'owasp_api_top_10_2023': {
                    'scan_timestamp': datetime.now().isoformat(),
                    'vulnerabilities': scan_results.get('vulnerabilities', []),
                    'summary': scan_results.get('summary', {})
                }
            }
            with open(filename, 'w') as f:
                json.dump(owasp_results, f, indent=2)
        else:
            filename = f"owasp_api_report_{timestamp}.html"
            # OWASP HTML report
            html_content = f"""
            <html>
            <head><title>OWASP API Top 10 2023 Report</title></head>
            <body>
                <h1>OWASP API Top 10 2023 Security Report</h1>
                <p>Scan completed at: {datetime.now().isoformat()}</p>
                <p>Total vulnerabilities: {len(scan_results.get('vulnerabilities', []))}</p>
                <h2>Vulnerabilities Found</h2>
                <pre>{json.dumps(scan_results.get('vulnerabilities', []), indent=2)}</pre>
            </body>
            </html>
            """
            with open(filename, 'w') as f:
                f.write(html_content)
        
        return filename

    @debug_method
    def scan_api_endpoints_optimized(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan multiple API endpoints with performance optimization"""
        if not self.enable_optimization or not self.performance_optimizer:
            debug_log("Performance optimization disabled, using standard scan")
            return self.scan_api_endpoints(endpoints)
        
        debug_log("Starting optimized API endpoints scan", endpoint_count=len(endpoints))
        
        # Prepare endpoints for optimization
        optimized_endpoints = []
        for endpoint in endpoints:
            # Build full URL
            base_url = endpoint.get('base_url', '')
            path = endpoint.get('path', '')
            
            if path.startswith('http'):
                full_url = path
            else:
                if base_url.endswith('/') and path.startswith('/'):
                    path = path[1:]
                full_url = urljoin(base_url, path)
            
            optimized_endpoints.append({
                'url': full_url,
                'method': endpoint.get('method', 'GET').upper(),
                'path': path,
                'base_url': base_url,
                'original_endpoint': endpoint
            })
        
        # Run optimized scan
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            optimized_results = loop.run_until_complete(
                self.performance_optimizer.optimize_scan(optimized_endpoints, self.api_tests)
            )
        finally:
            loop.close()
        
        # Convert results to standard format
        scan_results = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_endpoints': len(endpoints),
            'scanned_endpoints': len(endpoints),
            'vulnerabilities': optimized_results['scan_results']['vulnerabilities'],
            'test_results': optimized_results['scan_results']['test_results'],
            'summary': self._calculate_vulnerability_summary(optimized_results['scan_results']['vulnerabilities']),
            'status': 'completed',
            'performance_metrics': optimized_results['performance_metrics'],
            'optimization_stats': {
                'cache_hit_rate': optimized_results['cache_stats']['hit_rate'],
                'test_effectiveness': optimized_results['test_effectiveness'],
                'requests_per_second': optimized_results['performance_metrics']['requests_per_second']
            }
        }
        
        debug_log("Optimized scan completed", 
                 scanned=scan_results['scanned_endpoints'],
                 vulnerabilities=len(scan_results['vulnerabilities']),
                 performance_metrics=scan_results['performance_metrics'])
        
        return scan_results

    def _calculate_vulnerability_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate vulnerability summary by severity"""
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary

    @debug_method
    def scan_with_adaptive_optimization(self, endpoints: List[Dict[str, Any]], 
                                      initial_workers: int = 5) -> Dict[str, Any]:
        """Scan with adaptive optimization based on target response characteristics"""
        debug_log("Starting adaptive optimization scan", endpoint_count=len(endpoints))
        
        # Phase 1: Quick assessment scan
        assessment_results = self._run_assessment_scan(endpoints[:min(3, len(endpoints))])
        
        # Phase 2: Determine optimal configuration
        optimal_config = self._determine_optimal_config(assessment_results)
        
        # Phase 3: Run full scan with optimal configuration
        optimized_scanner = create_optimized_scanner(
            max_workers=optimal_config['max_workers'],
            max_connections=optimal_config['max_connections'],
            cache_size=optimal_config['cache_size'],
            max_requests_per_second=optimal_config['max_requests_per_second']
        )
        
        # Run optimized scan
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            optimized_results = loop.run_until_complete(
                optimized_scanner.optimize_scan(endpoints, self.api_tests)
            )
        finally:
            loop.close()
        
        return {
            'scan_results': optimized_results['scan_results'],
            'performance_metrics': optimized_results['performance_metrics'],
            'adaptive_config': optimal_config,
            'assessment_results': assessment_results
        }

    def _run_assessment_scan(self, sample_endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run a quick assessment scan to determine target characteristics"""
        debug_log("Running assessment scan", sample_count=len(sample_endpoints))
        
        assessment_metrics = {
            'response_times': [],
            'success_rate': 0,
            'error_patterns': [],
            'rate_limit_detected': False,
            'avg_response_size': 0
        }
        
        total_requests = 0
        successful_requests = 0
        response_sizes = []
        
        for endpoint in sample_endpoints:
            # Build URL
            base_url = endpoint.get('base_url', '')
            path = endpoint.get('path', '')
            method = endpoint.get('method', 'GET').upper()
            
            if path.startswith('http'):
                full_url = path
            else:
                if base_url.endswith('/') and path.startswith('/'):
                    path = path[1:]
                full_url = urljoin(base_url, path)
            
            # Test connectivity
            try:
                start_time = time.time()
                response = self.session.request(method, full_url, timeout=10)
                response_time = time.time() - start_time
                
                assessment_metrics['response_times'].append(response_time)
                response_sizes.append(len(response.content))
                total_requests += 1
                
                if response.status_code < 400:
                    successful_requests += 1
                elif response.status_code == 429:
                    assessment_metrics['rate_limit_detected'] = True
                else:
                    assessment_metrics['error_patterns'].append(response.status_code)
                    
            except Exception as e:
                assessment_metrics['error_patterns'].append(str(e))
                total_requests += 1
        
        # Calculate metrics
        if total_requests > 0:
            assessment_metrics['success_rate'] = successful_requests / total_requests
        if response_sizes:
            assessment_metrics['avg_response_size'] = statistics.mean(response_sizes)
        
        debug_log("Assessment scan completed", metrics=assessment_metrics)
        return assessment_metrics

    def _determine_optimal_config(self, assessment_results: Dict[str, Any]) -> Dict[str, Any]:
        """Determine optimal configuration based on assessment results"""
        avg_response_time = statistics.mean(assessment_results['response_times']) if assessment_results['response_times'] else 5.0
        success_rate = assessment_results['success_rate']
        rate_limit_detected = assessment_results['rate_limit_detected']
        
        # Adaptive configuration logic
        if avg_response_time > 3.0:
            # Slow API - reduce workers and increase timeouts
            max_workers = 3
            max_requests_per_second = 5
        elif avg_response_time < 1.0 and success_rate > 0.9:
            # Fast API - increase workers
            max_workers = 15
            max_requests_per_second = 20
        else:
            # Moderate API
            max_workers = 8
            max_requests_per_second = 10
        
        # Adjust for rate limiting
        if rate_limit_detected:
            max_requests_per_second = max(1, max_requests_per_second // 2)
        
        # Adjust for success rate
        if success_rate < 0.7:
            max_workers = max(2, max_workers // 2)
            max_requests_per_second = max(1, max_requests_per_second // 2)
        
        optimal_config = {
            'max_workers': max_workers,
            'max_connections': max_workers * 10,
            'cache_size': 1000,
            'max_requests_per_second': max_requests_per_second,
            'timeout': max(30, int(avg_response_time * 10))
        }
        
        debug_log("Optimal configuration determined", config=optimal_config)
        return optimal_config

    @debug_method
    def scan_with_intelligent_testing(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan with intelligent test selection based on endpoint characteristics"""
        debug_log("Starting intelligent testing scan", endpoint_count=len(endpoints))
        
        # Create intelligent test selector
        test_selector = IntelligentTestSelector()
        
        # Group endpoints by type for batch processing
        endpoint_groups = self._group_endpoints_by_type(endpoints)
        
        scan_results = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_endpoints': len(endpoints),
            'scanned_endpoints': 0,
            'vulnerabilities': [],
            'test_results': {},
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'endpoint_groups': {}
        }
        
        for group_name, group_endpoints in endpoint_groups.items():
            debug_log(f"Scanning endpoint group: {group_name}", count=len(group_endpoints))
            
            # Select relevant tests for this group
            sample_endpoint = group_endpoints[0]
            selected_tests = test_selector.select_tests_for_endpoint(sample_endpoint, self.api_tests)
            
            # Scan group with selected tests
            group_results = self._scan_endpoint_group(group_endpoints, selected_tests)
            
            scan_results['endpoint_groups'][group_name] = group_results
            scan_results['scanned_endpoints'] += len(group_endpoints)
            scan_results['vulnerabilities'].extend(group_results.get('vulnerabilities', []))
            
            # Update summary
            for vuln in group_results.get('vulnerabilities', []):
                severity = vuln.get('severity', 'info').lower()
                if severity in scan_results['summary']:
                    scan_results['summary'][severity] += 1
        
        scan_results['status'] = 'completed'
        
        debug_log("Intelligent testing scan completed", 
                 scanned=scan_results['scanned_endpoints'],
                 vulnerabilities=len(scan_results['vulnerabilities']))
        
        return scan_results

    def _group_endpoints_by_type(self, endpoints: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group endpoints by their type for batch processing"""
        groups = defaultdict(list)
        
        for endpoint in endpoints:
            path = endpoint.get('path', '').lower()
            
            # Determine endpoint type
            if any(pattern in path for pattern in ['/auth', '/login', '/token']):
                groups['authentication'].append(endpoint)
            elif any(pattern in path for pattern in ['/users', '/user', '/admin']):
                groups['user_management'].append(endpoint)
            elif any(pattern in path for pattern in ['/api', '/data', '/records']):
                groups['data_operations'].append(endpoint)
            elif any(pattern in path for pattern in ['/files', '/upload', '/download']):
                groups['file_operations'].append(endpoint)
            else:
                groups['generic'].append(endpoint)
        
        return dict(groups)

    def _scan_endpoint_group(self, endpoints: List[Dict[str, Any]], 
                           selected_tests: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a group of endpoints with selected tests"""
        group_results = {
            'endpoints_scanned': len(endpoints),
            'vulnerabilities': [],
            'test_results': {}
        }
        
        for endpoint in endpoints:
            endpoint_result = self.scan_single_endpoint(endpoint, set())
            if endpoint_result.get('vulnerabilities'):
                group_results['vulnerabilities'].extend(endpoint_result['vulnerabilities'])
        
        return group_results

    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        if not self.performance_optimizer:
            return {'error': 'Performance optimization not enabled'}
        
        return self.performance_optimizer.get_performance_report()

    def benchmark_performance(self, test_endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Benchmark scanner performance"""
        if not self.performance_optimizer:
            return {'error': 'Performance optimization not enabled'}
        
        return benchmark_scanner_performance(self.performance_optimizer, test_endpoints, self.api_tests)

    def optimize_configuration(self, target_endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Optimize scanner configuration for specific targets"""
        debug_log("Optimizing configuration for target endpoints", count=len(target_endpoints))
        
        # Run assessment
        assessment = self._run_assessment_scan(target_endpoints[:min(5, len(target_endpoints))])
        
        # Determine optimal configuration
        optimal_config = self._determine_optimal_config(assessment)
        
        # Create new optimized scanner
        optimized_scanner = create_optimized_scanner(
            max_workers=optimal_config['max_workers'],
            max_connections=optimal_config['max_connections'],
            cache_size=optimal_config['cache_size'],
            max_requests_per_second=optimal_config['max_requests_per_second']
        )
        
        # Benchmark the new configuration
        benchmark_results = benchmark_scanner_performance(optimized_scanner, target_endpoints, self.api_tests)
        
        return {
            'optimal_configuration': optimal_config,
            'assessment_results': assessment,
            'benchmark_results': benchmark_results,
            'recommendations': self._generate_optimization_recommendations(assessment, optimal_config)
        }

    def _generate_optimization_recommendations(self, assessment: Dict[str, Any], 
                                             config: Dict[str, Any]) -> List[str]:
        """Generate optimization recommendations"""
        recommendations = []
        
        avg_response_time = statistics.mean(assessment['response_times']) if assessment['response_times'] else 0
        
        if avg_response_time > 3.0:
            recommendations.append("Target API is slow - consider reducing parallel workers and increasing timeouts")
        
        if assessment['success_rate'] < 0.8:
            recommendations.append("Low success rate - consider reducing request rate and checking authentication")
        
        if assessment['rate_limit_detected']:
            recommendations.append("Rate limiting detected - use conservative request rates")
        
        if config['max_workers'] < 5:
            recommendations.append("Low worker count - consider increasing for better throughput")
        
        return recommendations

# Example usage
if __name__ == "__main__":
    # Initialize API security scanner
    scanner = APISecurityScanner()
    
    print("🔍 OWASP API Top 10 Security Scanner with Collection Support")
    print("=" * 60)
    
    # Example 1: Scan from Swagger URL with OWASP reporting
    print("\n📋 Example 1: Scanning from Swagger URL with OWASP Top 10")
    swagger_results = scanner.scan_from_swagger_url(
        "https://petstore.swagger.io/v2/swagger.json",
        "https://petstore.swagger.io/v2"
    )
    
    if 'error' not in swagger_results:
        # Generate standard report
        report_file = scanner.generate_api_security_report(swagger_results)
        print(f"✅ Standard scan completed. Report saved to: {report_file}")
        
        # Generate OWASP API Top 10 report
        owasp_report_file = scanner.generate_owasp_report(swagger_results, 'html')
        print(f"✅ OWASP API Top 10 report saved to: {owasp_report_file}")
        
        # Display OWASP checklist summary
        owasp_checklist = scanner.generate_owasp_api_top10_checklist(swagger_results)
        print("\n📊 OWASP API Top 10 Checklist Summary:")
        print("-" * 40)
        
        for vuln_id, vuln_info in owasp_checklist.items():
            status_icon = "🔴" if vuln_info['status'] == 'Vulnerable' else "🟢" if vuln_info['status'] == 'Secure' else "⚪"
            print(f"{status_icon} {vuln_id}: {vuln_info['status']} ({vuln_info['vulnerabilities_found']} vulns)")
    else:
        print(f"❌ Swagger scan failed: {swagger_results['error']}")
    
    # Example 2: Upload and scan API collection
    print("\n📁 Example 2: Upload and scan API collection")
    print("Supported formats: Postman (.json), Insomnia (.json), HAR (.har), curl commands (.txt)")
    
    # Example collection files (uncomment to test)
    # collection_examples = [
    #     ("postman_collection.json", "https://api.example.com"),
    #     ("insomnia_collection.json", "https://api.example.com"),
    #     ("har_export.har", None),
    #     ("curl_commands.txt", "https://api.example.com")
    # ]
    # 
    # for collection_file, base_url in collection_examples:
    #     print(f"\n📂 Processing: {collection_file}")
    #     results = scanner.upload_and_scan_collection(collection_file, base_url)
    #     
    #     if 'error' not in results:
    #         print(f"✅ Collection format: {results['collection_format']}")
    #         print(f"✅ Endpoints found: {results['endpoints_found']}")
    #         print(f"✅ Reports: {results['reports']['standard_report']}, {results['reports']['owasp_report']}")
    #     else:
    #         print(f"❌ Collection scan failed: {results['error']}")
    
    # Example 3: Direct collection scanning
    print("\n🔧 Example 3: Direct collection scanning")
    # results = scanner.scan_from_api_collection("my_collection.json", "https://api.example.com")
    # if 'error' not in results:
    #     print(f"✅ Collection scanned successfully!")
    #     print(f"📊 Format: {results['collection_format']}")
    #     print(f"📊 Endpoints: {results['endpoints_found']}")
    # else:
    #     print(f"❌ Collection scan failed: {results['error']}")
    
    # Example 4: JSON file scanning
    print("\n📋 Example 4: Scanning from JSON file with OWASP Top 10")
    # json_results = scanner.scan_from_json_file("api_spec.json", "https://api.example.com")
    # 
    # if 'error' not in json_results:
    #     # Generate both reports
    #     report_file = scanner.generate_api_security_report(json_results)
    #     owasp_report_file = scanner.generate_owasp_report(json_results, 'html')
    #     print(f"✅ JSON scan completed. Reports saved to: {report_file}, {owasp_report_file}")
    # else:
    #     print(f"❌ JSON scan failed: {json_results['error']}")
    
    print("\n🎯 OWASP API Top 10 Categories Covered:")
    print("=" * 50)
    print("🔴 API1:2023 - Broken Object Property Level Authorization")
    print("🔴 API2:2023 - Broken Authentication")
    print("🔴 API3:2023 - Broken Object Property Level Authorization")
    print("🟡 API4:2023 - Unrestricted Resource Consumption")
    print("🔴 API5:2023 - Broken Function Level Authorization")
    print("🟡 API6:2023 - Unrestricted Access to Sensitive Business Flows")
    print("🟡 API7:2023 - Server-Side Request Forgery")
    print("🟢 API8:2023 - Security Misconfiguration")
    print("🟢 API9:2023 - Improper Inventory Management")
    print("🟢 API10:2023 - Unsafe Consumption of APIs")
    
    print("\n📁 Supported API Collection Formats:")
    print("=" * 40)
    print("📋 Postman Collections (.json)")
    print("   • Full request/response data")
    print("   • Authentication information")
    print("   • Environment variables")
    print("   • Headers and body data")
    
    print("\n📋 Insomnia Collections (.json)")
    print("   • Request configurations")
    print("   • Headers and authentication")
    print("   • Body data and parameters")
    
    print("\n📋 HAR Files (.har)")
    print("   • HTTP Archive format")
    print("   • Browser network traffic")
    print("   • Complete request/response data")
    
    print("\n📋 curl Commands (.txt)")
    print("   • Command-line curl requests")
    print("   • Headers and data extraction")
    print("   • URL and method parsing")
    
    print("\n📋 Generic JSON (.json)")
    print("   • Custom API specifications")
    print("   • Simple endpoint definitions")
    print("   • Flexible format support")
    
    print("\n🚀 API Security Scanner ready for integration with Burp Suite!")
    print("📖 Features:")
    print("   • OWASP API Top 10 2023 compliance")
    print("   • Swagger/OpenAPI specification parsing")
    print("   • API collection upload and parsing")
    print("   • Multiple collection format support")
    print("   • Comprehensive vulnerability testing")
    print("   • Detailed HTML and JSON reporting")
    print("   • Security scoring and recommendations")
    print("   • Burp Suite integration ready")
    
    print("\n💡 Usage Examples:")
    print("   • Upload Postman collection for security testing")
    print("   • Import HAR files from browser traffic")
    print("   • Parse curl commands for API testing")
    print("   • Scan Swagger/OpenAPI specifications")
    print("   • Generate OWASP-compliant security reports")