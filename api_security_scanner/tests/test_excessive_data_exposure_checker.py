"""
Test suite for ExcessiveDataExposureChecker plugin
"""

import pytest
import json
from datetime import datetime
from unittest.mock import Mock, patch
from api_security_scanner.plugins.excessive_data_exposure_checker import ExcessiveDataExposureChecker


class TestExcessiveDataExposureChecker:
    """Test cases for ExcessiveDataExposureChecker plugin"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.plugin = ExcessiveDataExposureChecker()
    
    def test_plugin_initialization(self):
        """Test plugin initialization"""
        assert self.plugin.name == "ExcessiveDataExposureChecker"
        assert "excessive data exposure" in self.plugin.description.lower()
        assert self.plugin.version == "1.0.0"
        assert len(self.plugin.sensitive_patterns) > 0
        assert len(self.plugin.sensitive_fields) > 0
        assert len(self.plugin.debug_fields) > 0
    
    def test_check_empty_requests(self):
        """Test check with empty requests list"""
        result = self.plugin.check([])
        
        assert result.plugin_name == "ExcessiveDataExposureChecker"
        assert result.success is True
        assert len(result.vulnerabilities) == 0
        assert result.error is None
    
    def test_check_credit_card_exposure(self):
        """Test detection of credit card numbers in response"""
        requests = [{
            'url': 'https://api.example.com/users/123',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'user_id': 123,
                    'name': 'John Doe',
                    'credit_card': '4111-1111-1111-1111',
                    'email': 'john@example.com'
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find credit card vulnerability
        cc_vuln = next((v for v in result.vulnerabilities if 'Credit Card' in v.name), None)
        assert cc_vuln is not None
        assert cc_vuln.risk == "High"
        assert cc_vuln.cwe_id == "CWE-200"
    
    def test_check_ssn_exposure(self):
        """Test detection of SSN in response"""
        requests = [{
            'url': 'https://api.example.com/employees/456',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'employee_id': 456,
                    'name': 'Jane Smith',
                    'ssn': '123-45-6789',
                    'department': 'Engineering'
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find SSN vulnerability
        ssn_vuln = next((v for v in result.vulnerabilities if 'SSN' in v.name), None)
        assert ssn_vuln is not None
        assert ssn_vuln.risk == "High"
    
    def test_check_email_exposure(self):
        """Test detection of email addresses in response"""
        requests = [{
            'url': 'https://api.example.com/users',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'users': [
                        {'id': 1, 'name': 'User 1', 'email': 'user1@example.com'},
                        {'id': 2, 'name': 'User 2', 'email': 'user2@example.com'}
                    ]
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find email vulnerability
        email_vuln = next((v for v in result.vulnerabilities if 'Email' in v.name), None)
        assert email_vuln is not None
        assert email_vuln.risk == "Medium"
    
    def test_check_api_key_exposure(self):
        """Test detection of API keys in response"""
        requests = [{
            'url': 'https://api.example.com/config',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'api_key': 'sk-1234567890abcdef1234567890abcdef',
                    'database_url': 'postgresql://user:pass@localhost:5432/db'
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find API key vulnerability
        api_key_vuln = next((v for v in result.vulnerabilities if 'API Keys' in v.name), None)
        assert api_key_vuln is not None
        assert api_key_vuln.risk == "High"
    
    def test_check_sensitive_headers(self):
        """Test detection of sensitive data in response headers"""
        requests = [{
            'url': 'https://api.example.com/auth',
            'method': 'POST',
            'headers': {'Content-Type': 'application/json'},
            'body': '{"username": "test", "password": "test"}',
            'response': {
                'status_code': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'X-API-Key': 'secret-api-key-12345',
                    'X-User-ID': '12345',
                    'X-Debug': 'true'
                },
                'body': '{"token": "jwt-token-here"}'
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find sensitive headers vulnerability
        header_vuln = next((v for v in result.vulnerabilities if 'Response Headers' in v.name), None)
        assert header_vuln is not None
        assert header_vuln.risk == "Medium"
    
    def test_check_error_response_exposure(self):
        """Test detection of excessive data in error responses"""
        requests = [{
            'url': 'https://api.example.com/invalid',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'error': 'Internal Server Error',
                    'stack_trace': 'at com.example.Service.method(Service.java:123)',
                    'file': '/app/src/main/java/Service.java',
                    'line': 123,
                    'exception': 'java.lang.NullPointerException'
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find error response vulnerability
        error_vuln = next((v for v in result.vulnerabilities if 'Error Response' in v.name), None)
        assert error_vuln is not None
        assert error_vuln.risk == "Medium"
    
    def test_check_unnecessary_fields(self):
        """Test detection of unnecessary fields in successful responses"""
        requests = [{
            'url': 'https://api.example.com/users/123',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'user_id': 123,
                    'name': 'John Doe',
                    'email': 'john@example.com',
                    'internal_id': 'INT-12345',
                    'system_id': 'SYS-67890',
                    'debug_mode': True,
                    'version': '1.2.3',
                    'build_number': '456'
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find unnecessary fields vulnerability
        fields_vuln = next((v for v in result.vulnerabilities if 'Unnecessary Data Fields' in v.name), None)
        assert fields_vuln is not None
        assert fields_vuln.risk == "Low"
    
    def test_check_large_list_endpoint(self):
        """Test detection of large datasets in list endpoints"""
        # Create a large list of users
        large_user_list = [{'id': i, 'name': f'User {i}', 'email': f'user{i}@example.com'} for i in range(150)]
        
        requests = [{
            'url': 'https://api.example.com/users',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps(large_user_list)
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find large dataset vulnerability
        list_vuln = next((v for v in result.vulnerabilities if 'Large Data Set' in v.name), None)
        assert list_vuln is not None
        assert list_vuln.risk == "Low"
    
    def test_check_jwt_token_exposure(self):
        """Test detection of JWT tokens in response"""
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        requests = [{
            'url': 'https://api.example.com/auth/login',
            'method': 'POST',
            'headers': {'Content-Type': 'application/json'},
            'body': '{"username": "test", "password": "test"}',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'access_token': jwt_token,
                    'refresh_token': jwt_token,
                    'user': {'id': 123, 'name': 'John Doe'}
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find JWT token vulnerability
        jwt_vuln = next((v for v in result.vulnerabilities if 'JWT Tokens' in v.name), None)
        assert jwt_vuln is not None
        assert jwt_vuln.risk == "High"
    
    def test_check_database_connection_string(self):
        """Test detection of database connection strings"""
        requests = [{
            'url': 'https://api.example.com/config',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'database_url': 'postgresql://user:password@localhost:5432/mydb',
                    'mongodb_url': 'mongodb://user:password@localhost:27017/mydb',
                    'jdbc_url': 'jdbc:postgresql://localhost:5432/mydb?user=user&password=password'
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find database connection string vulnerability
        db_vuln = next((v for v in result.vulnerabilities if 'Database Connection' in v.name), None)
        assert db_vuln is not None
        assert db_vuln.risk == "High"
    
    def test_check_internal_ip_exposure(self):
        """Test detection of internal IP addresses"""
        requests = [{
            'url': 'https://api.example.com/servers',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'servers': [
                        {'name': 'web-server', 'ip': '192.168.1.100'},
                        {'name': 'db-server', 'ip': '10.0.0.50'},
                        {'name': 'api-server', 'ip': '172.16.0.10'}
                    ]
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find internal IP vulnerability
        ip_vuln = next((v for v in result.vulnerabilities if 'Internal IPs' in v.name), None)
        assert ip_vuln is not None
        assert ip_vuln.risk == "Medium"
    
    def test_check_password_field_exposure(self):
        """Test detection of password fields in response"""
        requests = [{
            'url': 'https://api.example.com/users/123',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'user_id': 123,
                    'username': 'john_doe',
                    'password': 'plaintext_password_123',
                    'pwd': 'another_password',
                    'pass': 'yet_another_password'
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find password vulnerability
        password_vuln = next((v for v in result.vulnerabilities if 'Passwords' in v.name), None)
        assert password_vuln is not None
        assert password_vuln.risk == "High"
    
    def test_check_file_path_exposure(self):
        """Test detection of file system paths"""
        requests = [{
            'url': 'https://api.example.com/files',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'files': [
                        {'name': 'config.txt', 'path': 'C:\\Windows\\System32\\config.txt'},
                        {'name': 'log.txt', 'path': '/var/log/app.log'},
                        {'name': 'data.json', 'path': '/home/user/data.json'}
                    ]
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Find file path vulnerability
        path_vuln = next((v for v in result.vulnerabilities if 'File Paths' in v.name), None)
        assert path_vuln is not None
        assert path_vuln.risk == "Low"
    
    def test_check_multiple_vulnerabilities(self):
        """Test detection of multiple types of vulnerabilities in single response"""
        requests = [{
            'url': 'https://api.example.com/user/profile',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'X-API-Key': 'secret-key-12345',
                    'X-Debug': 'true'
                },
                'body': json.dumps({
                    'user_id': 123,
                    'name': 'John Doe',
                    'email': 'john@example.com',
                    'phone': '555-123-4567',
                    'ssn': '123-45-6789',
                    'credit_card': '4111-1111-1111-1111',
                    'internal_id': 'INT-12345',
                    'debug_mode': True,
                    'api_key': 'sk-1234567890abcdef'
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Should detect multiple types of vulnerabilities
        vulnerability_types = {v.name for v in result.vulnerabilities}
        assert len(vulnerability_types) > 1  # Multiple different vulnerability types
    
    def test_check_no_vulnerabilities(self):
        """Test with clean response containing no sensitive data"""
        requests = [{
            'url': 'https://api.example.com/public/info',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'app_name': 'My App',
                    'version': '1.0.0',
                    'status': 'active',
                    'features': ['feature1', 'feature2']
                })
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) == 0
    
    def test_check_malformed_json(self):
        """Test handling of malformed JSON responses"""
        requests = [{
            'url': 'https://api.example.com/invalid',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': '{"invalid": json, "missing": quote}'
            }
        }]
        
        result = self.plugin.check(requests)
        
        # Should not crash and should still check for patterns in the malformed JSON
        assert result.success is True
        # May or may not find vulnerabilities depending on the malformed content
    
    def test_check_empty_response_body(self):
        """Test handling of empty response bodies"""
        requests = [{
            'url': 'https://api.example.com/empty',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '',
            'response': {
                'status_code': 204,
                'headers': {'Content-Type': 'application/json'},
                'body': ''
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        assert len(result.vulnerabilities) == 0
    
    def test_check_non_json_response(self):
        """Test handling of non-JSON responses"""
        requests = [{
            'url': 'https://api.example.com/text',
            'method': 'GET',
            'headers': {'Content-Type': 'text/plain'},
            'body': '',
            'response': {
                'status_code': 200,
                'headers': {'Content-Type': 'text/plain'},
                'body': 'This is plain text with email@example.com and phone 555-123-4567'
            }
        }]
        
        result = self.plugin.check(requests)
        
        assert result.success is True
        # Should still detect patterns in plain text
        assert len(result.vulnerabilities) > 0
    
    def test_generate_poc(self):
        """Test proof of concept generation"""
        # Create a mock vulnerability
        from api_security_scanner.core.scanner_plugins import Vulnerability, ProofOfConcept
        
        mock_poc = ProofOfConcept(
            vulnerability_id="test-id",
            request_method="GET",
            request_url="https://api.example.com/test",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="test",
            timestamp=datetime.now(),
            evidence_description="test evidence"
        )
        
        mock_vuln = Vulnerability(
            id="test-id",
            name="Test Vulnerability",
            description="Test description",
            risk="Medium",
            cvss_score=5.3,
            solution="Test remediation",
            references=[],
            cwe_id="CWE-200",
            wasc_id="WASC-13",
            request="GET /test HTTP/1.1",
            response="HTTP/1.1 200 OK",
            url="https://api.example.com/test",
            parameter="",
            evidence="test evidence",
            scan_id="",
            timestamp=datetime.now()
        )
        
        poc = self.plugin.generate_poc(mock_vuln)
        
        assert poc is None
    
    def test_plugin_error_handling(self):
        """Test plugin error handling with invalid request data"""
        # Test with malformed request data
        requests = [{
            'invalid': 'data',
            'response': None
        }]
        
        result = self.plugin.check(requests)
        
        # Should handle errors gracefully
        assert result.success is True  # Plugin continues processing even with individual errors
        assert result.error is not None or len(result.vulnerabilities) == 0
