"""
Test suite for new security plugins.

This module contains comprehensive tests for the newly implemented
security plugins including BOLA, SSRF, and Broken Authentication checkers.
"""

import pytest
import uuid
from datetime import datetime
from unittest.mock import Mock, patch

from api_security_scanner.plugins.bola_checker import BOLAChecker
from api_security_scanner.plugins.ssrf_security_checker import SSRFSecurityChecker
from api_security_scanner.plugins.broken_authentication_checker import BrokenAuthenticationChecker
from api_security_scanner.core.scanner_plugins import PluginResult, Vulnerability


class TestBOLAChecker:
    """Test cases for BOLA (Broken Object Level Authorization) Checker."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = BOLAChecker()
        self.test_requests = [
            {
                'url': 'https://api.example.com/users/123',
                'method': 'GET',
                'headers': {'Authorization': 'Bearer token123'},
                'body': ''
            },
            {
                'url': 'https://api.example.com/orders/456',
                'method': 'GET',
                'headers': {'Authorization': 'Bearer token123'},
                'body': '{"user_id": "123"}'
            }
        ]
    
    def test_plugin_initialization(self):
        """Test plugin initialization."""
        assert self.plugin.name == "BOLAChecker"
        assert self.plugin.description == "Detects Broken Object Level Authorization (BOLA) and IDOR vulnerabilities"
        assert self.plugin.version == "1.0.0"
    
    def test_extract_object_identifiers(self):
        """Test object identifier extraction."""
        # Test URL path extraction
        url = "https://api.example.com/users/123"
        body = ""
        identifiers = self.plugin._extract_object_identifiers(url, body)
        assert "123" in identifiers
        
        # Test JSON body extraction
        url = "https://api.example.com/orders"
        body = '{"user_id": "456", "order_id": "789"}'
        identifiers = self.plugin._extract_object_identifiers(url, body)
        assert "456" in identifiers
        assert "789" in identifiers
    
    def test_is_object_id(self):
        """Test object ID detection."""
        # Valid object IDs
        assert self.plugin._is_object_id("123") == True
        assert self.plugin._is_object_id("550e8400-e29b-41d4-a716-446655440000") == True  # UUID
        assert self.plugin._is_object_id("507f1f77bcf86cd799439011") == True  # MongoDB ObjectId
        
        # Invalid object IDs
        assert self.plugin._is_object_id("") == False
        assert self.plugin._is_object_id("abc") == False
        assert self.plugin._is_object_id("123abc") == False
    
    def test_is_object_id_param(self):
        """Test object ID parameter detection."""
        # Valid parameter names
        assert self.plugin._is_object_id_param("user_id") == True
        assert self.plugin._is_object_id_param("order_id") == True
        assert self.plugin._is_object_id_param("id") == True
        
        # Invalid parameter names
        assert self.plugin._is_object_id_param("name") == False
        assert self.plugin._is_object_id_param("email") == False
    
    def test_sequential_id_access(self):
        """Test sequential ID access detection."""
        url = "https://api.example.com/users/123"
        method = "GET"
        headers = {"Authorization": "Bearer token"}
        body = ""
        obj_id = "123"
        
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            vulnerabilities = self.plugin._test_sequential_id_access(url, method, headers, body, obj_id)
            
            # Should detect sequential ID access vulnerability
            assert len(vulnerabilities) > 0
            assert any("Sequential ID Access" in vuln.name for vuln in vulnerabilities)
    
    def test_predictable_id_access(self):
        """Test predictable ID access detection."""
        url = "https://api.example.com/users/123"
        method = "GET"
        headers = {"Authorization": "Bearer token"}
        body = ""
        obj_id = "123"
        
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            vulnerabilities = self.plugin._test_predictable_id_access(url, method, headers, body, obj_id)
            
            # Should detect predictable ID access vulnerability
            assert len(vulnerabilities) > 0
            assert any("Predictable ID Access" in vuln.name for vuln in vulnerabilities)
    
    def test_other_user_access(self):
        """Test other user access detection."""
        url = "https://api.example.com/users/123"
        method = "GET"
        headers = {"Authorization": "Bearer token"}
        body = ""
        obj_id = "123"
        
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            vulnerabilities = self.plugin._test_other_user_access(url, method, headers, body, obj_id)
            
            # Should detect other user access vulnerability
            assert len(vulnerabilities) > 0
            assert any("Other User Access" in vuln.name for vuln in vulnerabilities)
    
    def test_plugin_execution(self):
        """Test full plugin execution."""
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            result = self.plugin.check("https://api.example.com", self.test_requests)
            
            assert isinstance(result, PluginResult)
            assert result.plugin_name == "BOLAChecker"
            assert result.success == True
            # PluginResult doesn't have metadata attribute
            assert result.execution_time >= 0


class TestSSRFSecurityChecker:
    """Test cases for SSRF Security Checker."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = SSRFSecurityChecker()
        self.test_requests = [
            {
                'url': 'https://api.example.com/fetch?url=https://example.com',
                'method': 'GET',
                'headers': {'Authorization': 'Bearer token123'},
                'body': ''
            },
            {
                'url': 'https://api.example.com/proxy',
                'method': 'POST',
                'headers': {'Authorization': 'Bearer token123'},
                'body': '{"url": "https://example.com"}'
            }
        ]
    
    def test_plugin_initialization(self):
        """Test plugin initialization."""
        assert self.plugin.name == "SSRFSecurityChecker"
        assert self.plugin.description == "Detects Server-Side Request Forgery (SSRF) vulnerabilities"
        assert self.plugin.version == "1.0.0"
    
    def test_extract_ssrf_parameters(self):
        """Test SSRF parameter extraction."""
        # Test URL parameter extraction
        url = "https://api.example.com/fetch?url=https://example.com&callback=http://evil.com"
        body = ""
        params = self.plugin._extract_ssrf_parameters(url, body)
        assert "url" in params
        assert "callback" in params
        
        # Test JSON body extraction
        url = "https://api.example.com/proxy"
        body = '{"url": "https://example.com", "target": "http://internal.com"}'
        params = self.plugin._extract_ssrf_parameters(url, body)
        assert "url" in params
        assert "target" in params
    
    def test_is_potential_url(self):
        """Test potential URL detection."""
        # Valid URLs
        assert self.plugin._is_potential_url("https://example.com") == True
        assert self.plugin._is_potential_url("http://localhost") == True
        assert self.plugin._is_potential_url("ftp://files.example.com") == True
        
        # Invalid URLs
        assert self.plugin._is_potential_url("") == False
        assert self.plugin._is_potential_url("example.com") == False
        assert self.plugin._is_potential_url("not-a-url") == False
    
    def test_external_url_access(self):
        """Test external URL access detection."""
        url = "https://api.example.com/fetch"
        method = "GET"
        headers = {"Authorization": "Bearer token"}
        body = ""
        param_name = "url"
        param_value = "https://example.com"
        
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            vulnerabilities = self.plugin._test_external_url_access(url, method, headers, body, param_name, param_value)
            
            # Should detect external URL access vulnerability
            assert len(vulnerabilities) > 0
            assert any("External URL Access" in vuln.name for vuln in vulnerabilities)
    
    def test_localhost_access(self):
        """Test localhost access detection."""
        url = "https://api.example.com/fetch"
        method = "GET"
        headers = {"Authorization": "Bearer token"}
        body = ""
        param_name = "url"
        param_value = "https://example.com"
        
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            vulnerabilities = self.plugin._test_localhost_access(url, method, headers, body, param_name, param_value)
            
            # Should detect localhost access vulnerability
            assert len(vulnerabilities) > 0
            assert any("Localhost Access" in vuln.name for vuln in vulnerabilities)
    
    def test_file_url_access(self):
        """Test file URL access detection."""
        url = "https://api.example.com/fetch"
        method = "GET"
        headers = {"Authorization": "Bearer token"}
        body = ""
        param_name = "url"
        param_value = "https://example.com"
        
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            vulnerabilities = self.plugin._test_file_url_access(url, method, headers, body, param_name, param_value)
            
            # Should detect file URL access vulnerability
            assert len(vulnerabilities) > 0
            assert any("File URL Access" in vuln.name for vuln in vulnerabilities)
    
    def test_cloud_metadata_access(self):
        """Test cloud metadata access detection."""
        url = "https://api.example.com/fetch"
        method = "GET"
        headers = {"Authorization": "Bearer token"}
        body = ""
        
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            vulnerabilities = self.plugin._test_cloud_metadata_access(url, method, headers, body)
            
            # Should detect cloud metadata access vulnerability
            assert len(vulnerabilities) > 0
            assert any("Cloud Metadata Access" in vuln.name for vuln in vulnerabilities)
    
    def test_plugin_execution(self):
        """Test full plugin execution."""
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            result = self.plugin.check("https://api.example.com", self.test_requests)
            
            assert isinstance(result, PluginResult)
            assert result.plugin_name == "SSRFSecurityChecker"
            assert result.success == True
            # PluginResult doesn't have metadata attribute
            assert result.execution_time >= 0


class TestBrokenAuthenticationChecker:
    """Test cases for Broken Authentication Checker."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = BrokenAuthenticationChecker()
        self.test_requests = [
            {
                'url': 'https://api.example.com/login',
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"username": "admin", "password": "password123"}'
            },
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Authorization': 'Bearer token123'},
                'body': ''
            }
        ]
    
    def test_plugin_initialization(self):
        """Test plugin initialization."""
        assert self.plugin.name == "BrokenAuthenticationChecker"
        assert self.plugin.description == "Detects broken authentication mechanisms and vulnerabilities"
        assert self.plugin.version == "1.0.0"
    
    def test_has_authentication(self):
        """Test authentication detection."""
        # With authentication headers
        headers = {"Authorization": "Bearer token123"}
        body = ""
        assert self.plugin._has_authentication(headers, body) == True
        
        # With API key
        headers = {"X-API-Key": "key123"}
        body = ""
        assert self.plugin._has_authentication(headers, body) == True
        
        # With authentication in body
        headers = {}
        body = '{"token": "token123"}'
        assert self.plugin._has_authentication(headers, body) == True
        
        # Without authentication
        headers = {}
        body = ""
        assert self.plugin._has_authentication(headers, body) == False
    
    def test_check_weak_authentication_mechanisms(self):
        """Test weak authentication mechanism detection."""
        # Basic auth without HTTPS
        headers = {"Authorization": "Basic dXNlcjpwYXNz"}
        body = ""
        weak_auth = self.plugin._check_weak_authentication_mechanisms(headers, body)
        assert weak_auth is not None
        assert "Basic Authentication" in weak_auth
        
        # API key in headers
        headers = {"X-API-Key": "key123"}
        body = ""
        weak_auth = self.plugin._check_weak_authentication_mechanisms(headers, body)
        assert weak_auth is not None
        assert "API key" in weak_auth
    
    def test_check_weak_passwords(self):
        """Test weak password detection."""
        # Weak password - too short
        body = '{"password": "123"}'
        assert self.plugin._check_weak_passwords(body) == True
        
        # Weak password - only letters
        body = '{"password": "password"}'
        assert self.plugin._check_weak_passwords(body) == True
        
        # Weak password - common password
        body = '{"password": "admin"}'
        assert self.plugin._check_weak_passwords(body) == True
        
        # Strong password
        body = '{"password": "StrongP@ssw0rd123!"}'
        assert self.plugin._check_weak_passwords(body) == False
    
    def test_check_password_in_url(self):
        """Test password in URL detection."""
        # Password in URL
        url = "https://api.example.com/login?username=admin&password=secret"
        assert self.plugin._check_password_in_url(url) == True
        
        # Password in URL with different parameter name
        url = "https://api.example.com/login?username=admin&pass=secret"
        assert self.plugin._check_password_in_url(url) == True
        
        # No password in URL
        url = "https://api.example.com/users"
        assert self.plugin._check_password_in_url(url) == False
    
    def test_empty_authentication(self):
        """Test empty authentication detection."""
        url = "https://api.example.com/users"
        method = "GET"
        headers = {"Authorization": "Bearer token123"}
        body = ""
        
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            vulnerabilities = self.plugin._test_empty_authentication(url, method, headers, body)
            
            # Should detect empty authentication vulnerability
            assert len(vulnerabilities) > 0
            assert any("Empty Authentication" in vuln.name for vuln in vulnerabilities)
    
    def test_malformed_authentication(self):
        """Test malformed authentication detection."""
        url = "https://api.example.com/users"
        method = "GET"
        headers = {"Authorization": "Bearer token123"}
        body = ""
        
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            vulnerabilities = self.plugin._test_malformed_authentication(url, method, headers, body)
            
            # Should detect malformed authentication vulnerability
            assert len(vulnerabilities) > 0
            assert any("Malformed Authentication" in vuln.name for vuln in vulnerabilities)
    
    def test_sql_injection_auth(self):
        """Test SQL injection in authentication detection."""
        url = "https://api.example.com/login"
        method = "POST"
        headers = {"Authorization": "Bearer token123"}
        body = ""
        
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            vulnerabilities = self.plugin._test_sql_injection_auth(url, method, headers, body)
            
            # Should detect SQL injection in authentication vulnerability
            assert len(vulnerabilities) > 0
            assert any("SQL Injection" in vuln.name for vuln in vulnerabilities)
    
    def test_role_escalation(self):
        """Test role escalation detection."""
        url = "https://api.example.com/users"
        method = "GET"
        headers = {"Authorization": "Bearer token123"}
        body = ""
        
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            vulnerabilities = self.plugin._test_role_escalation(url, method, headers, body)
            
            # Should detect role escalation vulnerability
            assert len(vulnerabilities) > 0
            assert any("Role Escalation" in vuln.name for vuln in vulnerabilities)
    
    def test_admin_escalation(self):
        """Test admin escalation detection."""
        url = "https://api.example.com/admin"
        method = "GET"
        headers = {"Authorization": "Bearer token123"}
        body = ""
        
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            vulnerabilities = self.plugin._test_admin_escalation(url, method, headers, body)
            
            # Should detect admin escalation vulnerability
            assert len(vulnerabilities) > 0
            assert any("Admin Privilege Escalation" in vuln.name for vuln in vulnerabilities)
    
    def test_plugin_execution(self):
        """Test full plugin execution."""
        with patch.object(self.plugin, 'make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_request.return_value = mock_response
            
            result = self.plugin.check("https://api.example.com", self.test_requests)
            
            assert isinstance(result, PluginResult)
            assert result.plugin_name == "BrokenAuthenticationChecker"
            assert result.success == True
            # PluginResult doesn't have metadata attribute
            assert result.execution_time >= 0


class TestPluginIntegration:
    """Integration tests for all new plugins."""
    
    def test_all_plugins_implement_base_interface(self):
        """Test that all plugins implement the base plugin interface."""
        plugins = [
            BOLAChecker(),
            SSRFSecurityChecker(),
            BrokenAuthenticationChecker()
        ]
        
        for plugin in plugins:
            # Test required attributes
            assert hasattr(plugin, 'name')
            assert hasattr(plugin, 'description')
            assert hasattr(plugin, 'version')
            assert hasattr(plugin, 'author')
            
            # Test required methods
            assert hasattr(plugin, 'check')
            assert hasattr(plugin, 'generate_poc')
            
            # Test method signatures
            assert callable(plugin.check)
            assert callable(plugin.generate_poc)
    
    def test_plugin_result_consistency(self):
        """Test that all plugins return consistent PluginResult objects."""
        plugins = [
            BOLAChecker(),
            SSRFSecurityChecker(),
            BrokenAuthenticationChecker()
        ]
        
        test_requests = [
            {
                'url': 'https://api.example.com/test',
                'method': 'GET',
                'headers': {'Authorization': 'Bearer token'},
                'body': ''
            }
        ]
        
        for plugin in plugins:
            with patch.object(plugin, 'make_request') as mock_request:
                mock_request.return_value = {"status_code": 200}
                
                result = plugin.check("https://api.example.com", test_requests)
                
                # Test PluginResult structure
                assert isinstance(result, PluginResult)
                assert hasattr(result, 'plugin_name')
                assert hasattr(result, 'vulnerabilities')
                assert hasattr(result, 'execution_time')
                assert hasattr(result, 'success')
                assert hasattr(result, 'error')
                # PluginResult doesn't have metadata attribute
                
                # Test vulnerability structure
                for vulnerability in result.vulnerabilities:
                    assert isinstance(vulnerability, Vulnerability)
                    assert hasattr(vulnerability, 'id')
                    assert hasattr(vulnerability, 'name')
                    assert hasattr(vulnerability, 'description')
                    assert hasattr(vulnerability, 'risk')
                    assert hasattr(vulnerability, 'cvss_score')
                    assert hasattr(vulnerability, 'solution')
                    assert hasattr(vulnerability, 'references')
                    assert hasattr(vulnerability, 'cwe_id')
                    assert hasattr(vulnerability, 'wasc_id')
    
    def test_plugin_error_handling(self):
        """Test that all plugins handle errors gracefully."""
        plugins = [
            BOLAChecker(),
            SSRFSecurityChecker(),
            BrokenAuthenticationChecker()
        ]
        
        # Test with invalid input
        invalid_requests = [
            {
                'url': 'invalid-url',
                'method': 'INVALID',
                'headers': {},
                'body': 'invalid-json'
            }
        ]
        
        for plugin in plugins:
            with patch.object(plugin, 'make_request') as mock_request:
                mock_request.side_effect = Exception("Test error")
                
                result = plugin.check("https://api.example.com", invalid_requests)
                
                # Should handle errors gracefully
                assert isinstance(result, PluginResult)
                assert result.success == False
                assert result.error_message is not None
                assert len(result.vulnerabilities) == 0


if __name__ == "__main__":
    pytest.main([__file__])
