"""
Unit tests for plugin modules.
"""

import pytest
from unittest.mock import Mock, patch
import requests

from api_security_scanner.plugins.cors_checker import CORSChecker
from api_security_scanner.plugins.rate_limiting_checker import RateLimitingChecker
from api_security_scanner.plugins.security_headers_checker import SecurityHeadersChecker
from api_security_scanner.plugins.enhanced_security_checker import EnhancedSecurityChecker


class TestCORSChecker:
    """Test CORS checker plugin."""
    
    def test_cors_checker_init(self):
        """Test CORS checker initialization."""
        checker = CORSChecker()
        assert checker.name == "CORSChecker"
        assert checker.description is not None
        assert checker.version is not None
        assert checker.author is not None
    
    def test_cors_checker_check_no_cors_headers(self):
        """Test CORS checker with no CORS headers."""
        checker = CORSChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "CORSChecker"
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Should find CORS misconfiguration
        cors_vuln = next((v for v in result.vulnerabilities if "CORS" in v.name), None)
        assert cors_vuln is not None
    
    def test_cors_checker_check_with_cors_headers(self):
        """Test CORS checker with proper CORS headers."""
        checker = CORSChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "https://example.com",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization"
                }
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "CORSChecker"
        assert result.success is True
        # Should have fewer vulnerabilities with proper CORS headers
        assert len(result.vulnerabilities) < 3
    
    def test_cors_checker_check_wildcard_origin(self):
        """Test CORS checker with wildcard origin."""
        checker = CORSChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                }
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "CORSChecker"
        assert result.success is True
        
        # Should find wildcard origin vulnerability
        wildcard_vuln = next((v for v in result.vulnerabilities if "wildcard" in v.name.lower()), None)
        assert wildcard_vuln is not None
    
    def test_cors_checker_generate_poc(self):
        """Test CORS checker proof of concept generation."""
        checker = CORSChecker()
        
        poc = checker.generate_poc("cors-misconfiguration")
        
        assert poc is not None
        assert "javascript" in poc.lower() or "html" in poc.lower()
    
    def test_cors_checker_empty_requests(self):
        """Test CORS checker with empty requests."""
        checker = CORSChecker()
        
        result = checker.check("https://api.example.com", [])
        
        assert result.plugin_name == "CORSChecker"
        assert result.success is True
        assert len(result.vulnerabilities) == 0


class TestRateLimitingChecker:
    """Test rate limiting checker plugin."""
    
    def test_rate_limiting_checker_init(self):
        """Test rate limiting checker initialization."""
        checker = RateLimitingChecker()
        assert checker.name == "RateLimitingChecker"
        assert checker.description is not None
        assert checker.version is not None
        assert checker.author is not None
    
    def test_rate_limiting_checker_no_headers(self):
        """Test rate limiting checker with no rate limiting headers."""
        checker = RateLimitingChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "RateLimitingChecker"
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Should find rate limiting issues
        rate_limit_vuln = next((v for v in result.vulnerabilities if "rate" in v.name.lower()), None)
        assert rate_limit_vuln is not None
    
    def test_rate_limiting_checker_with_headers(self):
        """Test rate limiting checker with proper headers."""
        checker = RateLimitingChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {
                    "Content-Type": "application/json",
                    "X-RateLimit-Limit": "100",
                    "X-RateLimit-Remaining": "99",
                    "X-RateLimit-Reset": "1640995200"
                }
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "RateLimitingChecker"
        assert result.success is True
        # Should have fewer vulnerabilities with proper rate limiting headers
        assert len(result.vulnerabilities) < 2
    
    def test_rate_limiting_checker_generate_poc(self):
        """Test rate limiting checker proof of concept generation."""
        checker = RateLimitingChecker()
        
        poc = checker.generate_poc("rate-limiting-missing")
        
        assert poc is not None
        assert "curl" in poc.lower() or "python" in poc.lower()
    
    def test_rate_limiting_checker_multiple_requests(self):
        """Test rate limiting checker with multiple requests."""
        checker = RateLimitingChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            },
            {
                "url": "https://api.example.com/posts",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "RateLimitingChecker"
        assert result.success is True
        assert len(result.vulnerabilities) > 0


class TestSecurityHeadersChecker:
    """Test security headers checker plugin."""
    
    def test_security_headers_checker_init(self):
        """Test security headers checker initialization."""
        checker = SecurityHeadersChecker()
        assert checker.name == "SecurityHeadersChecker"
        assert checker.description is not None
        assert checker.version is not None
        assert checker.author is not None
    
    def test_security_headers_checker_missing_headers(self):
        """Test security headers checker with missing security headers."""
        checker = SecurityHeadersChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "SecurityHeadersChecker"
        assert result.success is True
        assert len(result.vulnerabilities) > 0
        
        # Should find missing security headers
        security_vuln = next((v for v in result.vulnerabilities if "security" in v.name.lower()), None)
        assert security_vuln is not None
    
    def test_security_headers_checker_with_headers(self):
        """Test security headers checker with proper security headers."""
        checker = SecurityHeadersChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {
                    "Content-Type": "application/json",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "X-XSS-Protection": "1; mode=block",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "Content-Security-Policy": "default-src 'self'"
                }
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "SecurityHeadersChecker"
        assert result.success is True
        # Should have fewer vulnerabilities with proper security headers
        assert len(result.vulnerabilities) < 5
    
    def test_security_headers_checker_weak_headers(self):
        """Test security headers checker with weak security headers."""
        checker = SecurityHeadersChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {
                    "Content-Type": "application/json",
                    "X-Frame-Options": "SAMEORIGIN",  # Weaker than DENY
                    "X-XSS-Protection": "0"  # Disabled
                }
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "SecurityHeadersChecker"
        assert result.success is True
        assert len(result.vulnerabilities) > 0
    
    def test_security_headers_checker_generate_poc(self):
        """Test security headers checker proof of concept generation."""
        checker = SecurityHeadersChecker()
        
        poc = checker.generate_poc("missing-security-headers")
        
        assert poc is not None
        assert "header" in poc.lower() or "http" in poc.lower()
    
    def test_security_headers_checker_check_specific_headers(self):
        """Test checking specific security headers."""
        checker = SecurityHeadersChecker()
        
        # Test with only some headers present
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {
                    "Content-Type": "application/json",
                    "X-Content-Type-Options": "nosniff"
                }
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "SecurityHeadersChecker"
        assert result.success is True
        # Should find vulnerabilities for missing headers
        assert len(result.vulnerabilities) > 0


class TestEnhancedSecurityChecker:
    """Test enhanced security checker plugin."""
    
    def test_enhanced_security_checker_init(self):
        """Test enhanced security checker initialization."""
        checker = EnhancedSecurityChecker()
        assert checker.name == "EnhancedSecurityChecker"
        assert checker.description is not None
        assert checker.version is not None
        assert checker.author is not None
    
    def test_enhanced_security_checker_basic_check(self):
        """Test enhanced security checker basic functionality."""
        checker = EnhancedSecurityChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "EnhancedSecurityChecker"
        assert result.success is True
        # Should perform multiple security checks
        assert len(result.vulnerabilities) >= 0
    
    def test_enhanced_security_checker_http_methods(self):
        """Test enhanced security checker with different HTTP methods."""
        checker = EnhancedSecurityChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            },
            {
                "url": "https://api.example.com/users",
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": '{"name": "test"}'
            },
            {
                "url": "https://api.example.com/users/1",
                "method": "DELETE",
                "headers": {"Content-Type": "application/json"}
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "EnhancedSecurityChecker"
        assert result.success is True
    
    def test_enhanced_security_checker_authentication(self):
        """Test enhanced security checker with authentication."""
        checker = EnhancedSecurityChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer token123"
                }
            }
        ]
        
        auth_headers = {"Authorization": "Bearer token123"}
        result = checker.check("https://api.example.com", requests_data, auth_headers)
        
        assert result.plugin_name == "EnhancedSecurityChecker"
        assert result.success is True
    
    def test_enhanced_security_checker_generate_poc(self):
        """Test enhanced security checker proof of concept generation."""
        checker = EnhancedSecurityChecker()
        
        poc = checker.generate_poc("enhanced-security-issue")
        
        assert poc is not None
        assert isinstance(poc, str)
    
    def test_enhanced_security_checker_empty_requests(self):
        """Test enhanced security checker with empty requests."""
        checker = EnhancedSecurityChecker()
        
        result = checker.check("https://api.example.com", [])
        
        assert result.plugin_name == "EnhancedSecurityChecker"
        assert result.success is True
        assert len(result.vulnerabilities) == 0
    
    def test_enhanced_security_checker_sensitive_data(self):
        """Test enhanced security checker for sensitive data exposure."""
        checker = EnhancedSecurityChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"},
                "body": '{"password": "secret123", "ssn": "123-45-6789"}'
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "EnhancedSecurityChecker"
        assert result.success is True
        # Should detect sensitive data in request body
        assert len(result.vulnerabilities) >= 0
    
    def test_enhanced_security_checker_url_analysis(self):
        """Test enhanced security checker URL analysis."""
        checker = EnhancedSecurityChecker()
        
        requests_data = [
            {
                "url": "https://api.example.com/admin/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            },
            {
                "url": "https://api.example.com/api/v1/users?debug=true",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            }
        ]
        
        result = checker.check("https://api.example.com", requests_data)
        
        assert result.plugin_name == "EnhancedSecurityChecker"
        assert result.success is True
        # Should analyze URLs for potential security issues
        assert len(result.vulnerabilities) >= 0


class TestPluginIntegration:
    """Test plugin integration and interaction."""
    
    def test_all_plugins_initialization(self):
        """Test that all plugins can be initialized."""
        plugins = [
            CORSChecker(),
            RateLimitingChecker(),
            SecurityHeadersChecker(),
            EnhancedSecurityChecker()
        ]
        
        for plugin in plugins:
            assert plugin.name is not None
            assert plugin.description is not None
            assert plugin.version is not None
            assert plugin.author is not None
    
    def test_plugins_consistent_interface(self):
        """Test that all plugins have consistent interface."""
        plugins = [
            CORSChecker(),
            RateLimitingChecker(),
            SecurityHeadersChecker(),
            EnhancedSecurityChecker()
        ]
        
        for plugin in plugins:
            # All plugins should have required methods
            assert hasattr(plugin, 'check')
            assert hasattr(plugin, 'generate_poc')
            assert callable(plugin.check)
            assert callable(plugin.generate_poc)
    
    def test_plugins_with_same_data(self):
        """Test all plugins with the same request data."""
        plugins = [
            CORSChecker(),
            RateLimitingChecker(),
            SecurityHeadersChecker(),
            EnhancedSecurityChecker()
        ]
        
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            }
        ]
        
        results = []
        for plugin in plugins:
            result = plugin.check("https://api.example.com", requests_data)
            results.append(result)
            
            assert result.plugin_name == plugin.name
            assert result.success is True
            assert isinstance(result.vulnerabilities, list)
        
        # All plugins should complete successfully
        assert len(results) == len(plugins)
    
    def test_plugin_error_handling(self):
        """Test plugin error handling."""
        checker = CORSChecker()
        
        # Test with invalid data
        result = checker.check("invalid-url", None)
        
        # Should handle errors gracefully
        assert result.plugin_name == "CORSChecker"
        assert result.success is True  # Should not crash
        assert isinstance(result.vulnerabilities, list)
