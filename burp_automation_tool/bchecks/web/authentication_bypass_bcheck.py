#!/usr/bin/env python3
"""
Authentication Bypass BCheck for Burp Suite
Detects various authentication and authorization bypass vulnerabilities
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.net import URL
import re
import base64

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Authentication Bypass BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(AuthBypassCheck(callbacks, self._helpers))

class AuthBypassCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "Authentication Bypass"
        
        # Authentication bypass payloads
        self.auth_bypass_payloads = {
            'idor': [
                "1",
                "2",
                "10",
                "100",
                "999",
                "9999",
                "admin",
                "administrator",
                "root",
                "superuser",
                "test",
                "demo",
                "guest",
                "anonymous"
            ],
            'jwt_tampering': [
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYxNjI0NzQ0MCwiZXhwIjoxNjE2MjUxMDQwfQ.",
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYxNjI0NzQ0MCwiZXhwIjoxNjE2MjUxMDQwfQ.signature",
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYxNjI0NzQ0MCwiZXhwIjoxNjE2MjUxMDQwfQ.eyJzdWIiOiJhZG1pbiJ9"
            ],
            'session_manipulation': [
                "admin",
                "administrator",
                "root",
                "superuser",
                "true",
                "1",
                "yes",
                "authenticated",
                "logged_in",
                "authorized"
            ],
            'header_bypass': [
                "X-Forwarded-For: 127.0.0.1",
                "X-Forwarded-For: localhost",
                "X-Forwarded-For: 0.0.0.0",
                "X-Forwarded-For: ::1",
                "X-Original-URL: /admin",
                "X-Rewrite-URL: /admin",
                "X-Custom-IP-Authorization: 127.0.0.1",
                "X-Originating-IP: 127.0.0.1",
                "X-Remote-IP: 127.0.0.1",
                "X-Remote-Addr: 127.0.0.1",
                "X-Client-IP: 127.0.0.1",
                "X-Host: 127.0.0.1",
                "X-Forwared-Host: 127.0.0.1"
            ],
            'parameter_pollution': [
                "admin=true",
                "isAdmin=1",
                "role=admin",
                "user=admin",
                "authenticated=yes",
                "logged_in=true",
                "authorized=1",
                "privileged=yes",
                "root=1",
                "superuser=true"
            ]
        }
        
        # Authentication bypass patterns
        self.auth_bypass_patterns = [
            r"admin",
            r"administrator",
            r"root",
            r"superuser",
            r"authenticated",
            r"authorized",
            r"logged_in",
            r"privileged",
            r"role\s*=",
            r"user\s*=",
            r"admin\s*=",
            r"auth\s*=",
            r"bypass",
            r"override"
        ]
        
        # Compile regex patterns
        self.auth_bypass_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.auth_bypass_patterns]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for authentication bypass indicators"""
        issues = []
        
        # Check request for auth bypass patterns
        request = baseRequestResponse.getRequest()
        request_str = self._helpers.bytesToString(request)
        
        for pattern in self.auth_bypass_regex:
            if pattern.search(request_str):
                issues.append(self._create_issue(
                    baseRequestResponse,
                    "Potential Authentication Bypass Detected",
                    f"Authentication bypass pattern detected in request: {pattern.pattern}",
                    "Medium"
                ))
                break
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for authentication bypass vulnerabilities"""
        issues = []
        
        # Test different authentication bypass techniques
        for technique, payloads in self.auth_bypass_payloads.items():
            for payload in payloads:
                # Create test request
                checkRequest = self._create_test_request(baseRequestResponse, insertionPoint, payload)
                
                # Send request and get response
                checkResponse = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest
                )
                
                if checkResponse is None:
                    continue
                
                # Analyze response for authentication bypass indicators
                if self._detect_auth_bypass(checkResponse, technique, payload):
                    issues.append(self._create_issue(
                        checkResponse,
                        f"Authentication Bypass - {technique.replace('_', ' ').title()}",
                        f"Authentication bypass vulnerability detected using {technique} technique with payload: {payload}",
                        "High"
                    ))
                    break  # Found vulnerability, move to next technique
        
        return issues

    def _create_test_request(self, baseRequestResponse, insertionPoint, payload):
        """Create a test request with the authentication bypass payload"""
        # Get the base request
        request = baseRequestResponse.getRequest()
        
        # Insert the payload
        checkRequest = insertionPoint.buildRequest(payload)
        
        return checkRequest

    def _detect_auth_bypass(self, response, technique, payload):
        """Detect authentication bypass based on response analysis"""
        if response is None:
            return False
        
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Check for authentication bypass indicators in response
        if self._has_auth_bypass_indicators(response_str, payload):
            return True
        
        # Check for specific technique indicators
        if technique == 'idor':
            return self._detect_idor(response, payload)
        elif technique == 'jwt_tampering':
            return self._detect_jwt_tampering(response, payload)
        elif technique == 'session_manipulation':
            return self._detect_session_manipulation(response, payload)
        
        return False

    def _has_auth_bypass_indicators(self, response_str, payload):
        """Check for authentication bypass indicators in response"""
        # Look for successful authentication indicators
        auth_indicators = [
            'welcome',
            'dashboard',
            'admin panel',
            'administrator',
            'management',
            'control panel',
            'settings',
            'users',
            'system',
            'configuration',
            'privileged',
            'authorized',
            'authenticated',
            'logged in',
            'access granted',
            'successful login'
        ]
        
        if any(indicator in response_str.lower() for indicator in auth_indicators):
            return True
        
        # Look for error messages that might indicate bypass
        error_indicators = [
            'access denied',
            'unauthorized',
            'forbidden',
            'insufficient privileges',
            'not authorized',
            'permission denied'
        ]
        
        # If we get a different error, it might indicate partial bypass
        if any(indicator in response_str.lower() for indicator in error_indicators):
            return False
        
        return False

    def _detect_idor(self, response, payload):
        """Detect Insecure Direct Object Reference"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for IDOR indicators
        idor_indicators = [
            'user id',
            'account id',
            'profile',
            'personal information',
            'private data',
            'confidential',
            'restricted',
            'internal'
        ]
        
        if any(indicator in response_str.lower() for indicator in idor_indicators):
            return True
        
        return False

    def _detect_jwt_tampering(self, response, payload):
        """Detect JWT tampering"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for JWT-related indicators
        jwt_indicators = [
            'jwt',
            'token',
            'bearer',
            'authorization',
            'authentication',
            'session'
        ]
        
        if any(indicator in response_str.lower() for indicator in jwt_indicators):
            return True
        
        return False

    def _detect_session_manipulation(self, response, payload):
        """Detect session manipulation"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for session-related indicators
        session_indicators = [
            'session',
            'cookie',
            'authentication',
            'authorization',
            'login',
            'user'
        ]
        
        if any(indicator in response_str.lower() for indicator in session_indicators):
            return True
        
        return False

    def _create_issue(self, requestResponse, name, detail, severity):
        """Create a scan issue"""
        return CustomScanIssue(
            requestResponse.getHttpService(),
            self._helpers.analyzeRequest(requestResponse).getUrl(),
            [requestResponse],
            name,
            detail,
            severity
        )

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        if self._severity == "High":
            return "High"
        elif self._severity == "Medium":
            return "Medium"
        elif self._severity == "Low":
            return "Low"
        else:
            return "Information"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Authentication bypass vulnerabilities allow attackers to gain unauthorized access to protected resources, potentially leading to data theft, privilege escalation, and complete system compromise."

    def getRemediationBackground(self):
        return "Implement proper authentication and authorization mechanisms, use secure session management, and validate all user inputs. Implement proper access controls and role-based permissions."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "1. Implement proper authentication mechanisms\n2. Use secure session management\n3. Implement role-based access control (RBAC)\n4. Validate and sanitize all user inputs\n5. Use secure tokens (JWT with proper signing)\n6. Implement proper authorization checks\n7. Use secure headers and cookies\n8. Regular security testing and code reviews\n9. Implement proper logging and monitoring\n10. Use web application firewalls (WAFs)"

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
