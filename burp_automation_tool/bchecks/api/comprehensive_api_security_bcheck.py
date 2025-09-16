#!/usr/bin/env python3
"""
Comprehensive API Security BCheck for Burp Suite
Detects multiple API security vulnerabilities in a single check
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.net import URL
import re
import json

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Comprehensive API Security BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(ComprehensiveAPISecurityCheck(callbacks, self._helpers))

class ComprehensiveAPISecurityCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "Comprehensive API Security Vulnerability"
        
        # Comprehensive test payloads
        self.security_payloads = {
            'authentication_bypass': [
                '{"token": "null"}',
                '{"token": ""}',
                '{"token": "undefined"}',
                '{"token": "admin"}',
                '{"token": "test"}',
                '{"token": "123456"}',
                '{"token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."}'
            ],
            'authorization_bypass': [
                '{"role": "admin"}',
                '{"role": "superuser"}',
                '{"role": "root"}',
                '{"role": "administrator"}',
                '{"user_id": "1"}',
                '{"user_id": "admin"}',
                '{"user_id": "0"}'
            ],
            'injection_payloads': [
                '{"query": "1\' OR \'1\'=\'1"}',
                '{"query": "1; DROP TABLE users;"}',
                '{"query": "1 UNION SELECT * FROM users"}',
                '{"query": "<script>alert(\'XSS\')</script>"}',
                '{"query": "javascript:alert(\'XSS\')"}',
                '{"query": "{{7*7}}"}',
                '{"query": "${7*7}"}'
            ],
            'ssrf_payloads': [
                '{"url": "http://127.0.0.1"}',
                '{"url": "http://localhost"}',
                '{"url": "http://169.254.169.254"}',
                '{"url": "http://metadata.google.internal"}',
                '{"url": "file:///etc/passwd"}',
                '{"url": "gopher://127.0.0.1:25/_HELO"}'
            ],
            'mass_assignment': [
                '{"id": 1, "role": "admin", "is_admin": true}',
                '{"id": 1, "role": "admin", "permissions": "all"}',
                '{"id": 1, "role": "admin", "access_level": "root"}',
                '{"id": 1, "role": "admin", "is_verified": true}'
            ],
            'business_logic': [
                '{"amount": -1}',
                '{"amount": 0}',
                '{"amount": 999999999}',
                '{"quantity": -1}',
                '{"quantity": 0}',
                '{"quantity": 999999999}',
                '{"price": -1}',
                '{"price": 0}'
            ]
        }
        
        # Detection patterns
        self.security_indicators = {
            'authentication': [
                r"unauthorized",
                r"forbidden",
                r"access denied",
                r"authentication failed",
                r"invalid token",
                r"token expired"
            ],
            'authorization': [
                r"insufficient privileges",
                r"permission denied",
                r"not authorized",
                r"access restricted"
            ],
            'injection': [
                r"sql.*error",
                r"mysql.*error",
                r"postgresql.*error",
                r"oracle.*error",
                r"microsoft.*error",
                r"stack trace",
                r"exception"
            ],
            'ssrf': [
                r"root:",
                r"localhost",
                r"127\.0\.0\.1",
                r"internal",
                r"private",
                r"metadata"
            ],
            'business_logic': [
                r"invalid.*amount",
                r"invalid.*quantity",
                r"invalid.*price",
                r"negative.*value",
                r"zero.*value"
            ]
        }
        
        # Compile regex patterns
        self.compiled_patterns = {}
        for category, patterns in self.security_indicators.items():
            self.compiled_patterns[category] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for security indicators"""
        issues = []
        
        # Check for API endpoints
        request = baseRequestResponse.getRequest()
        request_str = self._helpers.bytesToString(request)
        
        # Look for API indicators
        api_indicators = ['/api/', '/rest/', '/graphql', '/swagger', '/openapi']
        for indicator in api_indicators:
            if indicator in request_str:
                issues.append(ComprehensiveAPISecurityIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [baseRequestResponse],
                    "API Endpoint Detected",
                    f"Found API endpoint with indicator: {indicator}",
                    "Medium",
                    "Low"
                ))
                break
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for comprehensive API security vulnerabilities"""
        issues = []
        
        # Get the original request analysis
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        headers = request_info.getHeaders()
        
        # Test different security payloads
        for payload_type, payloads in self.security_payloads.items():
            for payload in payloads:
                # Create modified request with the payload
                modified_request = self._helpers.buildHttpMessage(
                    headers,
                    payload.encode('utf-8')
                )
                
                check_request_response = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    modified_request
                )
                
                if check_request_response:
                    response = check_request_response.getResponse()
                    response_str = self._helpers.bytesToString(response)
                    
                    # Check for security indicators
                    for category, patterns in self.compiled_patterns.items():
                        for pattern in patterns:
                            if pattern.search(response_str):
                                issues.append(ComprehensiveAPISecurityIssue(
                                    baseRequestResponse.getHttpService(),
                                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    [baseRequestResponse, check_request_response],
                                    f"API Security - {payload_type.replace('_', ' ').title()}",
                                    f"API security vulnerability detected with {payload_type} payload: {payload[:50]}...",
                                    "High",
                                    "Medium"
                                ))
                                break
        
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Consolidate duplicate issues"""
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0

class ComprehensiveAPISecurityIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return "Comprehensive API security vulnerabilities can include authentication bypass, authorization issues, injection attacks, SSRF, mass assignment, and business logic flaws."

    def getRemediationBackground(self):
        return "To prevent API security vulnerabilities, implement proper authentication, authorization, input validation, and business logic validation."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Implement proper authentication and authorization, validate all inputs, use parameterized queries, implement rate limiting, and validate business logic."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

