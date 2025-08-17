#!/usr/bin/env python3
"""
JWT Security BCheck for Burp Suite
Detects JWT vulnerabilities and misconfigurations
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
        callbacks.setExtensionName("JWT Security BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(JWTCheck(callbacks, self._helpers))

class JWTCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "JWT Security Vulnerability"
        
        # JWT test payloads
        self.jwt_payloads = {
            'none_algorithm': [
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE1MTYyMzkwMjJ9."
            ],
            'weak_secrets': [
                "secret",
                "password",
                "123456",
                "admin",
                "test",
                "key",
                "jwt_secret",
                "private_key"
            ],
            'modified_payloads': [
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            ]
        }
        
        # JWT detection patterns
        self.jwt_indicators = [
            r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            r"Authorization: Bearer",
            r"JWT",
            r"jwt",
            r"token"
        ]
        
        # Compile regex patterns
        self.jwt_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.jwt_indicators]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for JWT indicators"""
        issues = []
        
        # Check for JWT tokens in requests and responses
        request = baseRequestResponse.getRequest()
        request_str = self._helpers.bytesToString(request)
        
        response = baseRequestResponse.getResponse()
        response_str = self._helpers.bytesToString(response)
        
        # Look for JWT tokens
        for pattern in self.jwt_regex:
            if pattern.search(request_str) or pattern.search(response_str):
                issues.append(JWTIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [baseRequestResponse],
                    "JWT Token Detected",
                    "Found JWT token in request/response which should be validated for security",
                    "Medium",
                    "Low"
                ))
                break
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for JWT vulnerabilities"""
        issues = []
        
        # Get the original request analysis
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        headers = request_info.getHeaders()
        
        # Test different JWT payloads
        for payload_type, payloads in self.jwt_payloads.items():
            for payload in payloads:
                # Create modified request with the JWT payload
                modified_headers = list(headers)
                
                # Replace or add Authorization header
                auth_header_found = False
                for i, header in enumerate(modified_headers):
                    if header.startswith("Authorization:"):
                        modified_headers[i] = f"Authorization: Bearer {payload}"
                        auth_header_found = True
                        break
                
                if not auth_header_found:
                    modified_headers.append(f"Authorization: Bearer {payload}")
                
                modified_request = self._helpers.buildHttpMessage(
                    modified_headers,
                    baseRequestResponse.getRequest()[request_info.getBodyOffset():]
                )
                
                check_request_response = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    modified_request
                )
                
                if check_request_response:
                    response = check_request_response.getResponse()
                    response_str = self._helpers.bytesToString(response)
                    
                    # Check for JWT vulnerabilities
                    if payload_type == 'none_algorithm' and "HTTP/1.1 200" in response_str:
                        issues.append(JWTIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse, check_request_response],
                            "JWT None Algorithm Vulnerability",
                            "JWT none algorithm vulnerability detected - token accepted without signature verification",
                            "Critical",
                            "High"
                        ))
                    
                    if payload_type == 'weak_secrets' and "HTTP/1.1 200" in response_str:
                        issues.append(JWTIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse, check_request_response],
                            "JWT Weak Secret",
                            f"JWT weak secret vulnerability detected with secret: {payload}",
                            "High",
                            "Medium"
                        ))
        
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Consolidate duplicate issues"""
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0

class JWTIssue(IScanIssue):
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
        return "JWT (JSON Web Token) vulnerabilities can allow attackers to forge tokens, bypass authentication, or access unauthorized resources."

    def getRemediationBackground(self):
        return "To prevent JWT vulnerabilities, use strong algorithms, secure secrets, validate tokens properly, and implement proper key management."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Use strong JWT algorithms (RS256, ES256), implement secure secret management, validate all token claims, and use short token expiration times."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
