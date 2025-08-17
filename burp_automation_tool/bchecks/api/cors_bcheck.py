#!/usr/bin/env python3
"""
CORS Security BCheck for Burp Suite
Detects CORS misconfigurations and security vulnerabilities
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.net import URL
import re

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("CORS Security BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(CORSCheck(callbacks, self._helpers))

class CORSCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "CORS Security Misconfiguration"
        
        # CORS test payloads
        self.cors_payloads = {
            'origin_headers': [
                "https://evil.com",
                "https://attacker.com",
                "https://malicious.com",
                "https://test.com",
                "https://example.com",
                "null",
                "https://subdomain.evil.com",
                "https://evil.com:443",
                "https://evil.com:80"
            ],
            'methods': [
                "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
                "HEAD", "TRACE", "CONNECT"
            ],
            'headers': [
                "X-Requested-With",
                "Content-Type",
                "Authorization",
                "X-Custom-Header",
                "X-API-Key",
                "X-Auth-Token"
            ]
        }
        
        # CORS detection patterns
        self.cors_indicators = [
            r"Access-Control-Allow-Origin: \*",
            r"Access-Control-Allow-Origin: null",
            r"Access-Control-Allow-Credentials: true",
            r"Access-Control-Allow-Methods: \*",
            r"Access-Control-Allow-Headers: \*",
            r"Access-Control-Expose-Headers: \*"
        ]
        
        # Compile regex patterns
        self.cors_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.cors_indicators]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for CORS misconfigurations"""
        issues = []
        
        # Check response headers for CORS misconfigurations
        response = baseRequestResponse.getResponse()
        response_str = self._helpers.bytesToString(response)
        
        # Look for dangerous CORS headers
        for pattern in self.cors_regex:
            if pattern.search(response_str):
                issues.append(CORSIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [baseRequestResponse],
                    "CORS Misconfiguration Detected",
                    f"Found potentially dangerous CORS header: {pattern.pattern}",
                    "High",
                    "Medium"
                ))
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for CORS vulnerabilities"""
        issues = []
        
        # Get the original request analysis
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        headers = request_info.getHeaders()
        
        # Test different Origin headers
        for origin in self.cors_payloads['origin_headers']:
            # Create modified request with Origin header
            modified_headers = list(headers)
            modified_headers.append(f"Origin: {origin}")
            
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
                
                # Check for CORS misconfigurations
                if f"Access-Control-Allow-Origin: {origin}" in response_str:
                    issues.append(CORSIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [baseRequestResponse, check_request_response],
                        "CORS Origin Reflection",
                        f"CORS origin reflection detected with origin: {origin}",
                        "High",
                        "Medium"
                    ))
                
                if "Access-Control-Allow-Origin: *" in response_str:
                    issues.append(CORSIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [baseRequestResponse, check_request_response],
                        "CORS Wildcard Origin",
                        "CORS wildcard origin (*) detected which allows any domain",
                        "High",
                        "High"
                    ))
        
        # Test preflight requests
        for method in self.cors_payloads['methods']:
            for header in self.cors_payloads['headers']:
                # Create OPTIONS request for preflight
                preflight_headers = [
                    "OPTIONS / HTTP/1.1",
                    "Host: " + baseRequestResponse.getHttpService().getHost(),
                    f"Origin: https://evil.com",
                    f"Access-Control-Request-Method: {method}",
                    f"Access-Control-Request-Headers: {header}",
                    "Connection: close"
                ]
                
                preflight_request = self._helpers.buildHttpMessage(
                    preflight_headers,
                    ""
                )
                
                preflight_response = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    preflight_request
                )
                
                if preflight_response:
                    response = preflight_response.getResponse()
                    response_str = self._helpers.bytesToString(response)
                    
                    # Check for dangerous preflight responses
                    if "Access-Control-Allow-Origin: *" in response_str:
                        issues.append(CORSIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse, preflight_response],
                            "CORS Preflight Wildcard",
                            f"CORS preflight wildcard origin detected for {method} method and {header} header",
                            "High",
                            "High"
                        ))
                    
                    if "Access-Control-Allow-Credentials: true" in response_str and "Access-Control-Allow-Origin: *" in response_str:
                        issues.append(CORSIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse, preflight_response],
                            "CORS Credentials with Wildcard",
                            "CORS credentials allowed with wildcard origin - critical security issue",
                            "Critical",
                            "High"
                        ))
        
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Consolidate duplicate issues"""
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0

class CORSIssue(IScanIssue):
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
        return "CORS (Cross-Origin Resource Sharing) misconfigurations can allow malicious websites to access sensitive data from other domains, leading to information disclosure and session hijacking."

    def getRemediationBackground(self):
        return "To prevent CORS vulnerabilities, implement proper origin validation, avoid wildcard origins, and carefully configure allowed methods and headers."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Configure CORS to only allow specific trusted origins, avoid using wildcard (*) origins, and implement proper validation for all CORS headers."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
