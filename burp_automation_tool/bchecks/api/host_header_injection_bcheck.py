#!/usr/bin/env python3
"""
Host Header Injection BCheck for Burp Suite
Detects Host header injection vulnerabilities and cache poisoning
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
        callbacks.setExtensionName("Host Header Injection BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(HostHeaderInjectionCheck(callbacks, self._helpers))

class HostHeaderInjectionCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "Host Header Injection"
        
        # Host header injection test payloads
        self.host_injection_payloads = {
            'cache_poisoning': [
                "evil.com",
                "attacker.com",
                "malicious.com",
                "test.com",
                "example.com",
                "localhost",
                "127.0.0.1",
                "0.0.0.0",
                "[::1]"
            ],
            'ssrf_via_host': [
                "127.0.0.1:80",
                "127.0.0.1:443",
                "127.0.0.1:8080",
                "localhost:80",
                "localhost:443",
                "localhost:8080",
                "0.0.0.0:80",
                "0.0.0.0:443"
            ],
            'auth_bypass': [
                "admin.com",
                "admin.local",
                "internal.com",
                "internal.local",
                "trusted.com",
                "trusted.local"
            ],
            'port_manipulation': [
                "example.com:80",
                "example.com:443",
                "example.com:8080",
                "example.com:3000",
                "example.com:5000"
            ]
        }
        
        # Host header injection detection patterns
        self.host_injection_indicators = [
            r"HTTP/1\.1 200 OK",
            r"HTTP/1\.1 302 Found",
            r"HTTP/1\.1 301 Moved Permanently",
            r"Location:",
            r"X-Forwarded-Host:",
            r"X-Original-URL:",
            r"X-Rewrite-URL:"
        ]
        
        # Compile regex patterns
        self.host_injection_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.host_injection_indicators]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for Host header injection indicators"""
        issues = []
        
        # Check for Host header in requests
        request = baseRequestResponse.getRequest()
        request_str = self._helpers.bytesToString(request)
        
        # Look for Host header
        if "Host:" in request_str:
            issues.append(HostHeaderInjectionIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [baseRequestResponse],
                "Host Header Detected",
                "Found Host header which should be tested for injection vulnerabilities",
                "Medium",
                "Low"
            ))
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for Host header injection vulnerabilities"""
        issues = []
        
        # Get the original request analysis
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        headers = request_info.getHeaders()
        
        # Test different Host header injection payloads
        for injection_type, payloads in self.host_injection_payloads.items():
            for payload in payloads:
                # Create modified request with the Host header payload
                modified_headers = list(headers)
                
                # Replace or add Host header
                host_header_found = False
                for i, header in enumerate(modified_headers):
                    if header.startswith("Host:"):
                        modified_headers[i] = f"Host: {payload}"
                        host_header_found = True
                        break
                
                if not host_header_found:
                    modified_headers.append(f"Host: {payload}")
                
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
                    
                    # Check for Host header injection indicators
                    for pattern in self.host_injection_regex:
                        if pattern.search(response_str):
                            issues.append(HostHeaderInjectionIssue(
                                baseRequestResponse.getHttpService(),
                                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                [baseRequestResponse, check_request_response],
                                f"Host Header Injection - {injection_type.replace('_', ' ').title()}",
                                f"Host header injection vulnerability detected with payload: {payload}",
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

class HostHeaderInjectionIssue(IScanIssue):
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
        return "Host header injection occurs when an application uses the Host header value without proper validation, potentially leading to cache poisoning, SSRF, or authentication bypass."

    def getRemediationBackground(self):
        return "To prevent Host header injection, validate and sanitize all Host header values, use allowlists for allowed hosts, and implement proper cache validation."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Implement strict Host header validation, use allowlists for allowed hosts, validate cache keys, and consider using relative URLs instead of absolute URLs."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
