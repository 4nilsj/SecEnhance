#!/usr/bin/env python3
"""
Rate Limiting Bypass BCheck for Burp Suite
Detects rate limiting bypass vulnerabilities
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
        callbacks.setExtensionName("Rate Limiting Bypass BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(RateLimitingCheck(callbacks, self._helpers))

class RateLimitingCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "Rate Limiting Bypass"
        
        # Rate limiting bypass test payloads
        self.rate_limit_payloads = {
            'header_bypass': [
                "X-Forwarded-For: 127.0.0.1",
                "X-Real-IP: 127.0.0.1",
                "X-Client-IP: 127.0.0.1",
                "X-Remote-IP: 127.0.0.1",
                "X-Remote-Addr: 127.0.0.1",
                "X-Originating-IP: 127.0.0.1",
                "X-Forwarded: 127.0.0.1",
                "X-Forwarded-For: 192.168.1.1",
                "X-Forwarded-For: 10.0.0.1",
                "X-Forwarded-For: 172.16.0.1"
            ],
            'user_agent_bypass': [
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "User-Agent: curl/7.68.0",
                "User-Agent: PostmanRuntime/7.28.0"
            ],
            'session_bypass': [
                "Cookie: session=test123",
                "Cookie: sessionid=test123",
                "Cookie: PHPSESSID=test123",
                "Cookie: JSESSIONID=test123",
                "Cookie: ASP.NET_SessionId=test123"
            ]
        }
        
        # Rate limiting detection patterns
        self.rate_limit_indicators = [
            r"HTTP/1\.1 429 Too Many Requests",
            r"HTTP/1\.1 503 Service Unavailable",
            r"rate.*limit",
            r"too.*many.*requests",
            r"quota.*exceeded",
            r"throttle",
            r"blocked"
        ]
        
        # Compile regex patterns
        self.rate_limit_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.rate_limit_indicators]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for rate limiting indicators"""
        issues = []
        
        # Check for rate limiting headers in responses
        response = baseRequestResponse.getResponse()
        response_str = self._helpers.bytesToString(response)
        
        # Look for rate limiting indicators
        for pattern in self.rate_limit_regex:
            if pattern.search(response_str):
                issues.append(RateLimitingIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [baseRequestResponse],
                    "Rate Limiting Detected",
                    "Found rate limiting mechanism which should be tested for bypass vulnerabilities",
                    "Medium",
                    "Low"
                ))
                break
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for rate limiting bypass vulnerabilities"""
        issues = []
        
        # Get the original request analysis
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        headers = request_info.getHeaders()
        
        # Test different rate limiting bypass techniques
        for bypass_type, payloads in self.rate_limit_payloads.items():
            for payload in payloads:
                # Create modified request with the bypass payload
                modified_headers = list(headers)
                
                # Add or modify headers for bypass
                if bypass_type == 'header_bypass':
                    header_name = payload.split(':')[0]
                    header_value = payload.split(':')[1].strip()
                    
                    # Replace existing header or add new one
                    header_found = False
                    for i, header in enumerate(modified_headers):
                        if header.startswith(header_name + ":"):
                            modified_headers[i] = payload
                            header_found = True
                            break
                    
                    if not header_found:
                        modified_headers.append(payload)
                
                elif bypass_type == 'user_agent_bypass':
                    # Replace User-Agent header
                    for i, header in enumerate(modified_headers):
                        if header.startswith("User-Agent:"):
                            modified_headers[i] = payload
                            break
                
                elif bypass_type == 'session_bypass':
                    # Add session cookie
                    modified_headers.append(payload)
                
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
                    
                    # Check if bypass was successful (no rate limiting response)
                    if "HTTP/1.1 200" in response_str and "429" not in response_str:
                        issues.append(RateLimitingIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse, check_request_response],
                            f"Rate Limiting Bypass - {bypass_type.replace('_', ' ').title()}",
                            f"Rate limiting bypass vulnerability detected using {bypass_type} technique: {payload}",
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

class RateLimitingIssue(IScanIssue):
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
        return "Rate limiting bypass vulnerabilities allow attackers to exceed request limits, potentially enabling DoS attacks or brute force attempts."

    def getRemediationBackground(self):
        return "To prevent rate limiting bypass, implement proper rate limiting based on multiple factors and validate all request headers."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Implement rate limiting based on multiple factors (IP, user agent, session, etc.), validate all request headers, and use secure session management."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
