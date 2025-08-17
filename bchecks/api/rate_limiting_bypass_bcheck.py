#!/usr/bin/env python3
"""
Rate Limiting Bypass BCheck
Detects API rate limiting bypass vulnerabilities
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.net import URL
import re
import json

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Rate Limiting Bypass BCheck")
        callbacks.registerScannerCheck(RateLimitingBypassCheck(callbacks, callbacks.getHelpers()))

class RateLimitingBypassCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'RateLimit-Limit',
            'RateLimit-Remaining',
            'RateLimit-Reset'
        ]
        self._bypass_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Client-IP',
            'CF-Connecting-IP',
            'True-Client-IP'
        ]
        self._bypass_payloads = [
            '127.0.0.1',
            'localhost',
            '0.0.0.0',
            '::1',
            '192.168.1.1',
            '10.0.0.1'
        ]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scan for rate limiting headers"""
        issues = []
        
        response = baseRequestResponse.getResponse()
        response_info = self._helpers.analyzeResponse(response)
        headers = response_info.getHeaders()
        
        # Check for rate limiting headers
        rate_limit_detected = False
        for header in headers:
            for rate_header in self._rate_limit_headers:
                if rate_header.lower() in header.lower():
                    rate_limit_detected = True
                    break
            if rate_limit_detected:
                break
        
        if rate_limit_detected:
            issues.append(self._create_issue(
                baseRequestResponse,
                "Rate Limiting Detected",
                "API rate limiting headers detected",
                "Info"
            ))
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scan for rate limiting bypass"""
        issues = []
        
        # Test header-based bypass
        for header in self._bypass_headers:
            for payload in self._bypass_payloads:
                test_request = self._build_test_request_with_header(
                    baseRequestResponse, insertionPoint, header, payload
                )
                test_response = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), test_request
                )
                
                if self._is_bypass_successful(test_response):
                    issues.append(self._create_issue(
                        baseRequestResponse,
                        "Rate Limiting Bypass",
                        f"Rate limiting bypass successful using {header}: {payload}",
                        "High"
                    ))
                    break
        
        # Test parameter pollution bypass
        pollution_payloads = [
            'X-Forwarded-For=127.0.0.1&X-Forwarded-For=192.168.1.1',
            'X-Real-IP=localhost&X-Real-IP=10.0.0.1'
        ]
        
        for payload in pollution_payloads:
            test_request = self._build_test_request(baseRequestResponse, insertionPoint, payload)
            test_response = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), test_request
            )
            
            if self._is_bypass_successful(test_response):
                issues.append(self._create_issue(
                    baseRequestResponse,
                    "Rate Limiting Parameter Pollution",
                    f"Rate limiting bypass using parameter pollution: {payload}",
                    "High"
                ))
                break
        
        return issues

    def _build_test_request(self, baseRequestResponse, insertionPoint, payload):
        """Build test request with payload"""
        request = baseRequestResponse.getRequest()
        payload_bytes = self._helpers.stringToBytes(payload)
        return insertionPoint.buildRequest(payload_bytes)

    def _build_test_request_with_header(self, baseRequestResponse, insertionPoint, header, value):
        """Build test request with custom header"""
        request = baseRequestResponse.getRequest()
        request_info = self._helpers.analyzeRequest(request)
        headers = list(request_info.getHeaders())
        
        # Add or modify the header
        header_added = False
        for i, h in enumerate(headers):
            if h.lower().startswith(header.lower()):
                headers[i] = f"{header}: {value}"
                header_added = True
                break
        
        if not header_added:
            headers.append(f"{header}: {value}")
        
        # Rebuild request
        body = request[request_info.getBodyOffset():]
        return self._helpers.buildHttpMessage(headers, body)

    def _is_bypass_successful(self, response):
        """Check if rate limiting bypass was successful"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for indicators of successful bypass
        success_indicators = [
            'rate limit exceeded',
            'too many requests',
            '429',
            'quota exceeded'
        ]
        
        # If we don't see rate limiting errors, bypass might be successful
        return not any(indicator in response_str.lower() for indicator in success_indicators)

    def _create_issue(self, baseRequestResponse, name, detail, severity):
        """Create a scan issue"""
        return CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [baseRequestResponse],
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
        return self._severity

    def getConfidence(self):
        return "Medium"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
