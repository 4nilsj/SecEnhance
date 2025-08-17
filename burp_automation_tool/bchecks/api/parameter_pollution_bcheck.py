#!/usr/bin/env python3
"""
Parameter Pollution BCheck for Burp Suite
Detects HTTP parameter pollution vulnerabilities
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
        callbacks.setExtensionName("Parameter Pollution BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(ParameterPollutionCheck(callbacks, self._helpers))

class ParameterPollutionCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "HTTP Parameter Pollution"
        
        # Parameter pollution test payloads
        self.pollution_payloads = {
            'duplicate_params': [
                "param=value1&param=value2",
                "id=1&id=2",
                "user=admin&user=guest",
                "action=read&action=write"
            ],
            'conflicting_params': [
                "param=value1&param=value2",
                "id=1&id=999",
                "user=admin&user=test",
                "role=user&role=admin"
            ],
            'array_params': [
                "param[]=value1&param[]=value2",
                "id[]=1&id[]=2",
                "user[]=admin&user[]=guest"
            ]
        }
        
        # Detection patterns
        self.pollution_indicators = [
            r"HTTP/1\.1 200 OK",
            r"HTTP/1\.1 302 Found",
            r"HTTP/1\.1 400 Bad Request",
            r"HTTP/1\.1 500 Internal Server Error"
        ]
        
        # Compile regex patterns
        self.pollution_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.pollution_indicators]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for parameter pollution indicators"""
        issues = []
        
        # Check for duplicate parameters in requests
        request = baseRequestResponse.getRequest()
        request_str = self._helpers.bytesToString(request)
        
        # Look for duplicate parameters
        import re
        param_pattern = r'(\w+)=[^&]*'
        params = re.findall(param_pattern, request_str)
        
        if len(params) != len(set(params)):
            issues.append(ParameterPollutionIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [baseRequestResponse],
                "Potential Parameter Pollution - Duplicate Parameters",
                "Found duplicate parameters in request which may indicate parameter pollution",
                "Medium",
                "Low"
            ))
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for parameter pollution vulnerabilities"""
        issues = []
        
        # Get the original request analysis
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        headers = request_info.getHeaders()
        
        # Test different parameter pollution payloads
        for payload_type, payloads in self.pollution_payloads.items():
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
                    
                    # Check for pollution indicators
                    for pattern in self.pollution_regex:
                        if pattern.search(response_str):
                            issues.append(ParameterPollutionIssue(
                                baseRequestResponse.getHttpService(),
                                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                [baseRequestResponse, check_request_response],
                                f"Parameter Pollution - {payload_type.replace('_', ' ').title()}",
                                f"Parameter pollution vulnerability detected with {payload_type} payload: {payload}",
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

class ParameterPollutionIssue(IScanIssue):
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
        return "HTTP Parameter Pollution occurs when an attacker sends multiple values for the same parameter, potentially causing the application to behave unexpectedly."

    def getRemediationBackground(self):
        return "To prevent parameter pollution, implement proper parameter validation and handle multiple values for the same parameter consistently."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Implement strict parameter validation, handle multiple values consistently, and use parameter allowlists."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
