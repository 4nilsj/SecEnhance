#!/usr/bin/env python3
"""
GraphQL Injection BCheck
Detects GraphQL vulnerabilities including introspection and field injection
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.net import URL
import re
import json

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("GraphQL Injection BCheck")
        callbacks.registerScannerCheck(GraphQLInjectionCheck(callbacks, callbacks.getHelpers()))

class GraphQLInjectionCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._graphql_patterns = [
            r'__schema',
            r'__type',
            r'queryType',
            r'mutationType',
            r'GraphQL',
            r'graphql'
        ]
        self._introspection_payloads = [
            '{"query":"query{__schema{types{name}}}}"}',
            '{"query":"query{__type(name:\\"User\\"){name,fields{name}}}}"}',
            '{"query":"query{__schema{queryType{name}mutationType{name}subscriptionType{name}}}}"}'
        ]
        self._field_injection_payloads = [
            '{"query":"query{user(id:1){id,name,password}}"}',
            '{"query":"query{user(id:1){id,name,email,admin}}"}',
            '{"query":"query{user(id:1){id,name,ssn,credit_card}}"}'
        ]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scan for GraphQL vulnerabilities"""
        issues = []
        
        # Check if response contains GraphQL patterns
        response = baseRequestResponse.getResponse()
        response_str = self._helpers.bytesToString(response)
        
        for pattern in self._graphql_patterns:
            if re.search(pattern, response_str, re.IGNORECASE):
                issues.append(self._create_issue(
                    baseRequestResponse,
                    "GraphQL Endpoint Detected",
                    f"GraphQL endpoint detected with pattern: {pattern}",
                    "Medium"
                ))
                break
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scan for GraphQL vulnerabilities"""
        issues = []
        
        # Test for GraphQL introspection
        for payload in self._introspection_payloads:
            test_request = self._build_test_request(baseRequestResponse, insertionPoint, payload)
            test_response = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), test_request
            )
            
            if self._is_introspection_successful(test_response):
                issues.append(self._create_issue(
                    baseRequestResponse,
                    "GraphQL Introspection Enabled",
                    "GraphQL introspection is enabled, revealing schema information",
                    "Medium"
                ))
                break
        
        # Test for field injection
        for payload in self._field_injection_payloads:
            test_request = self._build_test_request(baseRequestResponse, insertionPoint, payload)
            test_response = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), test_request
            )
            
            if self._is_field_injection_successful(test_response):
                issues.append(self._create_issue(
                    baseRequestResponse,
                    "GraphQL Field Injection",
                    "Sensitive fields accessible through GraphQL",
                    "High"
                ))
                break
        
        return issues

    def _build_test_request(self, baseRequestResponse, insertionPoint, payload):
        """Build test request with payload"""
        request = baseRequestResponse.getRequest()
        payload_bytes = self._helpers.stringToBytes(payload)
        return insertionPoint.buildRequest(payload_bytes)

    def _is_introspection_successful(self, response):
        """Check if GraphQL introspection was successful"""
        response_str = self._helpers.bytesToString(response.getResponse())
        return any(pattern in response_str for pattern in ['__schema', '__type', 'queryType'])

    def _is_field_injection_successful(self, response):
        """Check if field injection was successful"""
        response_str = self._helpers.bytesToString(response.getResponse())
        sensitive_fields = ['password', 'ssn', 'credit_card', 'admin']
        return any(field in response_str.lower() for field in sensitive_fields)

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
