#!/usr/bin/env python3
"""
GraphQL Security BCheck for Burp Suite
Detects GraphQL vulnerabilities and misconfigurations
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
        callbacks.setExtensionName("GraphQL Security BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(GraphQLCheck(callbacks, self._helpers))

class GraphQLCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "GraphQL Security Vulnerability"
        
        # GraphQL test payloads
        self.graphql_payloads = {
            'introspection_queries': [
                '{"query":"query{__schema{types{name,fields{name}}}}"}',
                '{"query":"query{__type(name:\\"User\\"){name,fields{name,type{name}}}}"}',
                '{"query":"query{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}'
            ],
            'field_suggestions': [
                '{"query":"query{__type(name:\\"Query\\"){fields{name}}}"}',
                '{"query":"query{__type(name:\\"Mutation\\"){fields{name}}}"}',
                '{"query":"query{__type(name:\\"Subscription\\"){fields{name}}}"}'
            ],
            'batch_queries': [
                '[{"query":"query{user{id}}"},{"query":"query{admin{id}}"},{"query":"query{config{secret}}}]',
                '[{"query":"query{__schema{types{name}}}"},{"query":"query{user{id}}}]'
            ],
            'nested_queries': [
                '{"query":"query{user{id name email posts{id title content comments{id text user{id name}}}}}"}',
                '{"query":"query{users{id name email posts{id title content comments{id text user{id name}}}}}"}'
            ]
        }
        
        # GraphQL detection patterns
        self.graphql_indicators = [
            r"__schema",
            r"__type",
            r"__typename",
            r"GraphQL",
            r"graphql",
            r"query",
            r"mutation",
            r"subscription"
        ]
        
        # Compile regex patterns
        self.graphql_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.graphql_indicators]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for GraphQL indicators"""
        issues = []
        
        # Check for GraphQL endpoints and queries
        request = baseRequestResponse.getRequest()
        request_str = self._helpers.bytesToString(request)
        
        response = baseRequestResponse.getResponse()
        response_str = self._helpers.bytesToString(response)
        
        # Look for GraphQL indicators
        for pattern in self.graphql_regex:
            if pattern.search(request_str) or pattern.search(response_str):
                issues.append(GraphQLIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [baseRequestResponse],
                    "GraphQL Endpoint Detected",
                    "Found GraphQL endpoint which should be tested for security vulnerabilities",
                    "Medium",
                    "Low"
                ))
                break
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for GraphQL vulnerabilities"""
        issues = []
        
        # Get the original request analysis
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        headers = request_info.getHeaders()
        
        # Test different GraphQL payloads
        for payload_type, payloads in self.graphql_payloads.items():
            for payload in payloads:
                # Create modified request with the GraphQL payload
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
                    
                    # Check for GraphQL vulnerabilities
                    if payload_type == 'introspection_queries' and "__schema" in response_str:
                        issues.append(GraphQLIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse, check_request_response],
                            "GraphQL Introspection Enabled",
                            "GraphQL introspection is enabled, exposing schema information",
                            "High",
                            "High"
                        ))
                    
                    if payload_type == 'field_suggestions' and "fields" in response_str:
                        issues.append(GraphQLIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse, check_request_response],
                            "GraphQL Field Suggestions",
                            "GraphQL field suggestions are enabled, potentially exposing sensitive information",
                            "Medium",
                            "Medium"
                        ))
                    
                    if payload_type == 'batch_queries' and "HTTP/1.1 200" in response_str:
                        issues.append(GraphQLIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse, check_request_response],
                            "GraphQL Batch Queries",
                            "GraphQL batch queries are allowed, potentially enabling DoS attacks",
                            "Medium",
                            "Medium"
                        ))
                    
                    if payload_type == 'nested_queries' and "HTTP/1.1 200" in response_str:
                        issues.append(GraphQLIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse, check_request_response],
                            "GraphQL Nested Queries",
                            "GraphQL nested queries are allowed, potentially enabling DoS attacks",
                            "Medium",
                            "Medium"
                        ))
        
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Consolidate duplicate issues"""
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0

class GraphQLIssue(IScanIssue):
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
        return "GraphQL vulnerabilities can expose sensitive schema information, enable DoS attacks, or allow unauthorized access to data."

    def getRemediationBackground(self):
        return "To prevent GraphQL vulnerabilities, disable introspection in production, implement proper authentication, and use query depth limiting."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Disable GraphQL introspection in production, implement proper authentication and authorization, use query depth limiting, and validate all inputs."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
