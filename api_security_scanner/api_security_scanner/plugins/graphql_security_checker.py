"""
Comprehensive GraphQL Security Checker Plugin
Advanced GraphQL vulnerability detection, query analysis, and security testing.
Covers all major GraphQL attack vectors and security best practices.
"""

import re
import json
import uuid
import time
import random
import string
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

from api_security_scanner.core.scanner_plugins import BasePlugin, PluginResult, Vulnerability, ProofOfConcept, format_http_request, format_http_response


class GraphQLSecurityChecker(BasePlugin):
    """Comprehensive GraphQL security analysis plugin covering all major attack vectors."""
    
    name = "GraphQLSecurityChecker"
    description = "Advanced GraphQL vulnerability detection, query analysis, and security testing"
    version = "1.0.0"
    author = "API Security Scanner"
    
    def __init__(self, zap=None, target=None):
        super().__init__(zap=zap, target=target)
        
        # GraphQL endpoint patterns
        self.graphql_patterns = [
            r'/graphql',
            r'/api/graphql',
            r'/v\d+/graphql',
            r'/query',
            r'/api/query',
            r'/gql',
            r'/api/gql'
        ]
        
        # GraphQL introspection query
        self.introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args {
                        ...InputValue
                    }
                }
            }
        }
        
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }
        
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }
        
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        # Common GraphQL attack payloads
        self.attack_payloads = {
            'introspection': self.introspection_query,
            'deep_query': self._generate_deep_query(),
            'alias_attack': self._generate_alias_attack(),
            'batch_query': self._generate_batch_query(),
            'fragment_attack': self._generate_fragment_attack(),
            'union_attack': self._generate_union_attack(),
            'interface_attack': self._generate_interface_attack(),
            'directive_attack': self._generate_directive_attack(),
            'subscription_attack': self._generate_subscription_attack(),
            'mutation_attack': self._generate_mutation_attack()
        }
        
        # GraphQL security patterns
        self.security_patterns = {
            'introspection_disabled': re.compile(r'__schema|__type|__typename', re.IGNORECASE),
            'query_complexity': re.compile(r'query\s+\w+', re.IGNORECASE),
            'depth_limit': re.compile(r'\{[^}]*\{[^}]*\{[^}]*\{[^}]*\{', re.IGNORECASE),
            'rate_limiting': re.compile(r'rate.?limit|throttle', re.IGNORECASE),
            'authentication': re.compile(r'auth|token|bearer|jwt', re.IGNORECASE),
            'authorization': re.compile(r'permission|role|access|grant', re.IGNORECASE)
        }
        
        # Common GraphQL vulnerabilities
        self.vulnerability_patterns = {
            'information_disclosure': [
                'password', 'secret', 'key', 'token', 'credential',
                'ssn', 'social_security', 'credit_card', 'card_number',
                'email', 'phone', 'address', 'dob', 'birth_date'
            ],
            'injection_vectors': [
                'sql', 'nosql', 'command', 'script', 'xss',
                'ldap', 'xpath', 'template', 'expression'
            ],
            'authorization_bypass': [
                'admin', 'root', 'superuser', 'moderator',
                'delete', 'update', 'create', 'modify'
            ]
        }
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Perform comprehensive GraphQL security analysis."""
        vulnerabilities = []
        
        try:
            for request in requests_data:
                url = request.get('url', '')
                method = request.get('method', 'GET')
                
                # Check if this is a GraphQL endpoint
                if self._is_graphql_endpoint(url, request):
                    self.logger.info(f"GraphQL endpoint detected: {url}")
                    
                    # Make request with authentication
                    headers = request.get('headers', {}).copy()
                    if auth_headers:
                        headers.update(auth_headers)
                    
                    response = self.make_request(url, method, headers, request.get('body') or '')
                    
                    if response:
                        # 1. Test GraphQL introspection
                        intro_vulns = self._test_introspection(url, method, headers, response)
                        vulnerabilities.extend(intro_vulns)
                        
                        # 2. Test query complexity attacks
                        complexity_vulns = self._test_query_complexity_attacks(url, method, headers, response)
                        vulnerabilities.extend(complexity_vulns)
                        
                        # 3. Test depth-based attacks
                        depth_vulns = self._test_depth_attacks(url, method, headers, response)
                        vulnerabilities.extend(depth_vulns)
                        
                        # 4. Test alias-based attacks
                        alias_vulns = self._test_alias_attacks(url, method, headers, response)
                        vulnerabilities.extend(alias_vulns)
                        
                        # 5. Test batch query attacks
                        batch_vulns = self._test_batch_attacks(url, method, headers, response)
                        vulnerabilities.extend(batch_vulns)
                        
                        # 6. Test fragment-based attacks
                        fragment_vulns = self._test_fragment_attacks(url, method, headers, response)
                        vulnerabilities.extend(fragment_vulns)
                        
                        # 7. Test union/interface attacks
                        union_vulns = self._test_union_interface_attacks(url, method, headers, response)
                        vulnerabilities.extend(union_vulns)
                        
                        # 8. Test directive attacks
                        directive_vulns = self._test_directive_attacks(url, method, headers, response)
                        vulnerabilities.extend(directive_vulns)
                        
                        # 9. Test subscription attacks
                        subscription_vulns = self._test_subscription_attacks(url, method, headers, response)
                        vulnerabilities.extend(subscription_vulns)
                        
                        # 10. Test mutation attacks
                        mutation_vulns = self._test_mutation_attacks(url, method, headers, response)
                        vulnerabilities.extend(mutation_vulns)
                        
                        # 11. Test injection attacks
                        injection_vulns = self._test_injection_attacks(url, method, headers, response)
                        vulnerabilities.extend(injection_vulns)
                        
                        # 12. Test authorization bypass
                        auth_vulns = self._test_authorization_bypass(url, method, headers, response)
                        vulnerabilities.extend(auth_vulns)
                        
                        # 13. Test information disclosure
                        info_vulns = self._test_information_disclosure(url, method, headers, response)
                        vulnerabilities.extend(info_vulns)
                        
                        # 14. Test rate limiting
                        rate_vulns = self._test_rate_limiting(url, method, headers, response)
                        vulnerabilities.extend(rate_vulns)
        
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                vulnerabilities=[],
                error=f"GraphQL security check failed: {str(e)}"
            )
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities,
            error=None
        )
    
    def _is_graphql_endpoint(self, url: str, request: Dict[str, Any]) -> bool:
        """Check if the URL/request is a GraphQL endpoint."""
        # Check URL patterns
        for pattern in self.graphql_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        # Check request body for GraphQL queries
        body = request.get('body', '')
        if body:
            # Look for GraphQL query patterns
            if re.search(r'query\s*\{|mutation\s*\{|subscription\s*\{', body, re.IGNORECASE):
                return True
            
            # Look for GraphQL JSON format
            try:
                if isinstance(body, str):
                    data = json.loads(body)
                    if isinstance(data, dict) and ('query' in data or 'mutation' in data or 'subscription' in data):
                        return True
            except (json.JSONDecodeError, TypeError):
                pass
        
        # Check headers for GraphQL content type
        headers = request.get('headers', {})
        content_type = headers.get('Content-Type', '').lower()
        if 'application/graphql' in content_type:
            return True
        
        return False
    
    def _test_introspection(self, url: str, method: str, headers: Dict[str, str], 
                          response: Any) -> List[Vulnerability]:
        """Test for GraphQL introspection vulnerabilities."""
        vulnerabilities = []
        
        # Test introspection query
        introspection_payload = {
            "query": self.introspection_query
        }
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        test_response = self.make_request(url, method, test_headers, json.dumps(introspection_payload))
        
        if test_response and test_response.status_code == 200:
            response_text = test_response.text.lower()
            
            # Check if introspection is enabled
            if '__schema' in response_text or '__type' in response_text or '__typename' in response_text:
                vuln = self.create_vulnerability(
                    vuln_id=f"graphql-introspection-enabled-{uuid.uuid4().hex[:8]}",
                    name="GraphQL Introspection Enabled",
                    description="GraphQL introspection is enabled, allowing attackers to discover the complete schema",
                    risk="High",
                    cvss_score=7.5,
                    solution="Disable introspection in production environments",
                    references=[
                        "https://graphql.org/learn/introspection/",
                        "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"
                    ],
                    cwe_id="CWE-200",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="GraphQL Introspection",
                    evidence="Introspection query returned schema information",
                    scan_id="graphql-scan",
                    request=format_http_request(method, url, test_headers, json.dumps(introspection_payload)),
                    response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_query_complexity_attacks(self, url: str, method: str, headers: Dict[str, str], 
                                     response: Any) -> List[Vulnerability]:
        """Test for query complexity vulnerabilities."""
        vulnerabilities = []
        
        # Generate complex query
        complex_query = self._generate_complex_query()
        
        payload = {
            "query": complex_query
        }
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        start_time = time.time()
        test_response = self.make_request(url, method, test_headers, json.dumps(payload))
        end_time = time.time()
        
        if test_response and test_response.status_code == 200:
            # Check if query was processed (indicating no complexity limits)
            if end_time - start_time > 5:  # Query took more than 5 seconds
                vuln = self.create_vulnerability(
                    vuln_id=f"graphql-query-complexity-{uuid.uuid4().hex[:8]}",
                    name="GraphQL Query Complexity Attack",
                    description="GraphQL endpoint allows complex queries without complexity limits",
                    risk="High",
                    cvss_score=7.5,
                    solution="Implement query complexity analysis and limits",
                    references=[
                        "https://graphql.org/learn/thinking-in-graphs/",
                        "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
                    ],
                    cwe_id="CWE-400",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="Query Complexity",
                    evidence=f"Complex query processed in {end_time - start_time:.2f} seconds",
                    scan_id="graphql-scan",
                    request=format_http_request(method, url, test_headers, json.dumps(payload)),
                    response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_depth_attacks(self, url: str, method: str, headers: Dict[str, str], 
                          response: Any) -> List[Vulnerability]:
        """Test for query depth vulnerabilities."""
        vulnerabilities = []
        
        # Generate deep query (10+ levels)
        deep_query = self._generate_deep_query()
        
        payload = {
            "query": deep_query
        }
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        test_response = self.make_request(url, method, test_headers, json.dumps(payload))
        
        if test_response and test_response.status_code == 200:
            # Check if deep query was processed
            response_text = test_response.text.lower()
            if 'error' not in response_text or 'depth' not in response_text:
                vuln = self.create_vulnerability(
                    vuln_id=f"graphql-query-depth-{uuid.uuid4().hex[:8]}",
                    name="GraphQL Query Depth Attack",
                    description="GraphQL endpoint allows deep nested queries without depth limits",
                    risk="High",
                    cvss_score=7.5,
                    solution="Implement query depth limits (recommended: 10-15 levels)",
                    references=[
                        "https://graphql.org/learn/thinking-in-graphs/",
                        "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
                    ],
                    cwe_id="CWE-400",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="Query Depth",
                    evidence="Deep nested query processed successfully",
                    scan_id="graphql-scan",
                    request=format_http_request(method, url, test_headers, json.dumps(payload)),
                    response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_alias_attacks(self, url: str, method: str, headers: Dict[str, str], 
                          response: Any) -> List[Vulnerability]:
        """Test for alias-based attacks."""
        vulnerabilities = []
        
        # Generate alias attack query
        alias_query = self._generate_alias_attack()
        
        payload = {
            "query": alias_query
        }
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        test_response = self.make_request(url, method, test_headers, json.dumps(payload))
        
        if test_response and test_response.status_code == 200:
            # Check if alias attack was successful
            response_text = test_response.text.lower()
            if 'error' not in response_text:
                vuln = self.create_vulnerability(
                    vuln_id=f"graphql-alias-attack-{uuid.uuid4().hex[:8]}",
                    name="GraphQL Alias Attack",
                    description="GraphQL endpoint allows alias-based query multiplication attacks",
                    risk="Medium",
                    cvss_score=6.5,
                    solution="Implement query complexity analysis to prevent alias abuse",
                    references=[
                        "https://graphql.org/learn/queries/#aliases",
                        "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
                    ],
                    cwe_id="CWE-400",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="Query Aliases",
                    evidence="Alias-based query multiplication successful",
                    scan_id="graphql-scan",
                    request=format_http_request(method, url, test_headers, json.dumps(payload)),
                    response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_batch_attacks(self, url: str, method: str, headers: Dict[str, str], 
                          response: Any) -> List[Vulnerability]:
        """Test for batch query attacks."""
        vulnerabilities = []
        
        # Generate batch query
        batch_query = self._generate_batch_query()
        
        payload = {
            "query": batch_query
        }
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        test_response = self.make_request(url, method, test_headers, json.dumps(payload))
        
        if test_response and test_response.status_code == 200:
            # Check if batch query was processed
            response_text = test_response.text.lower()
            if 'error' not in response_text:
                vuln = self.create_vulnerability(
                    vuln_id=f"graphql-batch-attack-{uuid.uuid4().hex[:8]}",
                    name="GraphQL Batch Query Attack",
                    description="GraphQL endpoint allows batch queries without limits",
                    risk="Medium",
                    cvss_score=6.5,
                    solution="Implement batch query limits and rate limiting",
                    references=[
                        "https://graphql.org/learn/queries/#multiple-fields",
                        "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
                    ],
                    cwe_id="CWE-400",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="Batch Queries",
                    evidence="Batch query processed successfully",
                    scan_id="graphql-scan",
                    request=format_http_request(method, url, test_headers, json.dumps(payload)),
                    response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_fragment_attacks(self, url: str, method: str, headers: Dict[str, str], 
                             response: Any) -> List[Vulnerability]:
        """Test for fragment-based attacks."""
        vulnerabilities = []
        
        # Generate fragment attack
        fragment_query = self._generate_fragment_attack()
        
        payload = {
            "query": fragment_query
        }
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        test_response = self.make_request(url, method, test_headers, json.dumps(payload))
        
        if test_response and test_response.status_code == 200:
            # Check if fragment attack was successful
            response_text = test_response.text.lower()
            if 'error' not in response_text:
                vuln = self.create_vulnerability(
                    vuln_id=f"graphql-fragment-attack-{uuid.uuid4().hex[:8]}",
                    name="GraphQL Fragment Attack",
                    description="GraphQL endpoint allows fragment-based query complexity attacks",
                    risk="Medium",
                    cvss_score=6.5,
                    solution="Implement fragment complexity analysis",
                    references=[
                        "https://graphql.org/learn/queries/#fragments",
                        "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
                    ],
                    cwe_id="CWE-400",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="Query Fragments",
                    evidence="Fragment-based query complexity attack successful",
                    scan_id="graphql-scan",
                    request=format_http_request(method, url, test_headers, json.dumps(payload)),
                    response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_union_interface_attacks(self, url: str, method: str, headers: Dict[str, str], 
                                    response: Any) -> List[Vulnerability]:
        """Test for union/interface attacks."""
        vulnerabilities = []
        
        # Generate union/interface attack
        union_query = self._generate_union_attack()
        
        payload = {
            "query": union_query
        }
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        test_response = self.make_request(url, method, test_headers, json.dumps(payload))
        
        if test_response and test_response.status_code == 200:
            # Check if union/interface attack was successful
            response_text = test_response.text.lower()
            if 'error' not in response_text:
                vuln = self.create_vulnerability(
                    vuln_id=f"graphql-union-attack-{uuid.uuid4().hex[:8]}",
                    name="GraphQL Union/Interface Attack",
                    description="GraphQL endpoint allows union/interface-based query complexity attacks",
                    risk="Medium",
                    cvss_score=6.5,
                    solution="Implement union/interface query complexity analysis",
                    references=[
                        "https://graphql.org/learn/schema/#union-types",
                        "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
                    ],
                    cwe_id="CWE-400",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="Union/Interface Types",
                    evidence="Union/interface-based query complexity attack successful",
                    scan_id="graphql-scan",
                    request=format_http_request(method, url, test_headers, json.dumps(payload)),
                    response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_directive_attacks(self, url: str, method: str, headers: Dict[str, str], 
                              response: Any) -> List[Vulnerability]:
        """Test for directive-based attacks."""
        vulnerabilities = []
        
        # Generate directive attack
        directive_query = self._generate_directive_attack()
        
        payload = {
            "query": directive_query
        }
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        test_response = self.make_request(url, method, test_headers, json.dumps(payload))
        
        if test_response and test_response.status_code == 200:
            # Check if directive attack was successful
            response_text = test_response.text.lower()
            if 'error' not in response_text:
                vuln = self.create_vulnerability(
                    vuln_id=f"graphql-directive-attack-{uuid.uuid4().hex[:8]}",
                    name="GraphQL Directive Attack",
                    description="GraphQL endpoint allows directive-based query manipulation",
                    risk="Medium",
                    cvss_score=6.5,
                    solution="Implement directive validation and restrictions",
                    references=[
                        "https://graphql.org/learn/queries/#directives",
                        "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
                    ],
                    cwe_id="CWE-400",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="Query Directives",
                    evidence="Directive-based query manipulation successful",
                    scan_id="graphql-scan",
                    request=format_http_request(method, url, test_headers, json.dumps(payload)),
                    response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_subscription_attacks(self, url: str, method: str, headers: Dict[str, str], 
                                 response: Any) -> List[Vulnerability]:
        """Test for subscription-based attacks."""
        vulnerabilities = []
        
        # Generate subscription attack
        subscription_query = self._generate_subscription_attack()
        
        payload = {
            "query": subscription_query
        }
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        test_response = self.make_request(url, method, test_headers, json.dumps(payload))
        
        if test_response and test_response.status_code == 200:
            # Check if subscription attack was successful
            response_text = test_response.text.lower()
            if 'error' not in response_text:
                vuln = self.create_vulnerability(
                    vuln_id=f"graphql-subscription-attack-{uuid.uuid4().hex[:8]}",
                    name="GraphQL Subscription Attack",
                    description="GraphQL endpoint allows subscription-based resource exhaustion",
                    risk="High",
                    cvss_score=7.5,
                    solution="Implement subscription limits and resource monitoring",
                    references=[
                        "https://graphql.org/learn/subscriptions/",
                        "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection"
                    ],
                    cwe_id="CWE-400",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="GraphQL Subscriptions",
                    evidence="Subscription-based resource exhaustion successful",
                    scan_id="graphql-scan",
                    request=format_http_request(method, url, test_headers, json.dumps(payload)),
                    response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_mutation_attacks(self, url: str, method: str, headers: Dict[str, str], 
                             response: Any) -> List[Vulnerability]:
        """Test for mutation-based attacks."""
        vulnerabilities = []
        
        # Generate mutation attack
        mutation_query = self._generate_mutation_attack()
        
        payload = {
            "query": mutation_query
        }
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        test_response = self.make_request(url, method, test_headers, json.dumps(payload))
        
        if test_response and test_response.status_code == 200:
            # Check if mutation attack was successful
            response_text = test_response.text.lower()
            if 'error' not in response_text:
                vuln = self.create_vulnerability(
                    vuln_id=f"graphql-mutation-attack-{uuid.uuid4().hex[:8]}",
                    name="GraphQL Mutation Attack",
                    description="GraphQL endpoint allows unauthorized mutation operations",
                    risk="High",
                    cvss_score=8.1,
                    solution="Implement proper authorization for mutation operations",
                    references=[
                        "https://graphql.org/learn/queries/#mutations",
                        "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"
                    ],
                    cwe_id="CWE-285",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="GraphQL Mutations",
                    evidence="Unauthorized mutation operation successful",
                    scan_id="graphql-scan",
                    request=format_http_request(method, url, test_headers, json.dumps(payload)),
                    response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_injection_attacks(self, url: str, method: str, headers: Dict[str, str], 
                              response: Any) -> List[Vulnerability]:
        """Test for injection attacks in GraphQL."""
        vulnerabilities = []
        
        # Test various injection vectors
        injection_payloads = [
            {"query": "query { user(id: \"1' OR '1'='1\") { name } }"},
            {"query": "query { user(id: \"1; DROP TABLE users;\") { name } }"},
            {"query": "query { user(id: \"1${7*7}\") { name } }"},
            {"query": "query { user(id: \"1{{7*7}}\") { name } }"},
            {"query": "query { user(id: \"1<script>alert('xss')</script>\") { name } }"},
            {"query": "query { user(id: \"1'; EXEC xp_cmdshell('dir'); --\") { name } }"}
        ]
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        for payload in injection_payloads:
            test_response = self.make_request(url, method, test_headers, json.dumps(payload))
            
            if test_response and test_response.status_code == 200:
                response_text = test_response.text.lower()
                
                # Check for injection success indicators
                if any(indicator in response_text for indicator in ['error', 'exception', 'sql', 'script', '49']):
                    vuln = self.create_vulnerability(
                        vuln_id=f"graphql-injection-{uuid.uuid4().hex[:8]}",
                        name="GraphQL Injection Vulnerability",
                        description="GraphQL endpoint is vulnerable to injection attacks",
                        risk="High",
                        cvss_score=8.1,
                        solution="Implement proper input validation and parameterized queries",
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
                            "https://graphql.org/learn/best-practices/"
                        ],
                        cwe_id="CWE-89",
                        wasc_id="WASC-15",
                        url=url,
                        parameter="GraphQL Input",
                        evidence=f"Injection payload: {payload['query'][:100]}...",
                        scan_id="graphql-scan",
                        request=format_http_request(method, url, test_headers, json.dumps(payload)),
                        response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                    )
                    vulnerabilities.append(vuln)
                    break  # Found injection, no need to test more
        
        return vulnerabilities
    
    def _test_authorization_bypass(self, url: str, method: str, headers: Dict[str, str], 
                                 response: Any) -> List[Vulnerability]:
        """Test for authorization bypass vulnerabilities."""
        vulnerabilities = []
        
        # Test authorization bypass attempts
        auth_bypass_queries = [
            "query { admin { users { password } } }",
            "query { root { system { config } } }",
            "query { superuser { delete { all } } }",
            "mutation { deleteAllUsers { success } }",
            "mutation { updateUserRole(id: 1, role: \"admin\") { success } }"
        ]
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        for query in auth_bypass_queries:
            payload = {"query": query}
            test_response = self.make_request(url, method, test_headers, json.dumps(payload))
            
            if test_response and test_response.status_code == 200:
                response_text = test_response.text.lower()
                
                # Check if authorization bypass was successful
                if 'error' not in response_text and any(indicator in response_text for indicator in ['success', 'true', 'password', 'admin']):
                    vuln = self.create_vulnerability(
                        vuln_id=f"graphql-auth-bypass-{uuid.uuid4().hex[:8]}",
                        name="GraphQL Authorization Bypass",
                        description="GraphQL endpoint allows unauthorized access to sensitive operations",
                        risk="Critical",
                        cvss_score=9.1,
                        solution="Implement proper authorization checks for all GraphQL operations",
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
                            "https://graphql.org/learn/authorization/"
                        ],
                        cwe_id="CWE-285",
                        wasc_id="WASC-15",
                        url=url,
                        parameter="GraphQL Authorization",
                        evidence=f"Unauthorized query: {query[:100]}...",
                        scan_id="graphql-scan",
                        request=format_http_request(method, url, test_headers, json.dumps(payload)),
                        response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                    )
                    vulnerabilities.append(vuln)
                    break  # Found bypass, no need to test more
        
        return vulnerabilities
    
    def _test_information_disclosure(self, url: str, method: str, headers: Dict[str, str], 
                                   response: Any) -> List[Vulnerability]:
        """Test for information disclosure vulnerabilities."""
        vulnerabilities = []
        
        # Test for sensitive information disclosure
        info_disclosure_queries = [
            "query { __schema { types { name } } }",
            "query { user { password email ssn } }",
            "query { config { secret key token } }",
            "query { system { version build debug } }"
        ]
        
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        for query in info_disclosure_queries:
            payload = {"query": query}
            test_response = self.make_request(url, method, test_headers, json.dumps(payload))
            
            if test_response and test_response.status_code == 200:
                response_text = test_response.text.lower()
                
                # Check for sensitive information disclosure
                sensitive_patterns = self.vulnerability_patterns['information_disclosure']
                if any(pattern in response_text for pattern in sensitive_patterns):
                    vuln = self.create_vulnerability(
                        vuln_id=f"graphql-info-disclosure-{uuid.uuid4().hex[:8]}",
                        name="GraphQL Information Disclosure",
                        description="GraphQL endpoint discloses sensitive information",
                        risk="Medium",
                        cvss_score=6.5,
                        solution="Implement proper data filtering and access controls",
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                            "https://graphql.org/learn/authorization/"
                        ],
                        cwe_id="CWE-200",
                        wasc_id="WASC-15",
                        url=url,
                        parameter="GraphQL Data",
                        evidence=f"Sensitive information disclosed in: {query[:100]}...",
                        scan_id="graphql-scan",
                        request=format_http_request(method, url, test_headers, json.dumps(payload)),
                        response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                    )
                    vulnerabilities.append(vuln)
                    break  # Found disclosure, no need to test more
        
        return vulnerabilities
    
    def _test_rate_limiting(self, url: str, method: str, headers: Dict[str, str], 
                          response: Any) -> List[Vulnerability]:
        """Test for rate limiting vulnerabilities."""
        vulnerabilities = []
        
        # Test rate limiting by making multiple rapid requests
        simple_query = {"query": "query { __typename }"}
        test_headers = headers.copy()
        test_headers['Content-Type'] = 'application/json'
        
        success_count = 0
        for i in range(10):  # Make 10 rapid requests
            test_response = self.make_request(url, method, test_headers, json.dumps(simple_query))
            if test_response and test_response.status_code == 200:
                success_count += 1
            time.sleep(0.1)  # Small delay between requests
        
        # If all requests succeeded, rate limiting might be insufficient
        if success_count >= 8:  # 80% success rate
            vuln = self.create_vulnerability(
                vuln_id=f"graphql-rate-limiting-{uuid.uuid4().hex[:8]}",
                name="GraphQL Rate Limiting Insufficient",
                description="GraphQL endpoint lacks proper rate limiting",
                risk="Medium",
                cvss_score=6.5,
                solution="Implement rate limiting for GraphQL endpoints",
                references=[
                    "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
                    "https://graphql.org/learn/best-practices/"
                ],
                cwe_id="CWE-770",
                wasc_id="WASC-15",
                url=url,
                parameter="Rate Limiting",
                evidence=f"{success_count}/10 requests succeeded without rate limiting",
                scan_id="graphql-scan",
                request=format_http_request(method, url, test_headers, json.dumps(simple_query)),
                response=format_http_response(response.status_code, dict(response.headers), response.text) if response else ""
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    # Helper methods to generate attack payloads
    def _generate_deep_query(self) -> str:
        """Generate a deep nested query."""
        return """
        query {
            user {
                posts {
                    comments {
                        author {
                            posts {
                                comments {
                                    author {
                                        posts {
                                            comments {
                                                author {
                                                    name
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
    
    def _generate_alias_attack(self) -> str:
        """Generate an alias-based attack query."""
        aliases = []
        for i in range(20):
            aliases.append(f"user{i}: user(id: {i}) {{ name email }}")
        
        return f"query {{ {' '.join(aliases)} }}"
    
    def _generate_batch_query(self) -> str:
        """Generate a batch query attack."""
        queries = []
        for i in range(10):
            queries.append(f"query{i}: user(id: {i}) {{ name email posts {{ title }} }}")
        
        return f"query {{ {' '.join(queries)} }}"
    
    def _generate_fragment_attack(self) -> str:
        """Generate a fragment-based attack."""
        return """
        fragment UserData on User {
            name
            email
            posts {
                title
                comments {
                    author {
                        name
                        email
                    }
                }
            }
        }
        
        query {
            user {
                ...UserData
                posts {
                    ...UserData
                }
            }
        }
        """
    
    def _generate_union_attack(self) -> str:
        """Generate a union-based attack."""
        return """
        query {
            search(query: "test") {
                ... on User {
                    name
                    email
                }
                ... on Post {
                    title
                    content
                }
                ... on Comment {
                    text
                    author {
                        name
                    }
                }
            }
        }
        """
    
    def _generate_interface_attack(self) -> str:
        """Generate an interface-based attack."""
        return """
        query {
            node(id: "1") {
                ... on User {
                    name
                    email
                    posts {
                        title
                    }
                }
                ... on Post {
                    title
                    content
                    author {
                        name
                    }
                }
            }
        }
        """
    
    def _generate_directive_attack(self) -> str:
        """Generate a directive-based attack."""
        return """
        query {
            user @include(if: true) {
                name
                email
            }
            user @skip(if: false) {
                posts @include(if: true) {
                    title
                }
            }
        }
        """
    
    def _generate_subscription_attack(self) -> str:
        """Generate a subscription-based attack."""
        return """
        subscription {
            userUpdated {
                id
                name
                email
                posts {
                    title
                    comments {
                        text
                        author {
                            name
                        }
                    }
                }
            }
        }
        """
    
    def _generate_mutation_attack(self) -> str:
        """Generate a mutation-based attack."""
        return """
        mutation {
            deleteUser(id: 1) {
                success
                message
            }
            updateUserRole(id: 1, role: "admin") {
                success
                user {
                    role
                }
            }
        }
        """
    
    def _generate_complex_query(self) -> str:
        """Generate a complex query for complexity testing."""
        return """
        query {
            user {
                posts {
                    comments {
                        author {
                            posts {
                                comments {
                                    author {
                                        posts {
                                            comments {
                                                author {
                                                    posts {
                                                        comments {
                                                            author {
                                                                name
                                                                email
                                                                posts {
                                                                    title
                                                                    content
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
    
    def generate_poc(self, vulnerability_id: str) -> ProofOfConcept:
        """Generate proof-of-concept for GraphQL vulnerabilities."""
        return ProofOfConcept(
            vulnerability_id=vulnerability_id,
            request_method="POST",
            request_url="https://example.com/graphql",
            request_headers={"Content-Type": "application/json"},
            request_body='{"query": "query { __schema { types { name } } }"}',
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"data": {"__schema": {"types": [{"name": "User"}]}}}',
            timestamp=datetime.now(),
            evidence_description="GraphQL vulnerability detected"
        )
