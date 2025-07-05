"""
Authentication Security Analyzer
Comprehensive authentication security testing including JWT manipulation, OAuth flows, session management, and bypass techniques.
"""

import json
import logging
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, parse_qs, urlparse

import requests
import jwt
from rich.console import Console

from ..utils.debug_utils import debug_print

class AuthenticationAnalyzer:
    """Authentication security analyzer."""
    
    def __init__(self, debug: bool = False):
        """Initialize the authentication analyzer."""
        self.debug = debug
        self.console = Console()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'APISecurityTester/1.0'
        })
        
        # Common authentication bypass techniques
        self.bypass_techniques = [
            {"Authorization": "null"},
            {"Authorization": "undefined"},
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"Authorization": "Bearer "},
            {"X-API-Key": "null"},
            {"X-API-Key": "undefined"},
            {"X-API-Key": ""},
            {"X-Auth-Token": "null"},
            {"X-Auth-Token": "undefined"},
            {"X-Auth-Token": ""}
        ]
        
        # JWT manipulation payloads
        self.jwt_payloads = [
            {"alg": "none"},
            {"alg": "HS256", "typ": "JWT"},
            {"alg": "RS256", "typ": "JWT"},
            {"alg": "ES256", "typ": "JWT"}
        ]
    
    def analyze_rest_auth(self, base_url: str, rest_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze REST API authentication security."""
        debug_print("Analyzing REST API authentication")
        
        results = {
            "authentication_methods": [],
            "bypass_vulnerabilities": [],
            "jwt_vulnerabilities": [],
            "session_vulnerabilities": [],
            "oauth_vulnerabilities": [],
            "vulnerabilities": []
        }
        
        try:
            # Test authentication bypass
            bypass_results = self._test_auth_bypass(base_url)
            results["bypass_vulnerabilities"] = bypass_results
            
            # Test JWT tokens
            jwt_results = self._test_jwt_security(base_url)
            results["jwt_vulnerabilities"] = jwt_results
            
            # Test session management
            session_results = self._test_session_management(base_url)
            results["session_vulnerabilities"] = session_results
            
            # Test OAuth flows
            oauth_results = self._test_oauth_flows(base_url)
            results["oauth_vulnerabilities"] = oauth_results
            
            # Generate vulnerability summary
            self._generate_auth_vulnerability_summary(results)
            
        except Exception as e:
            debug_print("Error analyzing REST authentication:", str(e))
            results["error"] = str(e)
        
        return results
    
    def analyze_graphql_auth(self, endpoint: str, graphql_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze GraphQL authentication security."""
        debug_print("Analyzing GraphQL authentication")
        
        results = {
            "authentication_methods": [],
            "bypass_vulnerabilities": [],
            "jwt_vulnerabilities": [],
            "vulnerabilities": []
        }
        
        try:
            # Test authentication bypass
            bypass_results = self._test_graphql_auth_bypass(endpoint)
            results["bypass_vulnerabilities"] = bypass_results
            
            # Test JWT tokens in GraphQL
            jwt_results = self._test_graphql_jwt_security(endpoint)
            results["jwt_vulnerabilities"] = jwt_results
            
            # Generate vulnerability summary
            self._generate_auth_vulnerability_summary(results)
            
        except Exception as e:
            debug_print("Error analyzing GraphQL authentication:", str(e))
            results["error"] = str(e)
        
        return results
    
    def _test_auth_bypass(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for authentication bypass techniques."""
        debug_print("Testing authentication bypass techniques")
        
        vulnerabilities = []
        
        # Test common endpoints without authentication
        auth_endpoints = [
            "/api/users",
            "/api/admin",
            "/api/settings",
            "/api/profile",
            "/users",
            "/admin",
            "/settings",
            "/profile"
        ]
        
        for endpoint in auth_endpoints:
            url = urljoin(base_url, endpoint)
            
            # Test without any authentication
            try:
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    vulnerabilities.append({
                        "endpoint": endpoint,
                        "technique": "no_auth",
                        "severity": "high",
                        "description": f"Endpoint {endpoint} accessible without authentication",
                        "impact": "Unauthorized access to sensitive data"
                    })
                    
            except Exception as e:
                debug_print(f"Error testing {endpoint}:", str(e))
            
            # Test with bypass techniques
            for technique in self.bypass_techniques:
                try:
                    response = self.session.get(url, headers=technique, timeout=10)
                    
                    if response.status_code == 200:
                        vulnerabilities.append({
                            "endpoint": endpoint,
                            "technique": technique,
                            "severity": "high",
                            "description": f"Authentication bypass using {technique}",
                            "impact": "Unauthorized access to sensitive data"
                        })
                        
                except Exception as e:
                    debug_print(f"Error testing bypass technique {technique}:", str(e))
        
        return vulnerabilities
    
    def _test_jwt_security(self, base_url: str) -> List[Dict[str, Any]]:
        """Test JWT token security."""
        debug_print("Testing JWT security")
        
        vulnerabilities = []
        
        # Test JWT algorithm confusion
        for payload in self.jwt_payloads:
            try:
                # Create malicious JWT
                malicious_jwt = self._create_malicious_jwt(payload)
                
                # Test with malicious JWT
                headers = {"Authorization": f"Bearer {malicious_jwt}"}
                
                # Test on protected endpoints
                auth_endpoints = ["/api/users", "/api/admin", "/users", "/admin"]
                
                for endpoint in auth_endpoints:
                    url = urljoin(base_url, endpoint)
                    
                    try:
                        response = self.session.get(url, headers=headers, timeout=10)
                        
                        if response.status_code == 200:
                            vulnerabilities.append({
                                "endpoint": endpoint,
                                "technique": "jwt_algorithm_confusion",
                                "payload": payload,
                                "severity": "critical",
                                "description": f"JWT algorithm confusion successful with {payload}",
                                "impact": "Authentication bypass through JWT manipulation"
                            })
                            
                    except Exception as e:
                        debug_print(f"Error testing JWT on {endpoint}:", str(e))
                        
            except Exception as e:
                debug_print(f"Error creating malicious JWT with {payload}:", str(e))
        
        # Test JWT expiration bypass
        expired_jwt = self._create_expired_jwt()
        if expired_jwt:
            headers = {"Authorization": f"Bearer {expired_jwt}"}
            
            for endpoint in ["/api/users", "/api/admin"]:
                url = urljoin(base_url, endpoint)
                
                try:
                    response = self.session.get(url, headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        vulnerabilities.append({
                            "endpoint": endpoint,
                            "technique": "jwt_expiration_bypass",
                            "severity": "high",
                            "description": "Expired JWT token accepted",
                            "impact": "Authentication bypass through expired token"
                        })
                        
                except Exception as e:
                    debug_print(f"Error testing expired JWT on {endpoint}:", str(e))
        
        return vulnerabilities
    
    def _test_session_management(self, base_url: str) -> List[Dict[str, Any]]:
        """Test session management security."""
        debug_print("Testing session management")
        
        vulnerabilities = []
        
        # Test session fixation
        try:
            # Get initial session
            response = self.session.get(base_url, timeout=10)
            initial_cookies = self.session.cookies.get_dict()
            
            if initial_cookies:
                # Test if session ID is predictable
                for cookie_name, cookie_value in initial_cookies.items():
                    if "session" in cookie_name.lower() or "id" in cookie_name.lower():
                        # Test session ID predictability
                        if self._is_session_predictable(cookie_value):
                            vulnerabilities.append({
                                "technique": "session_prediction",
                                "cookie": cookie_name,
                                "severity": "medium",
                                "description": f"Session ID appears predictable: {cookie_value}",
                                "impact": "Session hijacking through prediction"
                            })
                        
                        # Test session ID length
                        if len(cookie_value) < 32:
                            vulnerabilities.append({
                                "technique": "weak_session_id",
                                "cookie": cookie_name,
                                "severity": "medium",
                                "description": f"Session ID too short: {len(cookie_value)} characters",
                                "impact": "Session hijacking through brute force"
                            })
                            
        except Exception as e:
            debug_print("Error testing session management:", str(e))
        
        return vulnerabilities
    
    def _test_oauth_flows(self, base_url: str) -> List[Dict[str, Any]]:
        """Test OAuth flow security."""
        debug_print("Testing OAuth flows")
        
        vulnerabilities = []
        
        # Test OAuth endpoints
        oauth_endpoints = [
            "/oauth/authorize",
            "/oauth/token",
            "/oauth/callback",
            "/auth/oauth/authorize",
            "/auth/oauth/token"
        ]
        
        for endpoint in oauth_endpoints:
            url = urljoin(base_url, endpoint)
            
            try:
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    # Check for OAuth misconfigurations
                    vulnerabilities.append({
                        "endpoint": endpoint,
                        "technique": "oauth_endpoint_exposed",
                        "severity": "medium",
                        "description": f"OAuth endpoint {endpoint} accessible without authentication",
                        "impact": "OAuth flow manipulation"
                    })
                    
            except Exception as e:
                debug_print(f"Error testing OAuth endpoint {endpoint}:", str(e))
        
        return vulnerabilities
    
    def _test_graphql_auth_bypass(self, endpoint: str) -> List[Dict[str, Any]]:
        """Test GraphQL authentication bypass."""
        debug_print("Testing GraphQL authentication bypass")
        
        vulnerabilities = []
        
        # Test protected GraphQL queries without authentication
        protected_queries = [
            """
            query GetUsers {
              users {
                id
                name
                email
                password
              }
            }
            """,
            """
            query GetAdminData {
              admin {
                settings
                users
                logs
              }
            }
            """
        ]
        
        for query in protected_queries:
            try:
                payload = {"query": query}
                response = self.session.post(endpoint, json=payload, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if "data" in data and data["data"]:
                        vulnerabilities.append({
                            "query": query.strip(),
                            "technique": "no_auth",
                            "severity": "high",
                            "description": "Protected GraphQL query accessible without authentication",
                            "impact": "Unauthorized access to sensitive data"
                        })
                        
            except Exception as e:
                debug_print(f"Error testing GraphQL query:", str(e))
        
        return vulnerabilities
    
    def _test_graphql_jwt_security(self, endpoint: str) -> List[Dict[str, Any]]:
        """Test JWT security in GraphQL."""
        debug_print("Testing GraphQL JWT security")
        
        vulnerabilities = []
        
        # Test with malicious JWT
        for payload in self.jwt_payloads:
            try:
                malicious_jwt = self._create_malicious_jwt(payload)
                
                headers = {"Authorization": f"Bearer {malicious_jwt}"}
                
                query = """
                query GetUsers {
                  users {
                    id
                    name
                    email
                  }
                }
                """
                
                payload_data = {"query": query}
                response = self.session.post(endpoint, json=payload_data, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if "data" in data and data["data"]:
                        vulnerabilities.append({
                            "technique": "jwt_algorithm_confusion",
                            "payload": payload,
                            "severity": "critical",
                            "description": f"GraphQL JWT algorithm confusion with {payload}",
                            "impact": "Authentication bypass in GraphQL"
                        })
                        
            except Exception as e:
                debug_print(f"Error testing GraphQL JWT with {payload}:", str(e))
        
        return vulnerabilities
    
    def _create_malicious_jwt(self, header: Dict[str, Any]) -> str:
        """Create a malicious JWT token."""
        try:
            # Create payload with admin privileges
            payload = {
                "sub": "admin",
                "role": "admin",
                "exp": int(time.time()) + 3600,  # 1 hour from now
                "iat": int(time.time())
            }
            
            # Create JWT with specified algorithm
            if header.get("alg") == "none":
                # Algorithm none attack
                return jwt.encode(payload, "", algorithm="none")
            else:
                # Use a weak secret
                return jwt.encode(payload, "weak_secret", algorithm="HS256")
                
        except Exception as e:
            debug_print("Error creating malicious JWT:", str(e))
            return ""
    
    def _create_expired_jwt(self) -> str:
        """Create an expired JWT token."""
        try:
            payload = {
                "sub": "user",
                "exp": int(time.time()) - 3600,  # Expired 1 hour ago
                "iat": int(time.time()) - 7200   # Issued 2 hours ago
            }
            
            return jwt.encode(payload, "secret", algorithm="HS256")
            
        except Exception as e:
            debug_print("Error creating expired JWT:", str(e))
            return ""
    
    def _is_session_predictable(self, session_id: str) -> bool:
        """Check if session ID appears predictable."""
        # Check for sequential patterns
        if session_id.isdigit():
            return True
        
        # Check for timestamp-based patterns
        if len(session_id) == 10 and session_id.isdigit():
            # Could be Unix timestamp
            return True
        
        # Check for base64 patterns
        if len(session_id) % 4 == 0 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in session_id):
            return True
        
        return False
    
    def _generate_auth_vulnerability_summary(self, results: Dict[str, Any]):
        """Generate authentication vulnerability summary."""
        if "vulnerabilities" not in results:
            results["vulnerabilities"] = []
        
        # Add issues from other tests
        for issue_list in ["bypass_vulnerabilities", "jwt_vulnerabilities", 
                          "session_vulnerabilities", "oauth_vulnerabilities"]:
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