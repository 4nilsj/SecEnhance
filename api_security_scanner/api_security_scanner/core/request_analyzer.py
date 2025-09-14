"""
Request Analyzer for JWT/OAuth/GraphQL Flow Detection
Analyzes requests and responses to identify JWT tokens, OAuth flows, and GraphQL endpoints.
"""

import re
import json
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse, parse_qs

from ..utils.logger import get_logger


class RequestAnalyzer:
    """Analyzes requests and responses for JWT tokens, OAuth flows, and GraphQL endpoints."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        
        # JWT token patterns
        self.jwt_pattern = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
        self.bearer_pattern = re.compile(r'Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', re.IGNORECASE)
        
        # OAuth flow patterns
        self.oauth_endpoints = {
            'authorization': re.compile(r'/oauth/authorize|/authorize|/auth', re.IGNORECASE),
            'token': re.compile(r'/oauth/token|/token', re.IGNORECASE),
            'userinfo': re.compile(r'/oauth/userinfo|/userinfo', re.IGNORECASE),
            'introspect': re.compile(r'/oauth/introspect|/introspect', re.IGNORECASE),
            'revoke': re.compile(r'/oauth/revoke|/revoke', re.IGNORECASE)
        }
        
        self.oauth_grant_types = {
            'authorization_code': re.compile(r'authorization_code', re.IGNORECASE),
            'client_credentials': re.compile(r'client_credentials', re.IGNORECASE),
            'password': re.compile(r'password', re.IGNORECASE),
            'refresh_token': re.compile(r'refresh_token', re.IGNORECASE),
            'implicit': re.compile(r'implicit', re.IGNORECASE)
        }
        
        self.oauth_parameters = {
            'client_id', 'client_secret', 'redirect_uri', 'response_type', 
            'scope', 'state', 'code', 'grant_type', 'access_token', 
            'refresh_token', 'token_type', 'expires_in'
        }
        
        # JWT-related headers
        self.jwt_headers = {
            'authorization', 'x-access-token', 'x-auth-token', 'x-jwt-token',
            'x-api-key', 'x-token', 'jwt', 'token'
        }
        
        # GraphQL endpoint patterns
        self.graphql_endpoints = {
            'graphql': re.compile(r'/graphql|/api/graphql|/v\d+/graphql', re.IGNORECASE),
            'query': re.compile(r'/query|/api/query', re.IGNORECASE),
            'gql': re.compile(r'/gql|/api/gql', re.IGNORECASE)
        }
        
        # GraphQL operation patterns
        self.graphql_operations = {
            'query': re.compile(r'query\s*\{|query\s+\w+', re.IGNORECASE),
            'mutation': re.compile(r'mutation\s*\{|mutation\s+\w+', re.IGNORECASE),
            'subscription': re.compile(r'subscription\s*\{|subscription\s+\w+', re.IGNORECASE),
            'introspection': re.compile(r'__schema|__type|__typename|__field|__directive', re.IGNORECASE)
        }
        
        # GraphQL content types
        self.graphql_content_types = {
            'application/graphql',
            'application/json'  # GraphQL over HTTP typically uses JSON
        }
        
        # GraphQL-specific parameters
        self.graphql_parameters = {
            'query', 'mutation', 'subscription', 'variables', 'operationName'
        }
        
        # OAuth-related response fields
        self.oauth_response_fields = {
            'access_token', 'refresh_token', 'id_token', 'token_type',
            'expires_in', 'scope', 'state', 'error', 'error_description'
        }
    
    def analyze_requests(self, requests_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze a list of requests for JWT tokens, OAuth flows, and GraphQL endpoints.
        
        Args:
            requests_data: List of request dictionaries
            
        Returns:
            Dictionary containing analysis results
        """
        analysis_result = {
            'contains_jwt': False,
            'contains_oauth': False,
            'contains_graphql': False,
            'jwt_tokens': [],
            'oauth_flows': [],
            'oauth_endpoints': [],
            'graphql_endpoints': [],
            'graphql_operations': [],
            'security_concerns': [],
            'recommended_plugins': []
        }
        
        try:
            for request in requests_data:
                url = request.get('url', '')
                method = request.get('method', 'GET')
                headers = request.get('headers', {})
                body = request.get('body', '')
                
                # Analyze individual request
                request_analysis = self._analyze_single_request(url, method, headers, body)
                
                # Merge results
                if request_analysis['contains_jwt']:
                    analysis_result['contains_jwt'] = True
                    analysis_result['jwt_tokens'].extend(request_analysis['jwt_tokens'])
                
                if request_analysis['contains_oauth']:
                    analysis_result['contains_oauth'] = True
                    analysis_result['oauth_flows'].extend(request_analysis['oauth_flows'])
                    analysis_result['oauth_endpoints'].extend(request_analysis['oauth_endpoints'])
                
                if request_analysis['contains_graphql']:
                    analysis_result['contains_graphql'] = True
                    analysis_result['graphql_endpoints'].extend(request_analysis['graphql_endpoints'])
                    analysis_result['graphql_operations'].extend(request_analysis['graphql_operations'])
                
                analysis_result['security_concerns'].extend(request_analysis['security_concerns'])
            
            # Determine recommended plugins
            analysis_result['recommended_plugins'] = self._get_recommended_plugins(analysis_result)
            
            # Log analysis results
            self.logger.info(f"Request analysis complete: JWT={analysis_result['contains_jwt']}, OAuth={analysis_result['contains_oauth']}, GraphQL={analysis_result['contains_graphql']}")
            
        except Exception as e:
            self.logger.error(f"Request analysis failed: {e}")
            analysis_result['error'] = str(e)
        
        return analysis_result
    
    def _analyze_single_request(self, url: str, method: str, headers: Dict[str, str], body: str) -> Dict[str, Any]:
        """Analyze a single request for JWT/OAuth/GraphQL indicators."""
        analysis = {
            'contains_jwt': False,
            'contains_oauth': False,
            'contains_graphql': False,
            'jwt_tokens': [],
            'oauth_flows': [],
            'oauth_endpoints': [],
            'graphql_endpoints': [],
            'graphql_operations': [],
            'security_concerns': []
        }
        
        # Check for JWT tokens in headers
        jwt_tokens = self._extract_jwt_from_headers(headers)
        if jwt_tokens:
            analysis['contains_jwt'] = True
            analysis['jwt_tokens'].extend(jwt_tokens)
        
        # Check for JWT tokens in body
        jwt_tokens_body = self._extract_jwt_from_body(body)
        if jwt_tokens_body:
            analysis['contains_jwt'] = True
            analysis['jwt_tokens'].extend(jwt_tokens_body)
        
        # Check for OAuth endpoints
        oauth_endpoints = self._detect_oauth_endpoints(url)
        if oauth_endpoints:
            analysis['contains_oauth'] = True
            analysis['oauth_endpoints'].extend(oauth_endpoints)
        
        # Check for OAuth flows in body
        oauth_flows = self._detect_oauth_flows(body)
        if oauth_flows:
            analysis['contains_oauth'] = True
            analysis['oauth_flows'].extend(oauth_flows)
        
        # Check for OAuth parameters in URL
        oauth_params = self._detect_oauth_parameters(url)
        if oauth_params:
            analysis['contains_oauth'] = True
            analysis['oauth_flows'].extend(oauth_params)
        
        # Check for GraphQL endpoints
        graphql_endpoints = self._detect_graphql_endpoints(url)
        if graphql_endpoints:
            analysis['contains_graphql'] = True
            analysis['graphql_endpoints'].extend(graphql_endpoints)
        
        # Check for GraphQL operations in body
        graphql_operations = self._detect_graphql_operations(body, headers)
        if graphql_operations:
            analysis['contains_graphql'] = True
            analysis['graphql_operations'].extend(graphql_operations)
        
        # Check for security concerns
        security_concerns = self._check_security_concerns(url, method, headers, body)
        analysis['security_concerns'].extend(security_concerns)
        
        return analysis
    
    def _extract_jwt_from_headers(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Extract JWT tokens from request headers."""
        tokens = []
        
        for header_name, header_value in headers.items():
            if header_name.lower() in self.jwt_headers:
                # Check for Bearer token format
                bearer_match = self.bearer_pattern.search(header_value)
                if bearer_match and self.jwt_pattern.match(bearer_match.group(1)):
                    tokens.append({
                        'token': bearer_match.group(1),
                        'location': f'Header: {header_name}',
                        'type': 'bearer'
                    })
                # Check for standalone JWT
                elif self.jwt_pattern.match(header_value):
                    tokens.append({
                        'token': header_value,
                        'location': f'Header: {header_name}',
                        'type': 'direct'
                    })
        
        return tokens
    
    def _extract_jwt_from_body(self, body: str) -> List[Dict[str, str]]:
        """Extract JWT tokens from request body."""
        tokens = []
        
        if not body:
            return tokens
        
        try:
            # Try to parse as JSON
            if body.strip().startswith('{'):
                data = json.loads(body)
                tokens.extend(self._extract_jwt_from_dict(data, 'JSON Body'))
            else:
                # Check for JWT in plain text
                jwt_matches = self.jwt_pattern.findall(body)
                for token in jwt_matches:
                    tokens.append({
                        'token': token,
                        'location': 'Body (text)',
                        'type': 'embedded'
                    })
        except (json.JSONDecodeError, ValueError):
            # Check for JWT in plain text even if JSON parsing fails
            jwt_matches = self.jwt_pattern.findall(body)
            for token in jwt_matches:
                tokens.append({
                    'token': token,
                    'location': 'Body (text)',
                    'type': 'embedded'
                })
        
        return tokens
    
    def _extract_jwt_from_dict(self, data: Dict[str, Any], location: str) -> List[Dict[str, str]]:
        """Recursively extract JWT tokens from a dictionary."""
        tokens = []
        
        for key, value in data.items():
            if isinstance(value, str) and self.jwt_pattern.match(value):
                tokens.append({
                    'token': value,
                    'location': f'{location} -> {key}',
                    'type': 'json_field'
                })
            elif isinstance(value, dict):
                tokens.extend(self._extract_jwt_from_dict(value, f'{location} -> {key}'))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str) and self.jwt_pattern.match(item):
                        tokens.append({
                            'token': item,
                            'location': f'{location} -> {key}[{i}]',
                            'type': 'json_array'
                        })
                    elif isinstance(item, dict):
                        tokens.extend(self._extract_jwt_from_dict(item, f'{location} -> {key}[{i}]'))
        
        return tokens
    
    def _detect_oauth_endpoints(self, url: str) -> List[Dict[str, str]]:
        """Detect OAuth endpoints in URL."""
        endpoints = []
        
        for endpoint_type, pattern in self.oauth_endpoints.items():
            if pattern.search(url):
                endpoints.append({
                    'type': endpoint_type,
                    'url': url,
                    'confidence': 'high'
                })
        
        return endpoints
    
    def _detect_oauth_flows(self, body: str) -> List[Dict[str, str]]:
        """Detect OAuth flows in request body."""
        flows = []
        
        if not body:
            return flows
        
        try:
            # Parse body as JSON or form data
            if body.strip().startswith('{'):
                data = json.loads(body)
            else:
                data = dict(parse_qs(body))
            
            # Check for OAuth grant types
            grant_type = None
            if isinstance(data, dict):
                grant_type = data.get('grant_type')
                if isinstance(grant_type, list):
                    grant_type = grant_type[0]
            
            if grant_type:
                for flow_type, pattern in self.oauth_grant_types.items():
                    if pattern.search(grant_type):
                        flows.append({
                            'type': flow_type,
                            'grant_type': grant_type,
                            'confidence': 'high'
                        })
            
            # Check for OAuth parameters
            oauth_params_found = []
            for param in self.oauth_parameters:
                if param in data:
                    oauth_params_found.append(param)
            
            if oauth_params_found:
                flows.append({
                    'type': 'oauth_parameters',
                    'parameters': oauth_params_found,
                    'confidence': 'medium'
                })
        
        except (json.JSONDecodeError, ValueError):
            # Check for OAuth patterns in plain text
            for flow_type, pattern in self.oauth_grant_types.items():
                if pattern.search(body):
                    flows.append({
                        'type': flow_type,
                        'source': 'text_match',
                        'confidence': 'low'
                    })
        
        return flows
    
    def _detect_oauth_parameters(self, url: str) -> List[Dict[str, str]]:
        """Detect OAuth parameters in URL query string."""
        flows = []
        
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            oauth_params_found = []
            for param in self.oauth_parameters:
                if param in query_params:
                    oauth_params_found.append(param)
            
            if oauth_params_found:
                flows.append({
                    'type': 'oauth_url_parameters',
                    'parameters': oauth_params_found,
                    'url': url,
                    'confidence': 'high'
                })
        
        except Exception:
            pass
        
        return flows
    
    def _detect_graphql_endpoints(self, url: str) -> List[Dict[str, str]]:
        """Detect GraphQL endpoints in URL."""
        endpoints = []
        
        try:
            for endpoint_type, pattern in self.graphql_endpoints.items():
                if pattern.search(url):
                    endpoints.append({
                        'type': 'graphql_endpoint',
                        'endpoint_type': endpoint_type,
                        'url': url,
                        'confidence': 'high'
                    })
        except Exception:
            pass
        
        return endpoints
    
    def _detect_graphql_operations(self, body: str, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Detect GraphQL operations in request body and headers."""
        operations = []
        
        try:
            # Check content type for GraphQL
            content_type = headers.get('Content-Type', '').lower()
            if 'application/graphql' in content_type:
                operations.append({
                    'type': 'graphql_content_type',
                    'content_type': content_type,
                    'confidence': 'high'
                })
            
            # Check for GraphQL operations in body
            if body:
                # Try to parse as JSON first
                try:
                    body_data = json.loads(body)
                    if isinstance(body_data, dict):
                        # Check for GraphQL query parameter
                        if 'query' in body_data:
                            query = body_data['query']
                            for op_type, pattern in self.graphql_operations.items():
                                if pattern.search(query):
                                    operations.append({
                                        'type': 'graphql_operation',
                                        'operation_type': op_type,
                                        'query': query[:200] + '...' if len(query) > 200 else query,
                                        'confidence': 'high'
                                    })
                        
                        # Check for other GraphQL parameters
                        graphql_params = []
                        for param in self.graphql_parameters:
                            if param in body_data:
                                graphql_params.append(param)
                        
                        if graphql_params:
                            operations.append({
                                'type': 'graphql_parameters',
                                'parameters': graphql_params,
                                'confidence': 'medium'
                            })
                
                except json.JSONDecodeError:
                    # Check for GraphQL operations in raw body
                    for op_type, pattern in self.graphql_operations.items():
                        if pattern.search(body):
                            operations.append({
                                'type': 'graphql_operation',
                                'operation_type': op_type,
                                'query': body[:200] + '...' if len(body) > 200 else body,
                                'confidence': 'medium'
                            })
        
        except Exception:
            pass
        
        return operations
    
    def _check_security_concerns(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Dict[str, str]]:
        """Check for security concerns in the request."""
        concerns = []
        
        # Check for JWT in URL parameters
        if 'jwt' in url.lower() or 'token' in url.lower():
            concerns.append({
                'type': 'jwt_in_url',
                'severity': 'medium',
                'description': 'JWT token appears to be passed in URL parameters',
                'recommendation': 'Use Authorization header instead'
            })
        
        # Check for missing HTTPS
        if url.startswith('http://') and ('jwt' in url.lower() or 'token' in url.lower() or 'oauth' in url.lower()):
            concerns.append({
                'type': 'insecure_transport',
                'severity': 'high',
                'description': 'JWT/OAuth traffic over HTTP',
                'recommendation': 'Use HTTPS for all JWT/OAuth communications'
            })
        
        # Check for weak authentication headers
        auth_header = headers.get('Authorization', '') or headers.get('authorization', '')
        if auth_header and not auth_header.startswith('Bearer '):
            concerns.append({
                'type': 'weak_auth_header',
                'severity': 'low',
                'description': 'Non-standard Authorization header format',
                'recommendation': 'Use Bearer token format'
            })
        
        return concerns
    
    def _get_recommended_plugins(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Get recommended plugins based on analysis results."""
        recommended = []
        
        if analysis_result['contains_jwt']:
            recommended.append('JWTSecurityChecker')
        
        if analysis_result['contains_oauth']:
            recommended.append('JWTSecurityChecker')  # JWT plugin also handles OAuth
        
        if analysis_result['contains_graphql']:
            recommended.append('GraphQLSecurityChecker')
        
        # Always recommend general security plugins
        recommended.extend(['SecurityHeadersChecker', 'ComprehensiveSecurityChecker'])
        
        return list(set(recommended))  # Remove duplicates
    
    def should_run_jwt_plugin(self, requests_data: List[Dict[str, Any]]) -> bool:
        """
        Determine if JWT security plugin should be run based on request analysis.
        
        Args:
            requests_data: List of request dictionaries
            
        Returns:
            True if JWT plugin should be run, False otherwise
        """
        analysis = self.analyze_requests(requests_data)
        
        # Run JWT plugin if JWT tokens or OAuth flows are detected
        return analysis['contains_jwt'] or analysis['contains_oauth']
    
    def should_run_graphql_plugin(self, requests_data: List[Dict[str, Any]]) -> bool:
        """
        Determine if GraphQL security plugin should be run based on request analysis.
        
        Args:
            requests_data: List of request dictionaries
            
        Returns:
            True if GraphQL plugin should be run, False otherwise
        """
        analysis = self.analyze_requests(requests_data)
        
        # Run GraphQL plugin if GraphQL endpoints or operations are detected
        return analysis['contains_graphql']
    
    def get_jwt_analysis_summary(self, requests_data: List[Dict[str, Any]]) -> str:
        """
        Get a summary of JWT/OAuth analysis results.
        
        Args:
            requests_data: List of request dictionaries
            
        Returns:
            Summary string
        """
        analysis = self.analyze_requests(requests_data)
        
        summary_parts = []
        
        if analysis['contains_jwt']:
            summary_parts.append(f"JWT tokens detected: {len(analysis['jwt_tokens'])}")
        
        if analysis['contains_oauth']:
            summary_parts.append(f"OAuth flows detected: {len(analysis['oauth_flows'])}")
            summary_parts.append(f"OAuth endpoints found: {len(analysis['oauth_endpoints'])}")
        
        if analysis['security_concerns']:
            summary_parts.append(f"Security concerns: {len(analysis['security_concerns'])}")
        
        if analysis['recommended_plugins']:
            summary_parts.append(f"Recommended plugins: {', '.join(analysis['recommended_plugins'])}")
        
        return "; ".join(summary_parts) if summary_parts else "No JWT/OAuth indicators found"
    
    def get_graphql_analysis_summary(self, requests_data: List[Dict[str, Any]]) -> str:
        """
        Get a summary of GraphQL analysis results.
        
        Args:
            requests_data: List of request dictionaries
            
        Returns:
            Summary string
        """
        analysis = self.analyze_requests(requests_data)
        
        summary_parts = []
        
        if analysis['contains_graphql']:
            summary_parts.append(f"GraphQL endpoints detected: {len(analysis['graphql_endpoints'])}")
            summary_parts.append(f"GraphQL operations found: {len(analysis['graphql_operations'])}")
            
            # Add details about operation types
            operation_types = set()
            for op in analysis['graphql_operations']:
                if 'operation_type' in op:
                    operation_types.add(op['operation_type'])
            
            if operation_types:
                summary_parts.append(f"Operation types: {', '.join(operation_types)}")
        
        return "; ".join(summary_parts) if summary_parts else "No GraphQL indicators found"
