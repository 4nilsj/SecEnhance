#!/usr/bin/env python3
"""
Enhanced Intelligence Module
Advanced machine learning and heuristic-based intelligence for better test applicability
"""

import re
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import logging

class EnhancedIntelligenceChecker:
    """
    Enhanced intelligence checker using ML-like heuristics and pattern recognition
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Enhanced API detection patterns
        self.api_patterns = {
            'rest_api': [
                r'/api/v?\d+/',
                r'/rest/v?\d+/',
                r'/services/',
                r'/endpoints/',
                r'/resources/',
                r'/data/',
                r'/query/',
                r'/search/',
                r'/filter/',
                r'/sort/',
                r'/page/',
                r'/limit/',
                r'/offset/'
            ],
            'graphql': [
                r'/graphql',
                r'/gql',
                r'/query',
                r'/mutation',
                r'/subscription'
            ],
            'soap': [
                r'/soap',
                r'/wsdl',
                r'/ws/',
                r'/service'
            ],
            'websocket': [
                r'/ws',
                r'/websocket',
                r'/socket',
                r'/stream'
            ]
        }
        
        # Request complexity scoring
        self.complexity_factors = {
            'headers': {
                'authentication': ['authorization', 'x-api-key', 'x-auth-token', 'cookie'],
                'content': ['content-type', 'accept', 'content-length'],
                'security': ['x-frame-options', 'x-xss-protection', 'x-content-type-options'],
                'cors': ['origin', 'access-control-request-method', 'access-control-request-headers']
            },
            'parameters': {
                'sensitive': ['id', 'user', 'admin', 'token', 'key', 'secret', 'password'],
                'injection_prone': ['search', 'query', 'filter', 'sort', 'page', 'limit'],
                'file_related': ['file', 'upload', 'download', 'path', 'filename']
            }
        }
        
        # Vulnerability likelihood scoring
        self.vuln_likelihood = defaultdict(float)
        self._initialize_vuln_scores()
    
    def _initialize_vuln_scores(self):
        """Initialize vulnerability likelihood scores based on common patterns"""
        self.vuln_likelihood.update({
            'sql_injection': 0.3,
            'xss': 0.4,
            'ssrf': 0.2,
            'authentication_bypass': 0.3,
            'authorization_bypass': 0.4,
            'information_disclosure': 0.5,
            'rate_limiting_bypass': 0.2,
            'mass_assignment': 0.3,
            'request_smuggling': 0.1,
            'host_header_injection': 0.2,
            'parameter_pollution': 0.3,
            'cors_misconfiguration': 0.4,
            'jwt_vulnerabilities': 0.3,
            'graphql_introspection': 0.2,
            'prototype_pollution': 0.2
        })
    
    def analyze_request_complexity(self, request: Any) -> Dict[str, float]:
        """
        Analyze request complexity to determine testing priority
        
        Args:
            request: Request object to analyze
            
        Returns:
            Dictionary with complexity scores
        """
        complexity_scores = {
            'overall': 0.0,
            'headers': 0.0,
            'parameters': 0.0,
            'body': 0.0,
            'path': 0.0
        }
        
        try:
            # Path complexity
            path = getattr(request, 'path', '') or ''
            complexity_scores['path'] = self._score_path_complexity(path)
            
            # Headers complexity
            headers = getattr(request, 'headers', {}) or {}
            complexity_scores['headers'] = self._score_headers_complexity(headers)
            
            # Parameters complexity
            params = getattr(request, 'parameters', {}) or {}
            complexity_scores['parameters'] = self._score_parameters_complexity(params)
            
            # Body complexity
            body = getattr(request, 'body', '') or ''
            complexity_scores['body'] = self._score_body_complexity(body)
            
            # Overall complexity (weighted average)
            weights = {'path': 0.2, 'headers': 0.3, 'parameters': 0.3, 'body': 0.2}
            complexity_scores['overall'] = sum(
                complexity_scores[key] * weights[key] 
                for key in weights.keys()
            )
            
        except Exception as e:
            self.logger.warning(f"Error analyzing request complexity: {e}")
        
        return complexity_scores
    
    def _score_path_complexity(self, path: str) -> float:
        """Score path complexity based on depth and patterns"""
        if not path:
            return 0.0
        
        score = 0.0
        
        # Depth scoring
        depth = len([seg for seg in path.split('/') if seg])
        score += min(depth * 0.1, 0.5)
        
        # Pattern scoring
        for pattern_type, patterns in self.api_patterns.items():
            for pattern in patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    score += 0.2
                    break
        
        # Dynamic segment scoring
        dynamic_segments = re.findall(r'\{[^}]+\}|\[[^\]]+\]|\d+', path)
        score += len(dynamic_segments) * 0.1
        
        return min(score, 1.0)
    
    def _score_headers_complexity(self, headers: Dict[str, str]) -> float:
        """Score headers complexity based on security and content headers"""
        if not headers:
            return 0.0
        
        score = 0.0
        
        for header_type, header_names in self.complexity_factors['headers'].items():
            for header_name in header_names:
                if any(h.lower() == header_name.lower() for h in headers.keys()):
                    score += 0.2
        
        # Additional complexity for custom headers
        custom_headers = [h for h in headers.keys() if h.lower().startswith('x-')]
        score += len(custom_headers) * 0.1
        
        return min(score, 1.0)
    
    def _score_parameters_complexity(self, params: Dict[str, Any]) -> float:
        """Score parameters complexity based on sensitivity and injection potential"""
        if not params:
            return 0.0
        
        score = 0.0
        
        for param_type, param_names in self.complexity_factors['parameters'].items():
            for param_name in param_names:
                if any(p.lower() == param_name.lower() for p in params.keys()):
                    score += 0.2
        
        # Array parameter complexity
        array_params = [p for p in params.keys() if isinstance(params[p], list)]
        score += len(array_params) * 0.1
        
        # JSON parameter complexity
        json_params = [p for p in params.keys() if isinstance(params[p], dict)]
        score += len(json_params) * 0.15
        
        return min(score, 1.0)
    
    def _score_body_complexity(self, body: Any) -> float:
        """Score body complexity based on content and structure"""
        if not body:
            return 0.0
        
        score = 0.0
        
        try:
            if isinstance(body, str):
                # JSON complexity
                if body.strip().startswith('{') or body.strip().startswith('['):
                    try:
                        parsed = json.loads(body)
                        score += self._score_json_complexity(parsed)
                    except json.JSONDecodeError:
                        score += 0.1
                
                # XML complexity
                elif body.strip().startswith('<'):
                    score += 0.3
                
                # Form data complexity
                elif '=' in body and '&' in body:
                    score += 0.2
                
                # Length complexity
                score += min(len(body) / 1000, 0.3)
            
            elif isinstance(body, dict):
                score += self._score_json_complexity(body)
            
            elif isinstance(body, bytes):
                score += min(len(body) / 1000, 0.3)
        
        except Exception as e:
            self.logger.debug(f"Error scoring body complexity: {e}")
        
        return min(score, 1.0)
    
    def _score_json_complexity(self, data: Any, depth: int = 0) -> float:
        """Recursively score JSON complexity"""
        if depth > 5:  # Prevent infinite recursion
            return 0.5
        
        score = 0.0
        
        if isinstance(data, dict):
            score += len(data) * 0.05
            for value in data.values():
                score += self._score_json_complexity(value, depth + 1) * 0.1
        
        elif isinstance(data, list):
            score += len(data) * 0.03
            for item in data:
                score += self._score_json_complexity(item, depth + 1) * 0.05
        
        elif isinstance(data, (int, float)):
            score += 0.01
        
        elif isinstance(data, str):
            score += min(len(data) / 100, 0.1)
        
        return min(score, 1.0)
    
    def get_optimal_test_sequence(self, request: Any, available_tests: List[str]) -> List[str]:
        """
        Get optimal test sequence based on request analysis
        
        Args:
            request: Request object to test
            available_tests: List of available test names
            
        Returns:
            Ordered list of tests to run
        """
        try:
            # Analyze request complexity
            complexity = self.analyze_request_complexity(request)
            
            # Get applicability scores for each test
            test_scores = {}
            for test in available_tests:
                applicability = self.get_test_applicability(request, test)
                complexity_bonus = complexity['overall'] * 0.3
                test_scores[test] = applicability + complexity_bonus
            
            # Sort tests by score (highest first)
            sorted_tests = sorted(
                available_tests, 
                key=lambda x: test_scores[x], 
                reverse=True
            )
            
            self.logger.debug(f"Test sequence: {sorted_tests} (scores: {test_scores})")
            return sorted_tests
        
        except Exception as e:
            self.logger.warning(f"Error getting optimal test sequence: {e}")
            return available_tests
    
    def get_test_applicability(self, request: Any, test_name: str) -> float:
        """
        Get applicability score for a specific test
        
        Args:
            request: Request object to test
            test_name: Name of the test
            
        Returns:
            Applicability score (0.0 to 1.0)
        """
        base_score = self.vuln_likelihood.get(test_name, 0.2)
        
        # Apply request-specific modifiers
        modifiers = self._get_test_modifiers(request, test_name)
        final_score = base_score * modifiers
        
        return min(max(final_score, 0.0), 1.0)
    
    def _get_test_modifiers(self, request: Any, test_name: str) -> float:
        """Get request-specific modifiers for test applicability"""
        modifier = 1.0
        
        try:
            if test_name == 'sql_injection':
                modifier *= self._get_sql_injection_modifier(request)
            elif test_name == 'xss':
                modifier *= self._get_xss_modifier(request)
            elif test_name == 'ssrf':
                modifier *= self._get_ssrf_modifier(request)
            elif test_name == 'authentication_bypass':
                modifier *= self._get_auth_bypass_modifier(request)
            elif test_name == 'jwt_vulnerabilities':
                modifier *= self._get_jwt_modifier(request)
            elif test_name == 'graphql_introspection':
                modifier *= self._get_graphql_modifier(request)
            elif test_name == 'prototype_pollution':
                modifier *= self._get_prototype_pollution_modifier(request)
        
        except Exception as e:
            self.logger.debug(f"Error getting test modifier for {test_name}: {e}")
        
        return modifier
    
    def _get_sql_injection_modifier(self, request: Any) -> float:
        """Get SQL injection test modifier"""
        modifier = 1.0
        
        # Check for database-related parameters
        params = getattr(request, 'parameters', {}) or {}
        db_params = ['id', 'user_id', 'search', 'query', 'filter', 'sort']
        
        for param in db_params:
            if any(p.lower() == param for p in params.keys()):
                modifier *= 1.5
        
        # Check for numeric parameters
        for param_name, param_value in params.items():
            if isinstance(param_value, (int, str)) and str(param_value).isdigit():
                modifier *= 1.2
        
        return modifier
    
    def _get_xss_modifier(self, request: Any) -> float:
        """Get XSS test modifier"""
        modifier = 1.0
        
        # Check for user input parameters
        params = getattr(request, 'parameters', {}) or {}
        user_input_params = ['search', 'query', 'comment', 'message', 'content', 'text']
        
        for param in user_input_params:
            if any(p.lower() == param for p in params.keys()):
                modifier *= 1.4
        
        # Check for HTML content
        body = getattr(request, 'body', '') or ''
        if isinstance(body, str) and any(tag in body.lower() for tag in ['<', '>', 'script', 'img']):
            modifier *= 1.3
        
        return modifier
    
    def _get_ssrf_modifier(self, request: Any) -> float:
        """Get SSRF test modifier"""
        modifier = 1.0
        
        # Check for URL-like parameters
        params = getattr(request, 'parameters', {}) or {}
        url_params = ['url', 'uri', 'link', 'redirect', 'target', 'callback', 'path']
        
        for param in url_params:
            if any(p.lower() == param for p in params.keys()):
                modifier *= 2.0
        
        # Check for IP-like parameters
        for param_name, param_value in params.items():
            if isinstance(param_value, str) and re.match(r'^\d+\.\d+\.\d+\.\d+$', param_value):
                modifier *= 1.5
        
        return modifier
    
    def _get_auth_bypass_modifier(self, request: Any) -> float:
        """Get authentication bypass test modifier"""
        modifier = 1.0
        
        # Check for authentication headers
        headers = getattr(request, 'headers', {}) or {}
        auth_headers = ['authorization', 'x-api-key', 'x-auth-token', 'cookie']
        
        for header in auth_headers:
            if any(h.lower() == header for h in headers.keys()):
                modifier *= 1.3
        
        # Check for user/admin parameters
        params = getattr(request, 'parameters', {}) or {}
        user_params = ['user', 'admin', 'role', 'permission', 'access']
        
        for param in user_params:
            if any(p.lower() == param for p in params.keys()):
                modifier *= 1.4
        
        return modifier
    
    def _get_jwt_modifier(self, request: Any) -> float:
        """Get JWT vulnerabilities test modifier"""
        modifier = 1.0
        
        # Check for JWT in authorization header
        headers = getattr(request, 'headers', {}) or {}
        auth_header = headers.get('authorization', '') or ''
        
        if auth_header.lower().startswith('bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            if self._looks_like_jwt(token):
                modifier *= 2.0
        
        return modifier
    
    def _get_graphql_modifier(self, request: Any) -> float:
        """Get GraphQL introspection test modifier"""
        modifier = 1.0
        
        # Check for GraphQL endpoint
        path = getattr(request, 'path', '') or ''
        if '/graphql' in path.lower() or '/gql' in path.lower():
            modifier *= 2.0
        
        # Check for GraphQL content
        body = getattr(request, 'body', '') or ''
        if isinstance(body, str):
            graphql_indicators = ['query', 'mutation', 'subscription', '__schema', '__typename']
            if any(indicator in body.lower() for indicator in graphql_indicators):
                modifier *= 1.5
        
        return modifier
    
    def _get_prototype_pollution_modifier(self, request: Any) -> float:
        """Get prototype pollution test modifier"""
        modifier = 1.0
        
        # Check for JSON body
        body = getattr(request, 'body', '') or ''
        if isinstance(body, str) and body.strip().startswith('{'):
            modifier *= 1.3
        
        # Check for object parameters
        params = getattr(request, 'parameters', {}) or {}
        for param_value in params.values():
            if isinstance(param_value, dict):
                modifier *= 1.2
        
        return modifier
    
    def _looks_like_jwt(self, token: str) -> bool:
        """Check if a string looks like a JWT token"""
        if not token or len(token) < 10:
            return False
        
        # JWT format: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Check if parts are base64url encoded
        try:
            for part in parts:
                if not part or not re.match(r'^[A-Za-z0-9_-]+$', part):
                    return False
            return True
        except Exception:
            return False
    
    def update_vuln_likelihood(self, test_name: str, success_rate: float, false_positive_rate: float):
        """
        Update vulnerability likelihood based on testing results
        
        Args:
            test_name: Name of the test
            success_rate: Rate of successful detections
            false_positive_rate: Rate of false positives
        """
        if test_name in self.vuln_likelihood:
            # Adjust based on success rate and false positive rate
            current_score = self.vuln_likelihood[test_name]
            
            # Increase score for high success rate, decrease for high false positive rate
            adjustment = (success_rate - false_positive_rate) * 0.1
            new_score = current_score + adjustment
            
            # Keep score within reasonable bounds
            self.vuln_likelihood[test_name] = max(0.1, min(0.9, new_score))
            
            self.logger.info(f"Updated {test_name} likelihood: {current_score:.3f} -> {self.vuln_likelihood[test_name]:.3f}")
    
    def get_intelligence_summary(self) -> Dict[str, Any]:
        """Get summary of intelligence data"""
        return {
            'vulnerability_likelihood': dict(self.vuln_likelihood),
            'api_patterns': {k: len(v) for k, v in self.api_patterns.items()},
            'complexity_factors': {k: len(v) for k, v in self.complexity_factors.items()}
        }
