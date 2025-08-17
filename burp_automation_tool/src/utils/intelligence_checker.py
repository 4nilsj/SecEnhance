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
        """Analyze request complexity and return scoring factors"""
        try:
            complexity_scores = {
                'path_complexity': 0.0,
                'header_complexity': 0.0,
                'parameter_complexity': 0.0,
                'body_complexity': 0.0,
                'overall_complexity': 0.0
            }
            
            # Path complexity
            path = self._safe_get(request, 'url', '') or self._safe_get(request, 'path', '')
            if path:
                path_segments = path.split('/')
                complexity_scores['path_complexity'] = min(len(path_segments) * 0.1, 1.0)
            
            # Header complexity
            headers = self._safe_get(request, 'headers', {}) or {}
            if headers:
                header_count = len(headers)
                complexity_scores['header_complexity'] = min(header_count * 0.05, 1.0)
            
            # Parameter complexity
            params = self._safe_get(request, 'parameters', {}) or self._safe_get(request, 'params', {})
            if params:
                param_count = len(params)
                complexity_scores['parameter_complexity'] = min(param_count * 0.1, 1.0)
            
            # Body complexity
            body = self._safe_get(request, 'body', '')
            if body:
                if isinstance(body, dict):
                    complexity_scores['body_complexity'] = min(len(body) * 0.1, 1.0)
                elif isinstance(body, str):
                    complexity_scores['body_complexity'] = min(len(body) * 0.001, 1.0)
            
            # Overall complexity
            complexity_scores['overall_complexity'] = sum([
                complexity_scores['path_complexity'],
                complexity_scores['header_complexity'],
                complexity_scores['parameter_complexity'],
                complexity_scores['body_complexity']
            ]) / 4.0
            
            return complexity_scores
            
        except Exception as e:
            self.logger.error(f"Error analyzing request complexity: {e}")
            return {'overall_complexity': 0.5}
    
    def get_optimal_test_sequence(self, request: Any, available_tests: List[str]) -> List[str]:
        """Get optimal test sequence based on request analysis"""
        try:
            if not available_tests:
                return []
            
            # Analyze request complexity
            complexity = self.analyze_request_complexity(request)
            
            # Score each test based on likelihood and complexity
            test_scores = []
            for test in available_tests:
                score = 0.0
                
                # Base likelihood score
                score += self.vuln_likelihood.get(test, 0.1)
                
                # Complexity adjustment
                if complexity['overall_complexity'] > 0.7:
                    score *= 1.2  # High complexity requests get priority
                elif complexity['overall_complexity'] < 0.3:
                    score *= 0.8  # Low complexity requests get lower priority
                
                # API type adjustments
                if self._is_rest_api(request):
                    if test in ['sql_injection', 'xss', 'authentication_bypass']:
                        score *= 1.3
                elif self._is_graphql(request):
                    if test in ['graphql_introspection', 'authentication_bypass']:
                        score *= 1.4
                
                test_scores.append((test, score))
            
            # Sort by score and return
            test_scores.sort(key=lambda x: x[1], reverse=True)
            return [test for test, score in test_scores]
            
        except Exception as e:
            self.logger.error(f"Error getting optimal test sequence: {e}")
            return available_tests
    
    def get_test_applicability(self, request: Any, test_name: str) -> float:
        """Get applicability score for a specific test on a request"""
        try:
            base_score = self.vuln_likelihood.get(test_name, 0.1)
            
            # Request-specific adjustments
            if test_name == 'sql_injection':
                if self._has_injection_prone_params(request):
                    base_score *= 1.5
                if self._is_rest_api(request):
                    base_score *= 1.2
            
            elif test_name == 'xss':
                if self._has_content_params(request):
                    base_score *= 1.4
                if self._is_json_api(request):
                    base_score *= 1.3
            
            elif test_name == 'authentication_bypass':
                if self._has_auth_headers(request):
                    base_score *= 1.6
                if self._is_auth_endpoint(request):
                    base_score *= 1.4
            
            # Complexity adjustment
            complexity = self.analyze_request_complexity(request)
            if complexity['overall_complexity'] > 0.6:
                base_score *= 1.1
            
            return min(base_score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error getting test applicability: {e}")
            return 0.1
    
    def update_vuln_likelihood(self, test_name: str, success_rate: float, false_positive_rate: float):
        """Update vulnerability likelihood based on test results"""
        try:
            if test_name in self.vuln_likelihood:
                current_score = self.vuln_likelihood[test_name]
                
                # Adjust based on success rate
                if success_rate > 0.5:
                    new_score = current_score * (1 + success_rate * 0.2)
                else:
                    new_score = current_score * (1 - (1 - success_rate) * 0.1)
                
                # Adjust based on false positive rate
                if false_positive_rate < 0.3:
                    new_score *= 1.1
                elif false_positive_rate > 0.7:
                    new_score *= 0.9
                
                # Keep within bounds
                self.vuln_likelihood[test_name] = max(0.05, min(0.95, new_score))
                
        except Exception as e:
            self.logger.error(f"Error updating vulnerability likelihood: {e}")
    
    def get_intelligence_summary(self) -> Dict[str, Any]:
        """Get summary of intelligence data"""
        try:
            return {
                'vulnerability_likelihood': dict(self.vuln_likelihood),
                'api_patterns': {k: len(v) for k, v in self.api_patterns.items()},
                'complexity_factors': {k: len(v) for k, v in self.complexity_factors.items()},
                'total_patterns': sum(len(patterns) for patterns in self.api_patterns.values()),
                'total_factors': sum(len(factors) for factors in self.complexity_factors.values())
            }
        except Exception as e:
            self.logger.error(f"Error getting intelligence summary: {e}")
            return {}
    
    def _safe_get(self, request: Any, attr: str, default: Any = None) -> Any:
        """Safely get attribute from request object"""
        try:
            if hasattr(request, attr):
                return getattr(request, attr)
            elif isinstance(request, dict):
                return request.get(attr, default)
            else:
                return default
        except:
            return default
    
    def _is_rest_api(self, request: Any) -> bool:
        """Check if request is to a REST API"""
        path = self._safe_get(request, 'url', '') or self._safe_get(request, 'path', '')
        return any(re.search(pattern, path) for pattern in self.api_patterns['rest_api'])
    
    def _is_graphql(self, request: Any) -> bool:
        """Check if request is to a GraphQL endpoint"""
        path = self._safe_get(request, 'url', '') or self._safe_get(request, 'path', '')
        return any(re.search(pattern, path) for pattern in self.api_patterns['graphql'])
    
    def _is_json_api(self, request: Any) -> bool:
        """Check if request uses JSON"""
        headers = self._safe_get(request, 'headers', {}) or {}
        content_type = headers.get('content-type', '').lower()
        return 'json' in content_type
    
    def _has_injection_prone_params(self, request: Any) -> bool:
        """Check if request has injection-prone parameters"""
        params = self._safe_get(request, 'parameters', {}) or self._safe_get(request, 'params', {})
        injection_keys = self.complexity_factors['parameters']['injection_prone']
        return any(key.lower() in str(param).lower() for param in params for key in injection_keys)
    
    def _has_content_params(self, request: Any) -> bool:
        """Check if request has content-related parameters"""
        params = self._safe_get(request, 'parameters', {}) or self._safe_get(request, 'params', {})
        content_keys = ['content', 'message', 'comment', 'description', 'text']
        return any(key.lower() in str(param).lower() for param in params for key in content_keys)
    
    def _has_auth_headers(self, request: Any) -> bool:
        """Check if request has authentication headers"""
        headers = self._safe_get(request, 'headers', {}) or {}
        auth_keys = self.complexity_factors['headers']['authentication']
        return any(key.lower() in str(header).lower() for header in headers for key in auth_keys)
    
    def _is_auth_endpoint(self, request: Any) -> bool:
        """Check if request is to an authentication endpoint"""
        path = self._safe_get(request, 'url', '') or self._safe_get(request, 'path', '')
        auth_patterns = ['/login', '/auth', '/signin', '/oauth', '/token']
        return any(pattern in path.lower() for pattern in auth_patterns)