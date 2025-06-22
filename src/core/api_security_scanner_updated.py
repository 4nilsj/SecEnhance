#!/usr/bin/env python3
"""
Updated API Security Scanner
Comprehensive API security scanner with Swagger/OpenAPI support and performance optimization
"""

import time
import json
import requests
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PerformanceOptimizer:
    """Performance optimization utilities"""
    
    def __init__(self, max_workers: int = 10, max_connections: int = 100, 
                 cache_size: int = 1000, max_requests_per_second: int = 10):
        self.max_workers = max_workers
        self.max_connections = max_connections
        self.cache_size = cache_size
        self.max_requests_per_second = max_requests_per_second
        self.cache = {}
        self.request_times = []
        self.session = requests.Session()
        
        # Configure session for better performance
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=max_connections,
            pool_maxsize=max_connections,
            max_retries=3
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
    
    def cached_request(self, url: str, method: str = 'GET', **kwargs) -> Dict[str, Any]:
        """Make a cached request"""
        cache_key = f"{method}:{url}:{hash(str(kwargs))}"
        
        if cache_key in self.cache:
            logger.debug(f"Cache HIT: {url}")
            return self.cache[cache_key]
        
        logger.debug(f"Cache MISS: {url}")
        start_time = time.time()
        
        try:
            response = self.session.request(method, url, timeout=10, **kwargs)
            duration = time.time() - start_time
            
            result = {
                'status_code': response.status_code,
                'duration': duration,
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'content': response.text,
                'url': url,
                'method': method,
                'success': True
            }
            
            # Cache the result
            if len(self.cache) < self.cache_size:
                self.cache[cache_key] = result
            
            self.request_times.append(duration)
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            result = {
                'status_code': 'error',
                'duration': duration,
                'error': str(e),
                'url': url,
                'method': method,
                'success': False
            }
            self.request_times.append(duration)
            return result
    
    def parallel_requests(self, requests_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute multiple requests in parallel"""
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for req in requests_list:
                future = executor.submit(self.cached_request, req['url'], req.get('method', 'GET'), **req.get('kwargs', {}))
                futures.append(future)
            
            results = []
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({'error': str(e), 'success': False})
        
        total_time = time.time() - start_time
        logger.info(f"Parallel requests completed in {total_time:.3f}s")
        
        return results
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        if not self.request_times:
            return {}
        
        return {
            'total_requests': len(self.request_times),
            'avg_response_time': sum(self.request_times) / len(self.request_times),
            'min_response_time': min(self.request_times),
            'max_response_time': max(self.request_times),
            'requests_per_second': len(self.request_times) / sum(self.request_times) if sum(self.request_times) > 0 else 0,
            'cache_size': len(self.cache),
            'cache_hit_rate': len([r for r in self.cache.values() if r.get('cached', False)]) / len(self.cache) if self.cache else 0
        }

class APISecurityScanner:
    """Comprehensive API security scanner with performance optimization"""
    
    def __init__(self, session: Optional[requests.Session] = None, 
                 auth_config: Optional[Dict[str, Any]] = None,
                 enable_optimization: bool = True, 
                 max_workers: int = 10):
        
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'API-Security-Scanner/2.0'
        })
        
        # Authentication configuration
        self.auth_config = auth_config or {}
        self.apply_auth_config()
        
        # Performance optimization
        self.enable_optimization = enable_optimization
        if enable_optimization:
            self.optimizer = PerformanceOptimizer(max_workers=max_workers)
        else:
            self.optimizer = None
        
        # API security test configurations
        self.api_tests = self.load_api_security_tests()
        self.scan_results = {}
        
        logger.info("APISecurityScanner initialized successfully")
    
    def apply_auth_config(self):
        """Apply authentication configuration to session"""
        if not self.auth_config:
            return
        
        # Apply global headers
        if 'headers' in self.auth_config:
            self.session.headers.update(self.auth_config['headers'])
        
        # Apply authentication
        auth_type = self.auth_config.get('type', '')
        
        if auth_type == 'bearer':
            token = self.auth_config.get('token', '')
            if token:
                self.session.headers['Authorization'] = f'Bearer {token}'
        
        elif auth_type == 'apikey':
            key = self.auth_config.get('key', '')
            value = self.auth_config.get('value', '')
            location = self.auth_config.get('location', 'header')
            
            if location == 'header':
                self.session.headers[key] = value
        
        elif auth_type == 'basic':
            username = self.auth_config.get('username', '')
            password = self.auth_config.get('password', '')
            if username and password:
                self.session.auth = (username, password)
        
        elif auth_type == 'oauth2':
            token = self.auth_config.get('access_token', '')
            if token:
                self.session.headers['Authorization'] = f'Bearer {token}'
    
    def load_api_security_tests(self) -> Dict[str, Any]:
        """Load comprehensive API security test configurations including OWASP API Top 10"""
        return {
            # OWASP API Top 10 - 2023
            'api1_broken_object_property_level_authorization': {
                'name': 'API1:2023 - Broken Object Property Level Authorization',
                'description': 'Test for unauthorized access to object properties',
                'owasp_category': 'API1:2023',
                'severity': 'Critical',
                'tests': [
                    {
                        'name': 'Property Enumeration',
                        'method': 'GET',
                        'params': {'fields': 'id,name,email,password,ssn,credit_card'},
                        'json': {'fields': 'id,name,email,password,ssn,credit_card'}
                    },
                    {
                        'name': 'Mass Assignment',
                        'method': 'POST',
                        'json': {'id': 1, 'role': 'admin', 'is_admin': True, 'permissions': 'all'}
                    }
                ]
            },
            'api2_broken_authentication': {
                'name': 'API2:2023 - Broken Authentication',
                'description': 'Test for authentication vulnerabilities',
                'owasp_category': 'API2:2023',
                'severity': 'Critical',
                'tests': [
                    {
                        'name': 'Weak Credentials',
                        'method': 'POST',
                        'json': {'username': 'admin', 'password': 'admin'}
                    },
                    {
                        'name': 'Empty Password',
                        'method': 'POST',
                        'json': {'username': 'admin', 'password': ''}
                    },
                    {
                        'name': 'SQL Injection in Auth',
                        'method': 'POST',
                        'json': {'username': "admin'--", 'password': 'anything'}
                    }
                ]
            },
            'api3_broken_object_property_level_authorization': {
                'name': 'API3:2023 - Broken Object Property Level Authorization',
                'description': 'Test for object-level authorization bypass',
                'owasp_category': 'API3:2023',
                'severity': 'Critical',
                'tests': [
                    {
                        'name': 'IDOR Test',
                        'method': 'GET',
                        'path_params': {'id': 1}
                    },
                    {
                        'name': 'Unauthorized Access',
                        'method': 'GET',
                        'path_params': {'id': 999}
                    }
                ]
            },
            'api4_unlimited_resource_consumption': {
                'name': 'API4:2023 - Unlimited Resource Consumption',
                'description': 'Test for resource exhaustion vulnerabilities',
                'owasp_category': 'API4:2023',
                'severity': 'High',
                'tests': [
                    {
                        'name': 'Large Payload',
                        'method': 'POST',
                        'json': {'data': 'A' * 1000000}
                    },
                    {
                        'name': 'Deep JSON',
                        'method': 'POST',
                        'json': self.generate_deep_nested_json(100)
                    }
                ]
            },
            'api5_broken_function_level_authorization': {
                'name': 'API5:2023 - Broken Function Level Authorization',
                'description': 'Test for function-level authorization bypass',
                'owasp_category': 'API5:2023',
                'severity': 'Critical',
                'tests': [
                    {
                        'name': 'Admin Function Access',
                        'method': 'GET',
                        'params': {'admin': 'true', 'debug': 'true'}
                    },
                    {
                        'name': 'Privilege Escalation',
                        'method': 'POST',
                        'json': {'action': 'create_admin', 'role': 'superuser'}
                    }
                ]
            },
            'api6_unrestricted_access_to_sensitive_business_flows': {
                'name': 'API6:2023 - Unrestricted Access to Sensitive Business Flows',
                'description': 'Test for business logic vulnerabilities',
                'owasp_category': 'API6:2023',
                'severity': 'High',
                'tests': [
                    {
                        'name': 'Purchase Without Payment',
                        'method': 'POST',
                        'json': {'item_id': 1, 'quantity': 10, 'payment_required': False}
                    },
                    {
                        'name': 'Bypass Rate Limiting',
                        'method': 'POST',
                        'json': {'action': 'reset_password', 'email': 'admin@test.com'}
                    }
                ]
            },
            'api7_server_side_request_forgery': {
                'name': 'API7:2023 - Server Side Request Forgery',
                'description': 'Test for SSRF vulnerabilities',
                'owasp_category': 'API7:2023',
                'severity': 'High',
                'tests': [
                    {
                        'name': 'Internal Network Access',
                        'method': 'GET',
                        'params': {'url': 'http://localhost:8080/admin'}
                    },
                    {
                        'name': 'AWS Metadata',
                        'method': 'GET',
                        'params': {'url': 'http://169.254.169.254/latest/meta-data/'}
                    }
                ]
            },
            'api8_security_misconfiguration': {
                'name': 'API8:2023 - Security Misconfiguration',
                'description': 'Test for security configuration issues',
                'owasp_category': 'API8:2023',
                'severity': 'Medium',
                'tests': [
                    {
                        'name': 'Debug Endpoints',
                        'method': 'GET',
                        'params': {'debug': 'true', 'verbose': 'true'}
                    },
                    {
                        'name': 'Error Information',
                        'method': 'GET',
                        'params': {'error': 'true', 'trace': 'true'}
                    }
                ]
            },
            'api9_improper_inventory_management': {
                'name': 'API9:2023 - Improper Inventory Management',
                'description': 'Test for deprecated API vulnerabilities',
                'owasp_category': 'API9:2023',
                'severity': 'Medium',
                'tests': [
                    {
                        'name': 'Deprecated Version',
                        'method': 'GET',
                        'headers': {'API-Version': 'v1'}
                    },
                    {
                        'name': 'Old Endpoint',
                        'method': 'GET',
                        'path': '/api/v1/users'
                    }
                ]
            },
            'api10_unsafe_consumption_of_apis': {
                'name': 'API10:2023 - Unsafe Consumption of APIs',
                'description': 'Test for unsafe API consumption patterns',
                'owasp_category': 'API10:2023',
                'severity': 'Medium',
                'tests': [
                    {
                        'name': 'Unvalidated Redirect',
                        'method': 'GET',
                        'params': {'redirect': 'https://evil.com'}
                    },
                    {
                        'name': 'Unsafe Deserialization',
                        'method': 'POST',
                        'json': {'data': '{"__class__": "os.system", "args": ["whoami"]}'}
                    }
                ]
            },
            # Additional security tests
            'sql_injection': {
                'name': 'SQL Injection',
                'description': 'Test for SQL injection vulnerabilities',
                'severity': 'Critical',
                'tests': [
                    {
                        'name': 'Basic SQL Injection',
                        'method': 'GET',
                        'params': {'search': "' OR 1=1--"}
                    },
                    {
                        'name': 'Union SQL Injection',
                        'method': 'GET',
                        'params': {'search': "' UNION SELECT * FROM users--"}
                    },
                    {
                        'name': 'Drop Table',
                        'method': 'GET',
                        'params': {'search': "'; DROP TABLE users--"}
                    }
                ]
            },
            'xss': {
                'name': 'Cross-Site Scripting (XSS)',
                'description': 'Test for XSS vulnerabilities',
                'severity': 'High',
                'tests': [
                    {
                        'name': 'Basic XSS',
                        'method': 'GET',
                        'params': {'name': '<script>alert("XSS")</script>'}
                    },
                    {
                        'name': 'JavaScript XSS',
                        'method': 'GET',
                        'params': {'name': 'javascript:alert("XSS")'}
                    },
                    {
                        'name': 'Image XSS',
                        'method': 'GET',
                        'params': {'name': '<img src=x onerror=alert("XSS")>'}
                    }
                ]
            },
            'information_disclosure': {
                'name': 'Information Disclosure',
                'description': 'Test for sensitive information disclosure',
                'severity': 'Medium',
                'tests': [
                    {
                        'name': 'Debug Information',
                        'method': 'GET',
                        'params': {'debug': 'true'}
                    },
                    {
                        'name': 'Error Messages',
                        'method': 'GET',
                        'params': {'error': 'true'}
                    },
                    {
                        'name': 'Version Information',
                        'method': 'GET',
                        'params': {'version': 'true'}
                    }
                ]
            },
            'rate_limiting': {
                'name': 'Rate Limiting Bypass',
                'description': 'Test for rate limiting vulnerabilities',
                'severity': 'Medium',
                'tests': [
                    {
                        'name': 'Rapid Requests',
                        'method': 'GET',
                        'count': 20
                    }
                ]
            }
        }
    
    def generate_deep_nested_json(self, depth: int) -> dict:
        """Generate a deeply nested JSON object for testing parser/resource exhaustion"""
        result = value = {}
        for i in range(depth):
            value[f"level_{i}"] = {}
            value = value[f"level_{i}"]
        value["end"] = "test"
        return result
    
    def scan_api_endpoints(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan API endpoints for security vulnerabilities"""
        logger.info(f"Starting security scan for {len(endpoints)} endpoints")
        
        start_time = time.time()
        all_vulnerabilities = []
        test_results = {}
        
        for endpoint in endpoints:
            # Use full_url if available, otherwise construct from base_url and path
            if 'full_url' in endpoint:
                endpoint_url = endpoint['full_url']
            else:
                endpoint_url = urljoin(endpoint['base_url'], endpoint['path'])
            
            logger.info(f"Scanning endpoint: {endpoint_url}")
            
            endpoint_vulns = []
            
            # Test each security category
            for category, test_config in self.api_tests.items():
                category_vulns = self._run_security_test(
                    endpoint_url, 
                    endpoint['method'], 
                    category, 
                    test_config
                )
                endpoint_vulns.extend(category_vulns)
                
                # Store test results
                test_results[category] = {
                    'tests_run': len(test_config['tests']),
                    'tests_skipped': 0,
                    'vulnerabilities': category_vulns
                }
            
            all_vulnerabilities.extend(endpoint_vulns)
        
        scan_duration = time.time() - start_time
        
        # Calculate vulnerability summary
        summary = self._calculate_vulnerability_summary(all_vulnerabilities)
        
        # Get performance metrics
        performance_metrics = {}
        if self.optimizer:
            performance_metrics = self.optimizer.get_performance_metrics()
        
        return {
            'scan_info': {
                'start_time': datetime.fromtimestamp(start_time).isoformat(),
                'duration': scan_duration,
                'endpoints_scanned': len(endpoints),
                'total_tests': sum(len(test_config['tests']) for test_config in self.api_tests.values())
            },
            'vulnerabilities': all_vulnerabilities,
            'summary': summary,
            'test_results': test_results,
            'performance_metrics': performance_metrics,
            'scanned_endpoints': len(endpoints)
        }
    
    def scan_api_endpoints_optimized(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan API endpoints with performance optimization"""
        logger.info(f"Starting optimized security scan for {len(endpoints)} endpoints")
        
        if not self.optimizer:
            return self.scan_api_endpoints(endpoints)
        
        start_time = time.time()
        all_vulnerabilities = []
        test_results = {}
        
        # Prepare all requests for parallel execution
        all_requests = []
        
        for endpoint in endpoints:
            # Use full_url if available, otherwise construct from base_url and path
            if 'full_url' in endpoint:
                endpoint_url = endpoint['full_url']
            else:
                endpoint_url = urljoin(endpoint['base_url'], endpoint['path'])
            
            for category, test_config in self.api_tests.items():
                for test in test_config['tests']:
                    request_data = {
                        'url': endpoint_url,
                        'method': test.get('method', endpoint['method']),
                        'kwargs': {}
                    }
                    
                    # Add parameters
                    if 'params' in test:
                        request_data['kwargs']['params'] = test['params']
                    
                    # Add JSON data
                    if 'json' in test:
                        request_data['kwargs']['json'] = test['json']
                    
                    # Add headers
                    if 'headers' in test:
                        request_data['kwargs']['headers'] = test['headers']
                    
                    all_requests.append(request_data)
        
        # Update progress for initialization
        total_requests = len(all_requests)
        self.update_scan_progress(0, total_requests, 'initializing')
        
        # Execute requests in parallel with progress tracking
        logger.info(f"Executing {len(all_requests)} requests in parallel")
        
        # Custom parallel execution with progress tracking
        completed_requests = 0
        
        def make_request_with_progress(request_data):
            nonlocal completed_requests
            try:
                response = self.optimizer.cached_request(
                    request_data['url'], 
                    request_data['method'], 
                    **request_data['kwargs']
                )
                completed_requests += 1
                self.update_scan_progress(completed_requests, total_requests, 'running')
                return response
            except Exception as e:
                completed_requests += 1
                self.update_scan_progress(completed_requests, total_requests, 'running')
                return {'error': str(e), 'success': False}
        
        # Execute in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.optimizer.max_workers) as executor:
            futures = [executor.submit(make_request_with_progress, req) for req in all_requests]
            responses = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # Update progress for analysis
        self.update_scan_progress(total_requests, total_requests, 'analyzing')
        
        # Analyze responses for vulnerabilities
        for i, response in enumerate(responses):
            if response.get('success', False):
                request_data = all_requests[i]
                vulns = self._analyze_response_for_vulnerabilities(
                    response, 
                    request_data['url'], 
                    request_data['method']
                )
                all_vulnerabilities.extend(vulns)
        
        scan_duration = time.time() - start_time
        
        # Update progress to completed
        self.update_scan_progress(total_requests, total_requests, 'completed')
        
        # Calculate vulnerability summary
        summary = self._calculate_vulnerability_summary(all_vulnerabilities)
        
        # Get performance metrics
        performance_metrics = self.optimizer.get_performance_metrics()
        
        # Optimization stats
        optimization_stats = {
            'cache_hit_rate': performance_metrics.get('cache_hit_rate', 0),
            'requests_per_second': performance_metrics.get('requests_per_second', 0),
            'avg_response_time': performance_metrics.get('avg_response_time', 0),
            'test_effectiveness': {cat: len(self.api_tests[cat]['tests']) for cat in self.api_tests.keys()}
        }
        
        return {
            'scan_info': {
                'start_time': datetime.fromtimestamp(start_time).isoformat(),
                'duration': scan_duration,
                'endpoints_scanned': len(endpoints),
                'total_tests': len(all_requests)
            },
            'vulnerabilities': all_vulnerabilities,
            'summary': summary,
            'test_results': test_results,
            'performance_metrics': performance_metrics,
            'optimization_stats': optimization_stats,
            'scanned_endpoints': len(endpoints)
        }
    
    def _run_security_test(self, url: str, method: str, test_category: str, 
                          test_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run security tests for a specific category"""
        vulnerabilities = []
        
        for test in test_config['tests']:
            try:
                test_method = test.get('method', method)
                test_url = url
                
                # Prepare request parameters
                kwargs = {}
                
                if 'params' in test:
                    kwargs['params'] = test['params']
                
                if 'json' in test:
                    kwargs['json'] = test['json']
                
                if 'headers' in test:
                    kwargs['headers'] = test['headers']
                
                # Make request
                if self.optimizer:
                    response = self.optimizer.cached_request(test_url, test_method, **kwargs)
                else:
                    response = self.session.request(test_method, test_url, timeout=10, **kwargs)
                    response = {
                        'status_code': response.status_code,
                        'content': response.text,
                        'headers': dict(response.headers),
                        'url': test_url,
                        'method': test_method,
                        'success': True
                    }
                
                # Analyze response for vulnerabilities
                vulns = self._analyze_response_for_vulnerabilities(
                    response, test_category, test
                )
                vulnerabilities.extend(vulns)
                
            except Exception as e:
                logger.error(f"Error running test {test.get('name', 'unknown')}: {e}")
        
        return vulnerabilities
    
    def _analyze_response_for_vulnerabilities(self, response: Dict[str, Any], 
                                            test_category: str, test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze response for security vulnerabilities"""
        vulnerabilities = []
        
        if not response.get('success', False):
            return vulnerabilities
        
        status_code = response.get('status_code', 0)
        content = response.get('content', '').lower()
        url = response.get('url', '')
        
        # Check for SQL injection
        if test_category == 'sql_injection':
            vulns = self._check_sql_injection(response, test_category, test)
            vulnerabilities.extend(vulns)
        
        # Check for XSS
        elif test_category == 'xss':
            vulns = self._check_xss(response, test_category, test)
            vulnerabilities.extend(vulns)
        
        # Check for authentication bypass
        elif 'authentication' in test_category.lower() or 'auth' in test_category.lower():
            vulns = self._check_auth_bypass(response, test_category, test)
            vulnerabilities.extend(vulns)
        
        # Check for information disclosure
        elif 'information' in test_category.lower():
            vulns = self._check_info_disclosure(response, test_category, test)
            vulnerabilities.extend(vulns)
        
        # Check for rate limiting bypass
        elif 'rate' in test_category.lower():
            vulns = self._check_rate_limiting(response, test_category, test)
            vulnerabilities.extend(vulns)
        
        # Generic vulnerability checks
        vulns = self._check_generic_vulnerabilities(response, test_category, test)
        vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _check_sql_injection(self, response: Dict[str, Any], test_category: str, 
                           test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        status_code = response.get('status_code', 0)
        content = response.get('content', '').lower()
        
        # Check for SQL error indicators
        sql_indicators = ['sql', 'mysql', 'oracle', 'postgresql', 'sqlite', 'syntax error']
        
        if status_code == 500:
            for indicator in sql_indicators:
                if indicator in content:
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'description': f'SQL injection detected with indicator: {indicator}',
                        'url': response.get('url', ''),
                        'test_category': test_category,
                        'payload': test.get('params', {}).get('search', 'unknown'),
                        'status_code': status_code
                    })
                    break
        
        # Check for unusual response patterns
        elif status_code == 200 and len(response.get('content', '')) > 100:
            # Large response might indicate successful injection
            vulnerabilities.append({
                'type': 'SQL Injection',
                'severity': 'High',
                'description': 'Potential SQL injection - unusual response size',
                'url': response.get('url', ''),
                'test_category': test_category,
                'payload': test.get('params', {}).get('search', 'unknown'),
                'status_code': status_code
            })
        
        return vulnerabilities
    
    def _check_xss(self, response: Dict[str, Any], test_category: str, 
                  test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for XSS vulnerabilities"""
        vulnerabilities = []
        
        content = response.get('content', '')
        payload = test.get('params', {}).get('name', '')
        
        # Check if payload is reflected in response
        if payload and payload in content:
            vulnerabilities.append({
                'type': 'Cross-Site Scripting (XSS)',
                'severity': 'High',
                'description': f'XSS payload reflected in response: {payload}',
                'url': response.get('url', ''),
                'test_category': test_category,
                'payload': payload,
                'status_code': response.get('status_code', 0)
            })
        
        return vulnerabilities
    
    def _check_auth_bypass(self, response: Dict[str, Any], test_category: str, 
                          test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for authentication bypass vulnerabilities"""
        vulnerabilities = []
        
        status_code = response.get('status_code', 0)
        content = response.get('content', '').lower()
        
        # Check for sensitive data in response
        sensitive_indicators = ['admin', 'password', 'secret', 'key', 'token']
        
        if status_code == 200:
            for indicator in sensitive_indicators:
                if indicator in content:
                    vulnerabilities.append({
                        'type': 'Authentication Bypass',
                        'severity': 'Critical',
                        'description': f'Authentication bypass - sensitive data accessible: {indicator}',
                        'url': response.get('url', ''),
                        'test_category': test_category,
                        'indicator': indicator,
                        'status_code': status_code
                    })
                    break
        
        return vulnerabilities
    
    def _check_info_disclosure(self, response: Dict[str, Any], test_category: str, 
                              test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for information disclosure vulnerabilities"""
        vulnerabilities = []
        
        status_code = response.get('status_code', 0)
        content = response.get('content', '').lower()
        
        if status_code == 200:
            # Check for debug information
            debug_indicators = ['debug', 'trace', 'error', 'stack', 'exception']
            
            for indicator in debug_indicators:
                if indicator in content:
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'Medium',
                        'description': f'Debug information disclosed: {indicator}',
                        'url': response.get('url', ''),
                        'test_category': test_category,
                        'indicator': indicator,
                        'status_code': status_code
                    })
                    break
        
        return vulnerabilities
    
    def _check_rate_limiting(self, response: Dict[str, Any], test_category: str, 
                           test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for rate limiting vulnerabilities"""
        vulnerabilities = []
        
        status_code = response.get('status_code', 0)
        
        # If multiple requests succeed without rate limiting
        if status_code == 200:
            vulnerabilities.append({
                'type': 'Rate Limiting Bypass',
                'severity': 'Medium',
                'description': 'No rate limiting detected',
                'url': response.get('url', ''),
                'test_category': test_category,
                'status_code': status_code
            })
        
        return vulnerabilities
    
    def _check_generic_vulnerabilities(self, response: Dict[str, Any], test_category: str, 
                                     test: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for generic vulnerabilities"""
        vulnerabilities = []
        
        status_code = response.get('status_code', 0)
        content = response.get('content', '').lower()
        
        # Check for server information disclosure
        if 'server' in response.get('headers', {}):
            server_header = response['headers']['server']
            if any(tech in server_header.lower() for tech in ['apache', 'nginx', 'iis']):
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'description': f'Server information disclosed: {server_header}',
                    'url': response.get('url', ''),
                    'test_category': test_category,
                    'server_info': server_header,
                    'status_code': status_code
                })
        
        return vulnerabilities
    
    def _calculate_vulnerability_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate vulnerability summary by severity"""
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        if not self.optimizer:
            return {'error': 'Performance optimization not enabled'}
        
        metrics = self.optimizer.get_performance_metrics()
        
        # Calculate cache performance
        cache_performance = {
            'total_hits': len([r for r in self.optimizer.cache.values() if r.get('cached', False)]),
            'total_misses': len(self.optimizer.request_times) - len([r for r in self.optimizer.cache.values() if r.get('cached', False)]),
            'hit_rate': len([r for r in self.optimizer.cache.values() if r.get('cached', False)]) / len(self.optimizer.request_times) if self.optimizer.request_times else 0
        }
        
        return {
            'metrics': metrics,
            'cache_performance': cache_performance,
            'optimization_enabled': self.enable_optimization,
            'max_workers': self.optimizer.max_workers if self.optimizer else None,
            'cache_size': self.optimizer.cache_size if self.optimizer else None
        }
    
    def generate_api_security_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate comprehensive API security report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f'api_security_report_{timestamp}.json'
        
        # Add metadata to results
        report_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'scanner_version': '2.0',
                'report_type': 'API Security Scan',
                'total_endpoints': scan_results.get('scanned_endpoints', 0),
                'total_vulnerabilities': len(scan_results.get('vulnerabilities', [])),
                'scan_duration': scan_results.get('scan_info', {}).get('duration', 0)
            },
            'scan_results': scan_results,
            'performance_metrics': self.get_performance_report() if self.optimizer else {}
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"API security report generated: {report_file}")
        return report_file
    
    def generate_owasp_report(self, scan_results: Dict[str, Any], format: str = 'html') -> str:
        """Generate OWASP API Top 10 report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format == 'html':
            report_file = f'owasp_api_report_{timestamp}.html'
            
            # Group vulnerabilities by OWASP category
            owasp_vulns = {}
            for vuln in scan_results.get('vulnerabilities', []):
                category = vuln.get('owasp_category', 'Other')
                if category not in owasp_vulns:
                    owasp_vulns[category] = []
                owasp_vulns[category].append(vuln)
            
            # Generate HTML report
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>OWASP API Top 10 Security Report</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; padding: 15px; background: #e9ecef; border-radius: 5px; }}
        .vulnerability {{ margin: 10px 0; padding: 15px; border-left: 4px solid #dc3545; background: #f8f9fa; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #28a745; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 OWASP API Top 10 Security Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Scan Summary</h2>
        <p><strong>Total Endpoints Scanned:</strong> {scan_results.get('scanned_endpoints', 0)}</p>
        <p><strong>Total Vulnerabilities Found:</strong> {len(scan_results.get('vulnerabilities', []))}</p>
        <p><strong>Scan Duration:</strong> {scan_results.get('scan_info', {}).get('duration', 0):.2f} seconds</p>
    </div>
    
    <h2>🚨 Vulnerabilities by OWASP Category</h2>
"""
            
            for category, vulns in owasp_vulns.items():
                html_content += f"""
    <h3>{category}</h3>
    <p>Found {len(vulns)} vulnerabilities</p>
"""
                
                for vuln in vulns:
                    severity_class = f"severity-{vuln.get('severity', 'medium').lower()}"
                    vuln_class = f"vulnerability {vuln.get('severity', 'medium').lower()}"
                    
                    html_content += f"""
    <div class="{vuln_class}">
        <h4><span class="{severity_class}">{vuln.get('severity', 'Medium')}</span> - {vuln.get('name', 'Unknown Vulnerability')}</h4>
        <p><strong>Endpoint:</strong> {vuln.get('endpoint', 'N/A')}</p>
        <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
        <p><strong>Test Category:</strong> {vuln.get('test_category', 'N/A')}</p>
        <p><strong>Details:</strong> {vuln.get('details', 'No additional details')}</p>
    </div>
"""
            
            html_content += """
</body>
</html>
"""
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"OWASP HTML report generated: {report_file}")
            return report_file
        
        else:
            # JSON format
            report_file = f'owasp_api_report_{timestamp}.json'
            report_data = {
                'owasp_report': {
                    'generated_at': datetime.now().isoformat(),
                    'format': format,
                    'vulnerabilities_by_category': owasp_vulns,
                    'summary': {
                        'total_vulnerabilities': len(scan_results.get('vulnerabilities', [])),
                        'categories_found': list(owasp_vulns.keys())
                    }
                }
            }
            
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            logger.info(f"OWASP JSON report generated: {report_file}")
            return report_file
    
    def set_auth_config(self, auth_config: Dict[str, Any]):
        """Set authentication configuration"""
        self.auth_config = auth_config
        self.apply_auth_config()
        logger.info(f"Authentication configuration updated: {auth_config.get('type', 'unknown')}")
    
    def get_scan_progress(self) -> Dict[str, Any]:
        """Get current scan progress"""
        if not hasattr(self, '_scan_progress'):
            return {'status': 'not_started', 'progress': 0}
        
        return self._scan_progress
    
    def update_scan_progress(self, current: int, total: int, status: str = 'running'):
        """Update scan progress"""
        if not hasattr(self, '_scan_progress'):
            self._scan_progress = {}
        
        progress_percent = (current / total * 100) if total > 0 else 0
        
        self._scan_progress = {
            'status': status,
            'current': current,
            'total': total,
            'progress': round(progress_percent, 2),
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"Scan progress: {progress_percent:.1f}% ({current}/{total})")
    
    def reset_scan_progress(self):
        """Reset scan progress"""
        if hasattr(self, '_scan_progress'):
            delattr(self, '_scan_progress')
    
    def scan_from_swagger_url(self, swagger_url: str, base_url: str = None, auth_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Scan API from Swagger/OpenAPI specification URL"""
        try:
            logger.info(f"Scanning from Swagger URL: {swagger_url}")
            
            # Fetch Swagger specification
            response = self.session.get(swagger_url, timeout=30)
            response.raise_for_status()
            
            # Parse specification
            spec_data = response.json()
            endpoints = self._extract_endpoints_from_spec(spec_data, base_url)
            
            if not endpoints:
                return {'error': 'No endpoints found in Swagger specification'}
            
            logger.info(f"Found {len(endpoints)} endpoints in Swagger specification")
            
            # Scan endpoints
            return self.scan_api_endpoints_optimized(endpoints)
            
        except Exception as e:
            logger.error(f"Error scanning from Swagger URL: {e}")
            return {'error': f'Failed to scan from Swagger URL: {str(e)}'}
    
    def scan_from_json_file(self, json_file: str, base_url: str = None, auth_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Scan API from JSON specification file"""
        try:
            logger.info(f"Scanning from JSON file: {json_file}")
            
            # Read JSON file
            with open(json_file, 'r', encoding='utf-8') as f:
                spec_data = json.load(f)
            
            # Extract endpoints
            endpoints = self._extract_endpoints_from_spec(spec_data, base_url)
            
            if not endpoints:
                return {'error': 'No endpoints found in JSON specification'}
            
            logger.info(f"Found {len(endpoints)} endpoints in JSON specification")
            
            # Scan endpoints
            return self.scan_api_endpoints_optimized(endpoints)
            
        except Exception as e:
            logger.error(f"Error scanning from JSON file: {e}")
            return {'error': f'Failed to scan from JSON file: {str(e)}'}
    
    def upload_and_scan_collection(self, collection_file: str, base_url: str = None, auth_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Upload and scan Postman collection"""
        try:
            logger.info(f"Scanning Postman collection: {collection_file}")
            
            # Read collection file
            with open(collection_file, 'r', encoding='utf-8') as f:
                collection_data = json.load(f)
            
            # Extract endpoints from collection
            endpoints = self._extract_endpoints_from_postman_collection(collection_data, base_url)
            
            if not endpoints:
                return {'error': 'No endpoints found in Postman collection'}
            
            logger.info(f"Found {len(endpoints)} endpoints in Postman collection")
            
            # Scan endpoints
            return self.scan_api_endpoints_optimized(endpoints)
            
        except Exception as e:
            logger.error(f"Error scanning Postman collection: {e}")
            return {'error': f'Failed to scan Postman collection: {str(e)}'}
    
    def _extract_endpoints_from_spec(self, spec: Dict[str, Any], base_url: str = None) -> List[Dict[str, Any]]:
        """Extract endpoints from OpenAPI/Swagger specification"""
        endpoints = []
        
        try:
            # Handle OpenAPI 3.x
            if 'openapi' in spec:
                paths = spec.get('paths', {})
                servers = spec.get('servers', [])
                default_base_url = servers[0].get('url', '') if servers else ''
                
                for path, methods in paths.items():
                    for method, details in methods.items():
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                            endpoint = {
                                'path': path,
                                'method': method.upper(),
                                'base_url': base_url or default_base_url,
                                'description': details.get('summary', details.get('description', ''))
                            }
                            endpoints.append(endpoint)
            
            # Handle Swagger 2.x
            elif 'swagger' in spec:
                paths = spec.get('paths', {})
                host = spec.get('host', '')
                schemes = spec.get('schemes', ['http'])
                default_base_url = f"{schemes[0]}://{host}" if host else ''
                
                for path, methods in paths.items():
                    for method, details in methods.items():
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                            endpoint = {
                                'path': path,
                                'method': method.upper(),
                                'base_url': base_url or default_base_url,
                                'description': details.get('summary', details.get('description', ''))
                            }
                            endpoints.append(endpoint)
            
            return endpoints
            
        except Exception as e:
            logger.error(f"Error extracting endpoints from spec: {e}")
            return []
    
    def _extract_endpoints_from_postman_collection(self, collection: Dict[str, Any], base_url: str = None) -> List[Dict[str, Any]]:
        """Extract endpoints from Postman collection"""
        endpoints = []
        
        try:
            # Get collection info
            collection_info = collection.get('info', {})
            collection_name = collection_info.get('name', 'Unknown Collection')
            
            # Extract base URL from collection variables if not provided
            if not base_url:
                variables = collection.get('variable', [])
                for var in variables:
                    if var.get('key') in ['baseUrl', 'base_url', 'host']:
                        base_url = var.get('value', '')
                        break
            
            # Ensure base_url has a scheme
            if base_url and not base_url.startswith(('http://', 'https://')):
                base_url = f"https://{base_url}"
            
            # Recursively extract endpoints from items
            def extract_from_items(items, parent_folder=""):
                for item in items:
                    if 'request' in item:
                        # This is a request item
                        request = item['request']
                        url = request.get('url', {})
                        
                        # Handle different URL formats
                        if isinstance(url, str):
                            # If it's a full URL, use it directly
                            if url.startswith(('http://', 'https://')):
                                full_url = url
                                # Parse to get base_url and path
                                parsed = urlparse(url)
                                path = parsed.path
                                if parsed.query:
                                    path += '?' + parsed.query
                                base_url_for_endpoint = f"{parsed.scheme}://{parsed.netloc}"
                            else:
                                # It's a path, combine with base_url
                                path = url if url.startswith('/') else f"/{url}"
                                base_url_for_endpoint = base_url or "http://localhost"
                                full_url = urljoin(base_url_for_endpoint, path)
                        elif isinstance(url, dict):
                            # Handle URL object format
                            raw_url = url.get('raw', '')
                            if raw_url:
                                if raw_url.startswith(('http://', 'https://')):
                                    full_url = raw_url
                                    parsed = urlparse(raw_url)
                                    path = parsed.path
                                    if parsed.query:
                                        path += '?' + parsed.query
                                    base_url_for_endpoint = f"{parsed.scheme}://{parsed.netloc}"
                                else:
                                    path = raw_url if raw_url.startswith('/') else f"/{raw_url}"
                                    base_url_for_endpoint = base_url or "http://localhost"
                                    full_url = urljoin(base_url_for_endpoint, path)
                            else:
                                # Extract from path components
                                path_parts = url.get('path', [])
                                if isinstance(path_parts, list):
                                    path = '/' + '/'.join(path_parts)
                                else:
                                    path = path_parts or '/'
                                
                                # Get host and protocol
                                host = url.get('host', [])
                                if isinstance(host, list):
                                    host = '.'.join(host)
                                
                                protocol = url.get('protocol', 'https')
                                if not protocol:
                                    protocol = 'https'
                                
                                if host:
                                    base_url_for_endpoint = f"{protocol}://{host}"
                                else:
                                    base_url_for_endpoint = base_url or "http://localhost"
                                
                                full_url = urljoin(base_url_for_endpoint, path)
                        else:
                            # Fallback
                            path = '/'
                            base_url_for_endpoint = base_url or "http://localhost"
                            full_url = urljoin(base_url_for_endpoint, path)
                        
                        method = request.get('method', 'GET').upper()
                        name = item.get('name', 'Unknown Request')
                        
                        endpoint = {
                            'path': path,
                            'method': method,
                            'base_url': base_url_for_endpoint,
                            'full_url': full_url,
                            'description': name,
                            'folder': parent_folder
                        }
                        endpoints.append(endpoint)
                    
                    elif 'item' in item:
                        # This is a folder, recurse into it
                        folder_name = item.get('name', 'Unknown Folder')
                        new_parent = f"{parent_folder}/{folder_name}" if parent_folder else folder_name
                        extract_from_items(item['item'], new_parent)
            
            # Start extraction from root items
            items = collection.get('item', [])
            extract_from_items(items)
            
            return endpoints
            
        except Exception as e:
            logger.error(f"Error extracting endpoints from Postman collection: {e}")
            return []

def main():
    """Main function for testing"""
    # Example usage
    scanner = APISecurityScanner(enable_optimization=True, max_workers=8)
    
    endpoints = [
        {
            'path': '/api/users',
            'method': 'GET',
            'base_url': 'http://localhost:5001',
            'description': 'User listing endpoint'
        },
        {
            'path': '/api/users/1',
            'method': 'GET',
            'base_url': 'http://localhost:5001',
            'description': 'Single user endpoint'
        }
    ]
    
    print("🚀 API Security Scanner - Testing")
    print("=" * 40)
    
    # Run optimized scan
    results = scanner.scan_api_endpoints_optimized(endpoints)
    
    print(f"✅ Scan completed in {results['scan_info']['duration']:.3f}s")
    print(f"🚨 Vulnerabilities found: {len(results['vulnerabilities'])}")
    print(f"📊 Performance: {results['performance_metrics'].get('requests_per_second', 0):.2f} req/s")
    
    # Save results
    with open('api_security_scan_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print("📄 Results saved to: api_security_scan_results.json")

if __name__ == "__main__":
    main() 