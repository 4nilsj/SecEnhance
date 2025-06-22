#!/usr/bin/env python3
"""
API Security Scanner - Minimal Version
"""

import requests
import json
import time
import os
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Simple fallback classes
class PerformanceOptimizer:
    def __init__(self, max_workers=10, timeout=30):
        self.max_workers = max_workers
        self.timeout = timeout

def create_performance_optimizer(max_workers=10, timeout=30):
    return PerformanceOptimizer(max_workers=max_workers, timeout=timeout)

class ScanMetrics:
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0

class ResponseCache:
    def __init__(self, max_size=1000):
        self.cache = {}
        self.max_size = max_size

class RateLimiter:
    def __init__(self, max_requests_per_second=10):
        self.max_requests_per_second = max_requests_per_second
        self.last_request_time = 0

class IntelligentTestSelector:
    def __init__(self):
        self.test_history = {}

def create_optimized_scanner(max_workers=10, max_connections=100, cache_size=1000, max_requests_per_second=10):
    return create_performance_optimizer(max_workers=max_workers, timeout=30)

def benchmark_scanner_performance(scanner, test_endpoints):
    return {"status": "benchmark_completed", "endpoints_tested": len(test_endpoints)}

class APISecurityScanner:
    """Minimal API security scanner"""
    
    def __init__(self, session: requests.Session = None, auth_config: Dict[str, Any] = None, 
                 enable_optimization: bool = True, max_workers: int = 10, progress_callback=None):
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.auth_config = auth_config or {}
        self.scan_results = {}
        self.progress_callback = progress_callback
        self.max_workers = max_workers  # Store for multi-threading
        
        if enable_optimization:
            self.performance_optimizer = create_optimized_scanner(
                max_workers=max_workers,
                max_connections=100,
                cache_size=1000,
                max_requests_per_second=10
            )
            self.scan_metrics = ScanMetrics()
        else:
            self.performance_optimizer = None
            self.scan_metrics = None
    
    def scan_api_endpoints(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Enhanced endpoint scanning with comprehensive issue detection using multi-threading"""
        scan_start_time = time.time()
        scan_id = f"scan_{int(time.time())}"
        
        scan_results = {
            'scan_id': scan_id,
            'scan_start_time': datetime.now().isoformat(),
            'scan_end_time': None,
            'scan_type': 'endpoint_scan',
            'endpoints_found': len(endpoints),
            'endpoints_scanned': 0,
            'vulnerabilities_found': [],
            'warnings_found': [],
            'performance_issues_found': [],
            'configuration_issues_found': [],
            'connectivity_issues_found': [],
            'scan_duration': 0,
            'error_summary': [],
            'endpoint_results': [],
            'scan_status': 'running',
            'issue_summary': {
                'total_issues': 0,
                'vulnerabilities': 0,
                'warnings': 0,
                'performance_issues': 0,
                'configuration_issues': 0,
                'connectivity_issues': 0,
                'errors': 0
            }
        }
        
        print(f"🔍 Starting comprehensive security scan of {len(endpoints)} endpoints using multi-threading...")
        
        # Report initial progress
        if self.progress_callback:
            initial_progress = {
                'current': 0,
                'total': len(endpoints),
                'percentage': 0,
                'current_endpoint': 'Initializing multi-threaded scan...',
                'current_method': '-',
                'status': 'initializing'
            }
            self.progress_callback(initial_progress)
        
        # Thread-safe counters and lists
        successful_scans = 0
        failed_scans = 0
        completed_count = 0
        lock = threading.Lock()
        
        def scan_endpoint_with_progress(endpoint_data):
            """Scan a single endpoint and update progress"""
            nonlocal successful_scans, failed_scans, completed_count
            
            endpoint, index = endpoint_data
            
            try:
                print(f"  📡 Scanning endpoint {index+1}/{len(endpoints)}: {endpoint.get('method', 'GET')} {endpoint.get('url', 'unknown')}")
                
                # Scan single endpoint
                endpoint_result = self.scan_single_endpoint(endpoint)
                
                # Thread-safe updates
                with lock:
                    scan_results['endpoint_results'].append(endpoint_result)
                    
                    # Aggregate all types of issues
                    if 'vulnerabilities' in endpoint_result and endpoint_result['vulnerabilities']:
                        scan_results['vulnerabilities_found'].extend(endpoint_result['vulnerabilities'])
                    
                    if 'warnings' in endpoint_result and endpoint_result['warnings']:
                        scan_results['warnings_found'].extend(endpoint_result['warnings'])
                    
                    if 'performance_issues' in endpoint_result and endpoint_result['performance_issues']:
                        scan_results['performance_issues_found'].extend(endpoint_result['performance_issues'])
                    
                    if 'configuration_issues' in endpoint_result and endpoint_result['configuration_issues']:
                        scan_results['configuration_issues_found'].extend(endpoint_result['configuration_issues'])
                    
                    if 'connectivity_issues' in endpoint_result and endpoint_result['connectivity_issues']:
                        scan_results['connectivity_issues_found'].extend(endpoint_result['connectivity_issues'])
                    
                    # Add errors to summary
                    if 'errors' in endpoint_result and endpoint_result['errors']:
                        scan_results['error_summary'].extend(endpoint_result['errors'])
                    
                    successful_scans += 1
                    completed_count += 1
                
                # Report progress
                if self.progress_callback:
                    progress = {
                        'current': completed_count,
                        'total': len(endpoints),
                        'percentage': int((completed_count / len(endpoints)) * 100),
                        'current_endpoint': endpoint.get('url', 'unknown'),
                        'current_method': endpoint.get('method', 'GET'),
                        'status': 'scanning'
                    }
                    self.progress_callback(progress)
                
                return endpoint_result
                
            except Exception as e:
                error_msg = f"Error scanning endpoint {endpoint.get('url', 'unknown')}: {str(e)}"
                print(f"  ❌ {error_msg}")
                
                with lock:
                    scan_results['error_summary'].append(error_msg)
                    failed_scans += 1
                    completed_count += 1
                
                return None
        
        # Use ThreadPoolExecutor for parallel scanning
        max_workers = min(self.max_workers, len(endpoints))  # Use configured threads or number of endpoints, whichever is smaller
        print(f"  🚀 Using {max_workers} threads for parallel scanning...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all endpoints for scanning
            future_to_endpoint = {
                executor.submit(scan_endpoint_with_progress, (endpoint, i)): (endpoint, i)
                for i, endpoint in enumerate(endpoints)
            }
            
            # Process completed scans
            for future in as_completed(future_to_endpoint):
                endpoint, index = future_to_endpoint[future]
                try:
                    result = future.result()
                    if result:
                        print(f"  ✅ Completed endpoint {index+1}/{len(endpoints)}: {endpoint.get('method', 'GET')} {endpoint.get('url', 'unknown')}")
                    else:
                        print(f"  ❌ Failed endpoint {index+1}/{len(endpoints)}: {endpoint.get('method', 'GET')} {endpoint.get('url', 'unknown')}")
                except Exception as e:
                    print(f"  ❌ Exception in endpoint {index+1}/{len(endpoints)}: {str(e)}")
        
        # Update scan results with final data
        scan_results['scan_duration'] = time.time() - scan_start_time
        scan_results['scan_end_time'] = datetime.now().isoformat()
        scan_results['endpoints_scanned'] = successful_scans
        scan_results['scan_status'] = 'completed'
        
        # Calculate issue summary statistics
        scan_results['issue_summary'] = {
            'total_issues': (
                len(scan_results['vulnerabilities_found']) +
                len(scan_results['warnings_found']) +
                len(scan_results['performance_issues_found']) +
                len(scan_results['configuration_issues_found']) +
                len(scan_results['connectivity_issues_found']) +
                len(scan_results['error_summary'])
            ),
            'vulnerabilities': len(scan_results['vulnerabilities_found']),
            'warnings': len(scan_results['warnings_found']),
            'performance_issues': len(scan_results['performance_issues_found']),
            'configuration_issues': len(scan_results['configuration_issues_found']),
            'connectivity_issues': len(scan_results['connectivity_issues_found']),
            'errors': len(scan_results['error_summary'])
        }
        
        # Create detailed error summary statistics
        error_summary = {
            'total_errors': len(scan_results['error_summary']),
            'fatal_errors': len([e for e in scan_results['error_summary'] if 'fatal' in e.lower()]),
            'error_categories': {
                'network': len([e for e in scan_results['error_summary'] if any(x in e.lower() for x in ['timeout', 'connection', 'network'])]),
                'authentication': len([e for e in scan_results['error_summary'] if any(x in e.lower() for x in ['auth', 'unauthorized', 'forbidden'])]),
                'endpoint': len([e for e in scan_results['error_summary'] if any(x in e.lower() for x in ['not found', '404', 'endpoint'])]),
                'server': len([e for e in scan_results['error_summary'] if any(x in e.lower() for x in ['server', '500', 'internal'])]),
                'other': len([e for e in scan_results['error_summary'] if not any(x in e.lower() for x in ['timeout', 'connection', 'network', 'auth', 'unauthorized', 'forbidden', 'not found', '404', 'endpoint', 'server', '500', 'internal'])])
            },
            'severity_breakdown': {
                'critical': len([v for v in scan_results['vulnerabilities_found'] if v.get('severity', '').lower() == 'critical']),
                'high': len([v for v in scan_results['vulnerabilities_found'] if v.get('severity', '').lower() == 'high']),
                'medium': len([v for v in scan_results['vulnerabilities_found'] if v.get('severity', '').lower() == 'medium']),
                'low': len([v for v in scan_results['vulnerabilities_found'] if v.get('severity', '').lower() == 'low'])
            }
        }
        scan_results['error_summary_stats'] = error_summary
        
        # Print comprehensive scan summary
        print(f"✅ Scan completed in {scan_results['scan_duration']:.2f}s")
        print(f"📊 Scan Summary:")
        print(f"   - Endpoints: {successful_scans} successful, {failed_scans} failed")
        print(f"   - Vulnerabilities: {len(scan_results['vulnerabilities_found'])}")
        print(f"   - Warnings: {len(scan_results['warnings_found'])}")
        print(f"   - Performance Issues: {len(scan_results['performance_issues_found'])}")
        print(f"   - Configuration Issues: {len(scan_results['configuration_issues_found'])}")
        print(f"   - Connectivity Issues: {len(scan_results['connectivity_issues_found'])}")
        print(f"   - Errors: {len(scan_results['error_summary'])}")
        print(f"   - Total Issues: {scan_results['issue_summary']['total_issues']}")
        
        # Report final progress
        if self.progress_callback:
            final_progress = {
                'current': len(endpoints),
                'total': len(endpoints),
                'percentage': 100,
                'current_endpoint': '',
                'current_method': '',
                'status': 'completed'
            }
            self.progress_callback(final_progress)
        
        return scan_results
    
    def scan_single_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a single API endpoint for security vulnerabilities and other issues"""
        endpoint_result = {
            'endpoint': endpoint,
            'vulnerabilities': [],
            'errors': [],
            'warnings': [],
            'performance_issues': [],
            'configuration_issues': [],
            'connectivity_issues': [],
            'response_analysis': {},
            'scan_status': 'completed'
        }
        
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET')
        
        try:
            print(f"    🔍 Testing {method} {url}")
            
            # Test 1: Basic connectivity and response analysis
            connectivity_result = self._test_endpoint_connectivity(url, method)
            endpoint_result['connectivity_issues'].extend(connectivity_result.get('issues', []))
            endpoint_result['response_analysis'] = connectivity_result.get('response_analysis', {})
            
            # Test 2: Performance analysis
            performance_result = self._test_endpoint_performance(url, method)
            endpoint_result['performance_issues'].extend(performance_result.get('issues', []))
            
            # Test 3: Configuration analysis
            config_result = self._test_endpoint_configuration(url, method)
            endpoint_result['configuration_issues'].extend(config_result.get('issues', []))
            
            # Test 4: Security vulnerability tests
            security_tests = self.get_security_tests()
            for test_category, tests in security_tests.items():
                for test in tests:
                    test_result = self.run_security_test(url, method, test, test_category)
                    if test_result.get('vulnerability_found'):
                        endpoint_result['vulnerabilities'].append(test_result['vulnerability'])
                    if test_result.get('error'):
                        endpoint_result['errors'].append(f"Test {test.get('name', 'Unknown')} failed: {test_result['error']}")
            
            # Test 5: Additional security checks
            additional_checks = self._run_additional_security_checks(url, method)
            endpoint_result['vulnerabilities'].extend(additional_checks.get('vulnerabilities', []))
            endpoint_result['warnings'].extend(additional_checks.get('warnings', []))
            
        except Exception as e:
            error_msg = f"Error scanning endpoint {url}: {str(e)}"
            endpoint_result['errors'].append(error_msg)
            endpoint_result['scan_status'] = 'failed'
            print(f"    ❌ {error_msg}")
        
        return endpoint_result
    
    def _test_endpoint_connectivity(self, url: str, method: str) -> Dict[str, Any]:
        """Test endpoint connectivity and basic response analysis"""
        issues = []
        response_analysis = {}
        
        try:
            # Test basic connectivity
            start_time = time.time()
            response = self.session.request(method, url, timeout=10)
            response_time = time.time() - start_time
            
            response_analysis = {
                'status_code': response.status_code,
                'response_time': response_time,
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'content_type': response.headers.get('Content-Type', ''),
                'server': response.headers.get('Server', ''),
                'response_size_kb': len(response.content) / 1024
            }
            
            # Check for connectivity issues
            if response.status_code >= 500:
                issues.append({
                    'type': 'Server Error',
                    'severity': 'high',
                    'description': f'Server returned {response.status_code} status code',
                    'evidence': f'HTTP {response.status_code}: {response.reason}',
                    'category': 'connectivity'
                })
            elif response.status_code == 404:
                issues.append({
                    'type': 'Endpoint Not Found',
                    'severity': 'medium',
                    'description': 'Endpoint does not exist or has changed',
                    'evidence': f'HTTP 404: {response.reason}',
                    'category': 'connectivity'
                })
            elif response.status_code == 405:
                issues.append({
                    'type': 'Method Not Allowed',
                    'severity': 'medium',
                    'description': f'HTTP method {method} not supported',
                    'evidence': f'HTTP 405: {response.reason}',
                    'category': 'connectivity'
                })
            
            # Check for slow response times
            if response_time > 5.0:
                issues.append({
                    'type': 'Slow Response Time',
                    'severity': 'medium',
                    'description': f'Response time is {response_time:.2f}s (slow)',
                    'evidence': f'Response time: {response_time:.2f} seconds',
                    'category': 'performance'
                })
            
            # Check for large response sizes
            if len(response.content) > 1024 * 1024:  # > 1MB
                issues.append({
                    'type': 'Large Response Size',
                    'severity': 'low',
                    'description': f'Response size is {len(response.content)/1024/1024:.1f}MB',
                    'evidence': f'Response size: {len(response.content)} bytes',
                    'category': 'performance'
                })
                
        except requests.exceptions.ConnectionError:
            issues.append({
                'type': 'Connection Refused',
                'severity': 'high',
                'description': 'Cannot connect to endpoint',
                'evidence': 'ConnectionError: Connection refused',
                'category': 'connectivity'
            })
        except requests.exceptions.Timeout:
            issues.append({
                'type': 'Request Timeout',
                'severity': 'high',
                'description': 'Request timed out',
                'evidence': 'Timeout: Request exceeded 10 seconds',
                'category': 'connectivity'
            })
        except requests.exceptions.SSLError:
            issues.append({
                'type': 'SSL/TLS Error',
                'severity': 'high',
                'description': 'SSL/TLS handshake failed',
                'evidence': 'SSLError: SSL certificate or protocol error',
                'category': 'connectivity'
            })
        except Exception as e:
            issues.append({
                'type': 'Unexpected Error',
                'severity': 'medium',
                'description': f'Unexpected error during connectivity test: {str(e)}',
                'evidence': f'Exception: {type(e).__name__}: {str(e)}',
                'category': 'connectivity'
            })
        
        return {
            'issues': issues,
            'response_analysis': response_analysis
        }
    
    def _test_endpoint_performance(self, url: str, method: str) -> Dict[str, Any]:
        """Test endpoint performance characteristics"""
        issues = []
        
        try:
            # Test response time consistency
            response_times = []
            for _ in range(3):
                start_time = time.time()
                response = self.session.request(method, url, timeout=10)
                response_times.append(time.time() - start_time)
                time.sleep(0.1)  # Small delay between requests
            
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            min_time = min(response_times)
            variance = max_time - min_time
            
            # Check for inconsistent response times
            if variance > 2.0:
                issues.append({
                    'type': 'Inconsistent Response Times',
                    'severity': 'medium',
                    'description': f'Response times vary significantly (min: {min_time:.2f}s, max: {max_time:.2f}s)',
                    'evidence': f'Response times: {[f"{t:.2f}s" for t in response_times]}',
                    'category': 'performance'
                })
            
            # Check for very slow average response time
            if avg_time > 3.0:
                issues.append({
                    'type': 'Slow Average Response Time',
                    'severity': 'medium',
                    'description': f'Average response time is {avg_time:.2f}s',
                    'evidence': f'Average response time: {avg_time:.2f} seconds',
                    'category': 'performance'
                })
                
        except Exception as e:
            issues.append({
                'type': 'Performance Test Error',
                'severity': 'low',
                'description': f'Error during performance testing: {str(e)}',
                'evidence': f'Exception: {type(e).__name__}: {str(e)}',
                'category': 'performance'
            })
        
        return {'issues': issues}
    
    def _test_endpoint_configuration(self, url: str, method: str) -> Dict[str, Any]:
        """Test endpoint configuration issues"""
        issues = []
        
        try:
            response = self.session.request(method, url, timeout=10)
            
            # Check for missing content type
            if 'Content-Type' not in response.headers:
                issues.append({
                    'type': 'Missing Content-Type Header',
                    'severity': 'low',
                    'description': 'Response missing Content-Type header',
                    'evidence': 'No Content-Type header in response',
                    'category': 'configuration'
                })
            
            # Check for missing cache control
            if 'Cache-Control' not in response.headers:
                issues.append({
                    'type': 'Missing Cache-Control Header',
                    'severity': 'low',
                    'description': 'Response missing Cache-Control header',
                    'evidence': 'No Cache-Control header in response',
                    'category': 'configuration'
                })
            
            # Check for server information disclosure
            server_header = response.headers.get('Server', '')
            if server_header and len(server_header) > 20:
                issues.append({
                    'type': 'Detailed Server Information',
                    'severity': 'low',
                    'description': 'Server header contains detailed information',
                    'evidence': f'Server: {server_header}',
                    'category': 'configuration'
                })
            
            # Check for missing security headers
            security_headers = ['X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']
            missing_headers = [h for h in security_headers if h not in response.headers]
            if missing_headers:
                issues.append({
                    'type': 'Missing Security Headers',
                    'severity': 'medium',
                    'description': f'Missing security headers: {", ".join(missing_headers)}',
                    'evidence': f'Missing headers: {missing_headers}',
                    'category': 'configuration'
                })
                
        except Exception as e:
            issues.append({
                'type': 'Configuration Test Error',
                'severity': 'low',
                'description': f'Error during configuration testing: {str(e)}',
                'evidence': f'Exception: {type(e).__name__}: {str(e)}',
                'category': 'configuration'
            })
        
        return {'issues': issues}
    
    def _run_additional_security_checks(self, url: str, method: str) -> Dict[str, Any]:
        """Run additional security checks beyond standard tests"""
        vulnerabilities = []
        warnings = []
        try:
            response = self.session.request(method, url, timeout=10)
            response_text = response.text.lower()
            sensitive_patterns = [
                'password', 'secret', 'key', 'token', 'api_key', 'private',
                'internal', 'admin', 'root', 'database', 'config'
            ]
            found_sensitive = [pattern for pattern in sensitive_patterns if pattern in response_text]
            if found_sensitive:
                warnings.append({
                    'title': 'Potential Information Disclosure',
                    'type': 'Potential Information Disclosure',
                    'severity': 'medium',
                    'description': f'Response may contain sensitive information: {", ".join(found_sensitive)}',
                    'evidence': f'Found sensitive patterns: {found_sensitive}',
                    'category': 'information_disclosure'
                })
            error_indicators = [
                'stack trace', 'exception', 'error in', 'debug', 'internal server error',
                'database error', 'sql error', 'file not found', 'permission denied'
            ]
            found_errors = [indicator for indicator in error_indicators if indicator in response_text]
            if found_errors:
                vulnerabilities.append({
                    'title': 'Error Information Disclosure',
                    'type': 'Error Information Disclosure',
                    'severity': 'medium',
                    'description': f'Error information exposed in response',
                    'evidence': f'Found error indicators: {found_errors}',
                    'category': 'information_disclosure',
                    'url': url,
                    'method': method
                })
            version_patterns = ['version', 'v1', 'v2', 'api/v1', 'api/v2']
            found_versions = [pattern for pattern in version_patterns if pattern in response_text]
            if found_versions:
                warnings.append({
                    'title': 'Version Information Disclosure',
                    'type': 'Version Information Disclosure',
                    'severity': 'low',
                    'description': f'Version information found in response',
                    'evidence': f'Found version patterns: {found_versions}',
                    'category': 'information_disclosure'
                })
        except Exception as e:
            warnings.append({
                'title': 'Additional Security Check Error',
                'type': 'Additional Security Check Error',
                'severity': 'low',
                'description': f'Error during additional security checks: {str(e)}',
                'evidence': f'Exception: {type(e).__name__}: {str(e)}',
                'category': 'error'
            })
        return {
            'vulnerabilities': vulnerabilities,
            'warnings': warnings
        }
    
    def get_security_tests(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get comprehensive security test configurations including misconfiguration tests"""
        return {
            'authentication': [
                {
                    'name': 'Missing Authentication',
                    'description': 'Test for endpoints that should require authentication',
                    'method': 'GET',
                    'expected_status': [401, 403],
                    'vulnerability_type': 'Missing Authentication',
                    'severity': 'High'
                }
            ],
            'authorization': [
                {
                    'name': 'Authorization Bypass',
                    'description': 'Test for unauthorized access to protected resources',
                    'method': 'GET',
                    'expected_status': [401, 403],
                    'vulnerability_type': 'Authorization Bypass',
                    'severity': 'High'
                }
            ],
            'injection': [
                {
                    'name': 'SQL Injection',
                    'description': 'Test for SQL injection vulnerabilities',
                    'payloads': ["' OR '1'='1", "'; DROP TABLE users; --", "1' UNION SELECT * FROM users --"],
                    'vulnerability_type': 'SQL Injection',
                    'severity': 'Critical'
                },
                {
                    'name': 'XSS Injection',
                    'description': 'Test for Cross-Site Scripting vulnerabilities',
                    'payloads': ["<script>alert('XSS')</script>", "javascript:alert('XSS')", "onerror=alert('XSS')"],
                    'vulnerability_type': 'Cross-Site Scripting',
                    'severity': 'High'
                }
            ],
            'information_disclosure': [
                {
                    'name': 'Error Information Disclosure',
                    'description': 'Test for sensitive information in error messages',
                    'method': 'GET',
                    'vulnerability_type': 'Information Disclosure',
                    'severity': 'Medium'
                },
                {
                    'name': 'Directory Traversal',
                    'description': 'Test for directory traversal vulnerabilities',
                    'payloads': ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
                    'vulnerability_type': 'Directory Traversal',
                    'severity': 'High'
                }
            ],
            'rate_limiting': [
                {
                    'name': 'Missing Rate Limiting',
                    'description': 'Test for missing rate limiting on endpoints',
                    'method': 'GET',
                    'requests_count': 10,
                    'time_window': 1,  # seconds
                    'vulnerability_type': 'Missing Rate Limiting',
                    'severity': 'Medium'
                }
            ],
            'http_methods': [
                {
                    'name': 'Dangerous HTTP Methods Allowed',
                    'description': 'Test for dangerous HTTP methods (PUT, DELETE, TRACE, OPTIONS)',
                    'methods': ['PUT', 'DELETE', 'TRACE', 'OPTIONS', 'PATCH'],
                    'vulnerability_type': 'Dangerous HTTP Methods',
                    'severity': 'Medium'
                },
                {
                    'name': 'HTTP Method Override',
                    'description': 'Test for HTTP method override vulnerabilities',
                    'headers': ['X-HTTP-Method', 'X-HTTP-Method-Override', 'X-Method-Override'],
                    'methods': ['PUT', 'DELETE', 'PATCH'],
                    'vulnerability_type': 'HTTP Method Override',
                    'severity': 'Medium'
                }
            ],
            'security_headers': [
                {
                    'name': 'Missing Security Headers',
                    'description': 'Test for missing security response headers',
                    'required_headers': [
                        'X-Content-Type-Options',
                        'X-Frame-Options', 
                        'X-XSS-Protection',
                        'Strict-Transport-Security',
                        'Content-Security-Policy',
                        'Referrer-Policy'
                    ],
                    'vulnerability_type': 'Missing Security Headers',
                    'severity': 'Medium'
                },
                {
                    'name': 'Weak Security Headers',
                    'description': 'Test for weak security header configurations',
                    'weak_configs': {
                        'X-Frame-Options': ['ALLOWALL', ''],
                        'X-XSS-Protection': ['0', ''],
                        'Strict-Transport-Security': ['max-age=0', ''],
                        'Content-Security-Policy': ['unsafe-inline', 'unsafe-eval']
                    },
                    'vulnerability_type': 'Weak Security Headers',
                    'severity': 'Low'
                }
            ],
            'cors_misconfiguration': [
                {
                    'name': 'CORS Misconfiguration',
                    'description': 'Test for CORS misconfiguration vulnerabilities',
                    'origin_headers': [
                        'https://evil.com',
                        'null',
                        'https://attacker.com',
                        'https://*.evil.com'
                    ],
                    'vulnerability_type': 'CORS Misconfiguration',
                    'severity': 'Medium'
                },
                {
                    'name': 'CORS Wildcard',
                    'description': 'Test for wildcard CORS configuration',
                    'vulnerability_type': 'CORS Wildcard',
                    'severity': 'Medium'
                }
            ],
            'ssl_tls': [
                {
                    'name': 'SSL/TLS Issues',
                    'description': 'Test for SSL/TLS configuration issues',
                    'vulnerability_type': 'SSL/TLS Misconfiguration',
                    'severity': 'High'
                },
                {
                    'name': 'Weak Cipher Suites',
                    'description': 'Test for weak cipher suite usage',
                    'vulnerability_type': 'Weak Cipher Suites',
                    'severity': 'Medium'
                }
            ],
            'cache_control': [
                {
                    'name': 'Missing Cache Control',
                    'description': 'Test for missing cache control headers on sensitive endpoints',
                    'vulnerability_type': 'Missing Cache Control',
                    'severity': 'Low'
                },
                {
                    'name': 'Weak Cache Control',
                    'description': 'Test for weak cache control configurations',
                    'vulnerability_type': 'Weak Cache Control',
                    'severity': 'Low'
                }
            ],
            'server_information': [
                {
                    'name': 'Server Information Disclosure',
                    'description': 'Test for server information disclosure in headers',
                    'sensitive_headers': [
                        'Server',
                        'X-Powered-By',
                        'X-AspNet-Version',
                        'X-AspNetMvc-Version',
                        'X-Runtime',
                        'X-Version'
                    ],
                    'vulnerability_type': 'Server Information Disclosure',
                    'severity': 'Low'
                }
            ],
            'debug_endpoints': [
                {
                    'name': 'Debug Endpoints Exposed',
                    'description': 'Test for exposed debug endpoints',
                    'debug_paths': [
                        '/debug', '/debugger', '/console', '/admin/debug',
                        '/api/debug', '/dev', '/development', '/test',
                        '/swagger-ui', '/api-docs', '/docs', '/documentation'
                    ],
                    'vulnerability_type': 'Debug Endpoints Exposed',
                    'severity': 'Medium'
                }
            ],
            'version_disclosure': [
                {
                    'name': 'API Version Disclosure',
                    'description': 'Test for API version information disclosure',
                    'version_indicators': [
                        'version', 'v1', 'v2', 'api/v1', 'api/v2',
                        'swagger', 'openapi', 'api-docs'
                    ],
                    'vulnerability_type': 'API Version Disclosure',
                    'severity': 'Low'
                }
            ]
        }
    
    def run_security_test(self, url: str, method: str, test: Dict[str, Any], test_category: str) -> Dict[str, Any]:
        """Run a single security test against an endpoint"""
        test_result = {
            'test_name': test.get('name', 'Unknown'),
            'test_category': test_category,
            'vulnerability_found': False,
            'vulnerability': None
        }
        try:
            # Capture request/response data for vulnerability evidence
            request_data = None
            response_data = None
            
            if test_category == 'injection':
                payloads = test.get('payloads', [])
                for payload in payloads:
                    # Capture request/response for injection test
                    if method == 'GET':
                        test_url = f"{url}?test={payload}"
                        try:
                            response = self.session.get(test_url, timeout=10)
                            request_data = {
                                'method': 'GET',
                                'url': test_url,
                                'headers': dict(self.session.headers),
                                'params': {'test': payload}
                            }
                            response_data = {
                                'status_code': response.status_code,
                                'headers': dict(response.headers),
                                'content': response.text[:5000],  # Limit content size
                                'content_length': len(response.content)
                            }
                        except Exception as e:
                            request_data = {'method': 'GET', 'url': test_url, 'error': str(e)}
                            response_data = {'error': str(e)}
                    else:
                        try:
                            response = self.session.post(url, json={'test': payload}, timeout=10)
                            request_data = {
                                'method': 'POST',
                                'url': url,
                                'headers': dict(self.session.headers),
                                'json': {'test': payload}
                            }
                            response_data = {
                                'status_code': response.status_code,
                                'headers': dict(response.headers),
                                'content': response.text[:5000],  # Limit content size
                                'content_length': len(response.content)
                            }
                        except Exception as e:
                            request_data = {'method': 'POST', 'url': url, 'error': str(e)}
                            response_data = {'error': str(e)}
                    
                    if self.test_injection(url, method, payload, test):
                        test_result['vulnerability_found'] = True
                        test_result['vulnerability'] = {
                            'title': test.get('name', test.get('vulnerability_type', 'Unknown Vulnerability')),
                            'type': test.get('vulnerability_type', 'Injection'),
                            'severity': test.get('severity', 'Medium'),
                            'description': test.get('description', ''),
                            'evidence': f"Injection payload successful: {payload}",
                            'test_name': test.get('name', ''),
                            'category': test_category,
                            'url': url,
                            'method': method,
                            'request_data': request_data,
                            'response_data': response_data
                        }
                        break
            elif test_category == 'authentication':
                # Capture request/response for authentication test
                try:
                    # Clear any existing authentication
                    original_auth = self.session.auth
                    original_headers = dict(self.session.headers)
                    
                    self.session.auth = None
                    auth_headers = ['Authorization', 'X-API-Key', 'X-Auth-Token']
                    for header in auth_headers:
                        if header in self.session.headers:
                            del self.session.headers[header]
                    
                    # Make request without authentication
                    if method == 'GET':
                        response = self.session.get(url, timeout=10)
                    else:
                        response = self.session.post(url, timeout=10)
                    
                    request_data = {
                        'method': method,
                        'url': url,
                        'headers': dict(self.session.headers),
                        'auth_removed': True
                    }
                    response_data = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content': response.text[:5000],  # Limit content size
                        'content_length': len(response.content)
                    }
                    
                    # Restore original authentication
                    self.session.auth = original_auth
                    self.session.headers.update(original_headers)
                    
                except Exception as e:
                    request_data = {'method': method, 'url': url, 'error': str(e)}
                    response_data = {'error': str(e)}
                
                if self.test_authentication(url, method, test):
                    test_result['vulnerability_found'] = True
                    test_result['vulnerability'] = {
                        'title': test.get('name', test.get('vulnerability_type', 'Unknown Vulnerability')),
                        'type': test.get('vulnerability_type', 'Missing Authentication'),
                        'severity': test.get('severity', 'High'),
                        'description': test.get('description', ''),
                        'evidence': f"Endpoint accessible without authentication: {url}",
                        'test_name': test.get('name', ''),
                        'category': test_category,
                        'url': url,
                        'method': method,
                        'request_data': request_data,
                        'response_data': response_data
                    }
            elif test_category == 'information_disclosure':
                # Capture request/response for information disclosure test
                try:
                    if method == 'GET':
                        response = self.session.get(url, timeout=10)
                    else:
                        response = self.session.post(url, timeout=10)
                    
                    request_data = {
                        'method': method,
                        'url': url,
                        'headers': dict(self.session.headers)
                    }
                    response_data = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content': response.text[:5000],  # Limit content size
                        'content_length': len(response.content)
                    }
                except Exception as e:
                    request_data = {'method': method, 'url': url, 'error': str(e)}
                    response_data = {'error': str(e)}
                
                if self.test_information_disclosure(url, method, test):
                    test_result['vulnerability_found'] = True
                    test_result['vulnerability'] = {
                        'title': test.get('name', test.get('vulnerability_type', 'Unknown Vulnerability')),
                        'type': test.get('vulnerability_type', 'Information Disclosure'),
                        'severity': test.get('severity', 'Medium'),
                        'description': test.get('description', ''),
                        'evidence': f"Sensitive information exposed: {url}",
                        'test_name': test.get('name', ''),
                        'category': test_category,
                        'url': url,
                        'method': method,
                        'request_data': request_data,
                        'response_data': response_data
                    }
            elif test_category == 'rate_limiting':
                # Capture request/response for rate limiting test
                try:
                    # Make multiple rapid requests to test rate limiting
                    responses = []
                    for i in range(5):
                        if method == 'GET':
                            response = self.session.get(url, timeout=10)
                        else:
                            response = self.session.post(url, timeout=10)
                        responses.append({
                            'status_code': response.status_code,
                            'headers': dict(response.headers),
                            'content_length': len(response.content)
                        })
                    
                    request_data = {
                        'method': method,
                        'url': url,
                        'headers': dict(self.session.headers),
                        'rapid_requests': 5
                    }
                    response_data = {
                        'responses': responses,
                        'rate_limit_detected': any(r['status_code'] == 429 for r in responses)
                    }
                except Exception as e:
                    request_data = {'method': method, 'url': url, 'error': str(e)}
                    response_data = {'error': str(e)}
                
                if self.test_rate_limiting(url, method, test):
                    test_result['vulnerability_found'] = True
                    test_result['vulnerability'] = {
                        'title': test.get('name', test.get('vulnerability_type', 'Unknown Vulnerability')),
                        'type': test.get('vulnerability_type', 'Missing Rate Limiting'),
                        'severity': test.get('severity', 'Medium'),
                        'description': test.get('description', ''),
                        'evidence': f"No rate limiting detected: {url}",
                        'test_name': test.get('name', ''),
                        'category': test_category,
                        'url': url,
                        'method': method,
                        'request_data': request_data,
                        'response_data': response_data
                    }
            elif test_category == 'http_methods':
                # Capture request/response for HTTP methods test
                dangerous_methods = test.get('methods', ['PUT', 'DELETE', 'TRACE', 'OPTIONS', 'PATCH'])
                method_results = []
                
                for test_method in dangerous_methods:
                    try:
                        if test_method == 'GET':
                            response = self.session.get(url, timeout=10)
                        elif test_method == 'POST':
                            response = self.session.post(url, timeout=10)
                        elif test_method == 'PUT':
                            response = self.session.put(url, timeout=10)
                        elif test_method == 'DELETE':
                            response = self.session.delete(url, timeout=10)
                        elif test_method == 'PATCH':
                            response = self.session.patch(url, timeout=10)
                        elif test_method == 'OPTIONS':
                            response = self.session.options(url, timeout=10)
                        elif test_method == 'HEAD':
                            response = self.session.head(url, timeout=10)
                        else:
                            continue
                        
                        method_results.append({
                            'method': test_method,
                            'status_code': response.status_code,
                            'allowed': response.status_code not in [405, 501, 502, 503]
                        })
                    except Exception as e:
                        method_results.append({
                            'method': test_method,
                            'error': str(e),
                            'allowed': False
                        })
                
                request_data = {
                    'url': url,
                    'headers': dict(self.session.headers),
                    'tested_methods': dangerous_methods
                }
                response_data = {
                    'method_results': method_results,
                    'dangerous_methods_allowed': any(r.get('allowed', False) for r in method_results)
                }
                
                if self.test_http_methods(url, method, test):
                    test_result['vulnerability_found'] = True
                    test_result['vulnerability'] = {
                        'title': test.get('name', test.get('vulnerability_type', 'Unknown Vulnerability')),
                        'type': test.get('vulnerability_type', 'Dangerous HTTP Methods'),
                        'severity': test.get('severity', 'Medium'),
                        'description': test.get('description', ''),
                        'evidence': f"Dangerous HTTP methods allowed: {url}",
                        'test_name': test.get('name', ''),
                        'category': test_category,
                        'url': url,
                        'method': method,
                        'request_data': request_data,
                        'response_data': response_data
                    }
            elif test_category == 'security_headers':
                # Capture request/response for security headers test
                try:
                    if method == 'GET':
                        response = self.session.get(url, timeout=10)
                    else:
                        response = self.session.post(url, timeout=10)
                    
                    request_data = {
                        'method': method,
                        'url': url,
                        'headers': dict(self.session.headers)
                    }
                    response_data = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content': response.text[:5000],  # Limit content size
                        'content_length': len(response.content)
                    }
                except Exception as e:
                    request_data = {'method': method, 'url': url, 'error': str(e)}
                    response_data = {'error': str(e)}
                
                if self.test_security_headers(url, method, test):
                    test_result['vulnerability_found'] = True
                    test_result['vulnerability'] = {
                        'title': test.get('name', test.get('vulnerability_type', 'Unknown Vulnerability')),
                        'type': test.get('vulnerability_type', 'Missing Security Headers'),
                        'severity': test.get('severity', 'Medium'),
                        'description': test.get('description', ''),
                        'evidence': f"Security headers misconfigured: {url}",
                        'test_name': test.get('name', ''),
                        'category': test_category,
                        'url': url,
                        'method': method,
                        'request_data': request_data,
                        'response_data': response_data
                    }
            elif test_category == 'cors_misconfiguration':
                # Capture request/response for CORS test
                try:
                    if method == 'GET':
                        response = self.session.get(url, timeout=10)
                    else:
                        response = self.session.post(url, timeout=10)
                    
                    request_data = {
                        'method': method,
                        'url': url,
                        'headers': dict(self.session.headers)
                    }
                    response_data = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content': response.text[:5000],  # Limit content size
                        'content_length': len(response.content)
                    }
                except Exception as e:
                    request_data = {'method': method, 'url': url, 'error': str(e)}
                    response_data = {'error': str(e)}
                
                if self.test_cors_misconfiguration(url, method, test):
                    test_result['vulnerability_found'] = True
                    test_result['vulnerability'] = {
                        'title': test.get('name', test.get('vulnerability_type', 'Unknown Vulnerability')),
                        'type': test.get('vulnerability_type', 'CORS Misconfiguration'),
                        'severity': test.get('severity', 'Medium'),
                        'description': test.get('description', ''),
                        'evidence': f"CORS misconfiguration detected: {url}",
                        'test_name': test.get('name', ''),
                        'category': test_category,
                        'url': url,
                        'method': method,
                        'request_data': request_data,
                        'response_data': response_data
                    }
            elif test_category == 'ssl_tls':
                # Capture request/response for SSL/TLS test
                try:
                    if method == 'GET':
                        response = self.session.get(url, timeout=10)
                    else:
                        response = self.session.post(url, timeout=10)
                    
                    request_data = {
                        'method': method,
                        'url': url,
                        'headers': dict(self.session.headers)
                    }
                    response_data = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content': response.text[:5000],  # Limit content size
                        'content_length': len(response.content)
                    }
                except Exception as e:
                    request_data = {'method': method, 'url': url, 'error': str(e)}
                    response_data = {'error': str(e)}
                
                if self.test_ssl_tls(url, method, test):
                    test_result['vulnerability_found'] = True
                    test_result['vulnerability'] = {
                        'title': test.get('name', test.get('vulnerability_type', 'Unknown Vulnerability')),
                        'type': test.get('vulnerability_type', 'SSL/TLS Misconfiguration'),
                        'severity': test.get('severity', 'High'),
                        'description': test.get('description', ''),
                        'evidence': f"SSL/TLS issues detected: {url}",
                        'test_name': test.get('name', ''),
                        'category': test_category,
                        'url': url,
                        'method': method,
                        'request_data': request_data,
                        'response_data': response_data
                    }
            elif test_category == 'cache_control':
                # Capture request/response for cache control test
                try:
                    if method == 'GET':
                        response = self.session.get(url, timeout=10)
                    else:
                        response = self.session.post(url, timeout=10)
                    
                    request_data = {
                        'method': method,
                        'url': url,
                        'headers': dict(self.session.headers)
                    }
                    response_data = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content': response.text[:5000],  # Limit content size
                        'content_length': len(response.content)
                    }
                except Exception as e:
                    request_data = {'method': method, 'url': url, 'error': str(e)}
                    response_data = {'error': str(e)}
                
                if self.test_cache_control(url, method, test):
                    test_result['vulnerability_found'] = True
                    test_result['vulnerability'] = {
                        'title': test.get('name', test.get('vulnerability_type', 'Unknown Vulnerability')),
                        'type': test.get('vulnerability_type', 'Missing Cache Control'),
                        'severity': test.get('severity', 'Low'),
                        'description': test.get('description', ''),
                        'evidence': f"Cache control issues: {url}",
                        'test_name': test.get('name', ''),
                        'category': test_category,
                        'url': url,
                        'method': method,
                        'request_data': request_data,
                        'response_data': response_data
                    }
            elif test_category == 'server_information':
                # Capture request/response for server information test
                try:
                    if method == 'GET':
                        response = self.session.get(url, timeout=10)
                    else:
                        response = self.session.post(url, timeout=10)
                    
                    request_data = {
                        'method': method,
                        'url': url,
                        'headers': dict(self.session.headers)
                    }
                    response_data = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content': response.text[:5000],  # Limit content size
                        'content_length': len(response.content)
                    }
                except Exception as e:
                    request_data = {'method': method, 'url': url, 'error': str(e)}
                    response_data = {'error': str(e)}
                
                if self.test_server_information(url, method, test):
                    test_result['vulnerability_found'] = True
                    test_result['vulnerability'] = {
                        'title': test.get('name', test.get('vulnerability_type', 'Unknown Vulnerability')),
                        'type': test.get('vulnerability_type', 'Server Information Disclosure'),
                        'severity': test.get('severity', 'Low'),
                        'description': test.get('description', ''),
                        'evidence': f"Server information exposed: {url}",
                        'test_name': test.get('name', ''),
                        'category': test_category,
                        'url': url,
                        'method': method,
                        'request_data': request_data,
                        'response_data': response_data
                    }
            elif test_category == 'debug_endpoints':
                # For debug endpoints, just check the URL pattern
                request_data = {
                    'method': method,
                    'url': url,
                    'headers': dict(self.session.headers)
                }
                response_data = {
                    'debug_paths_checked': test.get('debug_paths', [])
                }
                
                if self.test_debug_endpoints(url, method, test):
                    test_result['vulnerability_found'] = True
                    test_result['vulnerability'] = {
                        'title': test.get('name', test.get('vulnerability_type', 'Unknown Vulnerability')),
                        'type': test.get('vulnerability_type', 'Debug Endpoints Exposed'),
                        'severity': test.get('severity', 'Medium'),
                        'description': test.get('description', ''),
                        'evidence': f"Debug endpoints exposed: {url}",
                        'test_name': test.get('name', ''),
                        'category': test_category,
                        'url': url,
                        'method': method,
                        'request_data': request_data,
                        'response_data': response_data
                    }
            elif test_category == 'version_disclosure':
                # Capture request/response for version disclosure test
                try:
                    response = self.session.get(url, timeout=10)
                    request_data = {
                        'method': 'GET',
                        'url': url,
                        'headers': dict(self.session.headers)
                    }
                    response_data = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content': response.text[:5000],  # Limit content size
                        'content_length': len(response.content)
                    }
                except Exception as e:
                    request_data = {'method': 'GET', 'url': url, 'error': str(e)}
                    response_data = {'error': str(e)}
                
                if self.test_version_disclosure(url, method, test):
                    test_result['vulnerability_found'] = True
                    test_result['vulnerability'] = {
                        'title': test.get('name', test.get('vulnerability_type', 'Unknown Vulnerability')),
                        'type': test.get('vulnerability_type', 'API Version Disclosure'),
                        'severity': test.get('severity', 'Low'),
                        'description': test.get('description', ''),
                        'evidence': f"Version information exposed: {url}",
                        'test_name': test.get('name', ''),
                        'category': test_category,
                        'url': url,
                        'method': method,
                        'request_data': request_data,
                        'response_data': response_data
                    }
        except Exception as e:
            test_result['error'] = str(e)
        return test_result
    
    def test_injection(self, url: str, method: str, payload: str, test: Dict[str, Any]) -> bool:
        """Test for injection vulnerabilities"""
        try:
            # Add payload to URL parameters or body
            if method == 'GET':
                test_url = f"{url}?test={payload}"
                response = self.session.get(test_url, timeout=10)
            else:
                response = self.session.post(url, json={'test': payload}, timeout=10)
            
            # Check for injection indicators in response
            response_text = response.text.lower()
            injection_indicators = [
                'sql', 'mysql', 'oracle', 'postgresql', 'sqlite', 'database error',
                'syntax error', 'mysql_fetch_array', 'ora-', 'sqlstate'
            ]
            
            return any(indicator in response_text for indicator in injection_indicators)
            
        except Exception:
            return False
    
    def test_authentication(self, url: str, method: str, test: Dict[str, Any]) -> bool:
        """Test for missing authentication"""
        try:
            # Clear any existing authentication
            original_auth = self.session.auth
            original_headers = dict(self.session.headers)
            
            self.session.auth = None
            auth_headers = ['Authorization', 'X-API-Key', 'X-Auth-Token']
            for header in auth_headers:
                if header in self.session.headers:
                    del self.session.headers[header]
            
            # Make request without authentication
            if method == 'GET':
                response = self.session.get(url, timeout=10)
            else:
                response = self.session.post(url, timeout=10)
            
            # Restore original authentication
            self.session.auth = original_auth
            self.session.headers.update(original_headers)
            
            # Check if endpoint is accessible without authentication
            expected_status = test.get('expected_status', [401, 403])
            return response.status_code not in expected_status
            
        except Exception:
            return False
    
    def test_information_disclosure(self, url: str, method: str, test: Dict[str, Any]) -> bool:
        """Test for information disclosure vulnerabilities"""
        try:
            if method == 'GET':
                response = self.session.get(url, timeout=10)
            else:
                response = self.session.post(url, timeout=10)
            
            response_text = response.text.lower()
            
            # Check for sensitive information in response
            sensitive_patterns = [
                'stack trace', 'exception', 'error in', 'debug', 'internal server error',
                'database error', 'sql error', 'file not found', 'permission denied'
            ]
            
            return any(pattern in response_text for pattern in sensitive_patterns)
            
        except Exception:
            return False
    
    def test_rate_limiting(self, url: str, method: str, test: Dict[str, Any]) -> bool:
        """Test for missing rate limiting"""
        try:
            requests_count = test.get('requests_count', 10)
            time_window = test.get('time_window', 1)
            
            # Make multiple rapid requests
            responses = []
            for _ in range(requests_count):
                if method == 'GET':
                    response = self.session.get(url, timeout=10)
                else:
                    response = self.session.post(url, timeout=10)
                responses.append(response.status_code)
            
            # Check if all requests succeeded (no rate limiting)
            return all(status == 200 for status in responses)
            
        except Exception:
            return False
    
    def test_http_methods(self, url: str, method: str, test: Dict[str, Any]) -> bool:
        """Test dangerous HTTP methods"""
        try:
            dangerous_methods = test.get('methods', ['PUT', 'DELETE', 'TRACE', 'OPTIONS', 'PATCH'])
            
            # Test each dangerous method
            for test_method in dangerous_methods:
                try:
                    if test_method == 'GET':
                        response = self.session.get(url, timeout=10)
                    elif test_method == 'POST':
                        response = self.session.post(url, timeout=10)
                    elif test_method == 'PUT':
                        response = self.session.put(url, timeout=10)
                    elif test_method == 'DELETE':
                        response = self.session.delete(url, timeout=10)
                    elif test_method == 'PATCH':
                        response = self.session.patch(url, timeout=10)
                    elif test_method == 'OPTIONS':
                        response = self.session.options(url, timeout=10)
                    elif test_method == 'HEAD':
                        response = self.session.head(url, timeout=10)
                    else:
                        continue
                    
                    # If we get a successful response (not 405 Method Not Allowed), it's a vulnerability
                    if response.status_code not in [405, 501, 502, 503]:
                        return True
                        
                except Exception:
                    continue
            
            return False
            
        except Exception:
            return False
    
    def test_security_headers(self, url: str, method: str, test: Dict[str, Any]) -> bool:
        """Test security headers"""
        try:
            # Make a request to get response headers
            if method == 'GET':
                response = self.session.get(url, timeout=10)
            else:
                response = self.session.post(url, timeout=10)
            
            # Check for missing required headers
            required_headers = test.get('required_headers', [])
            missing_headers = []
            for header in required_headers:
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                return True  # Vulnerability found - missing headers
            
            # Check for weak configurations
            weak_configs = test.get('weak_configs', {})
            for header, weak_values in weak_configs.items():
                if header in response.headers:
                    header_value = response.headers[header].lower()
                    for weak_value in weak_values:
                        if weak_value.lower() in header_value:
                            return True  # Vulnerability found - weak configuration
            
            return False
            
        except Exception:
            return False
    
    def test_cors_misconfiguration(self, url: str, method: str, test: Dict[str, Any]) -> bool:
        """Test CORS configuration"""
        try:
            origin_headers = test.get('origin_headers', [])
            
            # Test each malicious origin
            for origin in origin_headers:
                try:
                    # Set Origin header
                    headers = {'Origin': origin}
                    
                    if method == 'GET':
                        response = self.session.get(url, headers=headers, timeout=10)
                    else:
                        response = self.session.post(url, headers=headers, timeout=10)
                    
                    # Check if the origin is reflected in Access-Control-Allow-Origin
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    if origin in acao or '*' in acao:
                        return True  # Vulnerability found
                        
                except Exception:
                    continue
            
            return False
            
        except Exception:
            return False
    
    def test_ssl_tls(self, url: str, method: str, test: Dict[str, Any]) -> bool:
        """Test SSL/TLS configuration"""
        try:
            # Check if the connection is secure
            if not self.session.is_secure:
                return False
            
            # Check if the cipher suite is strong
            if self.session.cipher:
                cipher_strength = self.session.cipher.strength
                if cipher_strength < test.get('min_cipher_strength', 128):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def test_cache_control(self, url: str, method: str, test: Dict[str, Any]) -> bool:
        """Test cache control headers"""
        try:
            # Make a request to get response headers
            if method == 'GET':
                response = self.session.get(url, timeout=10)
            else:
                response = self.session.post(url, timeout=10)
            
            # Check for missing cache control headers
            cache_control = response.headers.get('Cache-Control', '')
            pragma = response.headers.get('Pragma', '')
            
            # If no cache control headers, it's a vulnerability
            if not cache_control and not pragma:
                return True
            
            # Check for weak cache control configurations
            cache_control_lower = cache_control.lower()
            weak_configs = [
                'public',
                'max-age=0',
                'no-cache=""',
                'no-store=""'
            ]
            
            for weak_config in weak_configs:
                if weak_config in cache_control_lower:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def test_server_information(self, url: str, method: str, test: Dict[str, Any]) -> bool:
        """Test server information disclosure"""
        try:
            # Make a request to get response headers
            if method == 'GET':
                response = self.session.get(url, timeout=10)
            else:
                response = self.session.post(url, timeout=10)
            
            # Check if sensitive headers are exposed
            sensitive_headers = test.get('sensitive_headers', [])
            for header in sensitive_headers:
                if header in response.headers:
                    return True  # Vulnerability found - sensitive header exposed
            
            return False
            
        except Exception:
            return False
    
    def test_debug_endpoints(self, url: str, method: str, test: Dict[str, Any]) -> bool:
        """Test for exposed debug endpoints"""
        try:
            # Check if the endpoint is in the debug paths
            debug_paths = test.get('debug_paths', [])
            for path in debug_paths:
                if path in url:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def test_version_disclosure(self, url: str, method: str, test: Dict[str, Any]) -> bool:
        """Test for version information disclosure"""
        try:
            # Check if the version is exposed in the response
            response = self.session.get(url, timeout=10)
            response_text = response.text.lower()
            
            # Check for version indicators in the response
            version_indicators = test.get('version_indicators', [])
            for indicator in version_indicators:
                if indicator in response_text:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def upload_and_scan_collection(self, file_path: str, base_url: str = None, auth_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Upload and scan API collection file"""
        try:
            print(f"📁 Reading collection file: {file_path}")
            
            # Read collection file
            with open(file_path, 'r', encoding='utf-8') as f:
                collection_data = json.load(f)
            
            # Detect collection format
            format_type = self.detect_collection_format(collection_data)
            print(f"🔍 Detected collection format: {format_type}")
            
            # Parse collection
            endpoints = self.parse_api_collection(collection_data, format_type, base_url)
            print(f"📊 Found {len(endpoints)} endpoints in collection")
            
            if not endpoints:
                return {
                    'collection_file': file_path,
                    'collection_format': format_type,
                    'endpoints_found': 0,
                    'error': 'No endpoints found in collection',
                    'status': 'failed'
                }
            
            # Apply authentication if provided
            if auth_config:
                self.set_auth_config(auth_config)
                print(f"🔐 Applied authentication: {auth_config.get('type', 'unknown')}")
            
            # Scan endpoints
            print(f"🚀 Starting scan of {len(endpoints)} endpoints...")
            scan_results = self.scan_api_endpoints(endpoints)
            
            # Ensure scan results have the correct structure
            if 'scan_results' not in scan_results:
                # The scan_results is already the complete result
                final_results = scan_results
            else:
                # Extract the nested scan_results
                final_results = scan_results['scan_results']
            
            # Add collection metadata
            final_results.update({
                'collection_file': file_path,
                'collection_format': format_type,
                'scan_type': 'collection_upload'
            })
            
            print(f"✅ Collection scan completed successfully")
            print(f"📈 Results: {final_results.get('endpoints_scanned', 0)}/{final_results.get('endpoints_found', 0)} endpoints scanned")
            print(f"🚨 Vulnerabilities found: {len(final_results.get('vulnerabilities_found', []))}")
            
            return {
                'collection_file': file_path,
                'collection_format': format_type,
                'endpoints_found': len(endpoints),
                'scan_results': final_results,
                'status': 'completed'
            }
            
        except FileNotFoundError:
            error_msg = f"Collection file not found: {file_path}"
            print(f"❌ {error_msg}")
            return {
                'collection_file': file_path,
                'error': error_msg,
                'status': 'failed'
            }
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON in collection file: {str(e)}"
            print(f"❌ {error_msg}")
            return {
                'collection_file': file_path,
                'error': error_msg,
                'status': 'failed'
            }
        except Exception as e:
            error_msg = f"Error scanning collection: {str(e)}"
            print(f"❌ {error_msg}")
            return {
                'collection_file': file_path,
                'error': error_msg,
                'status': 'failed'
            }
    
    def scan_from_swagger_url(self, swagger_url: str, base_url: str = None, auth_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Scan API endpoints from Swagger/OpenAPI URL"""
        try:
            # Fetch Swagger specification
            response = self.session.get(swagger_url)
            response.raise_for_status()
            
            # Parse specification
            spec = response.json()
            endpoints = self.parse_swagger_spec(spec, base_url)
            
            # Apply authentication if provided
            if auth_config:
                self.set_auth_config(auth_config)
            
            # Scan endpoints
            scan_results = self.scan_api_endpoints(endpoints)
            
            return {
                'swagger_url': swagger_url,
                'endpoints_found': len(endpoints),
                'scan_results': scan_results,
                'status': 'completed'
            }
            
        except Exception as e:
            return {
                'swagger_url': swagger_url,
                'error': str(e),
                'status': 'failed'
            }
    
    def scan_from_json_file(self, json_file_path: str, base_url: str, auth_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Scan API endpoints from JSON file"""
        try:
            # Read JSON file
            with open(json_file_path, 'r') as f:
                spec = json.load(f)
            
            # Parse specification
            endpoints = self.parse_swagger_spec(spec, base_url)
            
            # Apply authentication if provided
            if auth_config:
                self.set_auth_config(auth_config)
            
            # Scan endpoints
            scan_results = self.scan_api_endpoints(endpoints)
            
            return {
                'json_file': json_file_path,
                'endpoints_found': len(endpoints),
                'scan_results': scan_results,
                'status': 'completed'
            }
            
        except Exception as e:
            return {
                'json_file': json_file_path,
                'error': str(e),
                'status': 'failed'
            }
    
    def set_auth_config(self, auth_config: Dict[str, Any]):
        """Set authentication configuration for scanning"""
        self.auth_config = auth_config
        # Apply authentication to session
        if auth_config.get('type') == 'bearer':
            self.session.headers['Authorization'] = f"Bearer {auth_config.get('token', '')}"
        elif auth_config.get('type') == 'apikey':
            key = auth_config.get('key', '')
            value = auth_config.get('value', '')
            if key and value:
                self.session.headers[key] = value
        elif auth_config.get('type') == 'basic':
            username = auth_config.get('username', '')
            password = auth_config.get('password', '')
            if username and password:
                self.session.auth = (username, password)
        elif auth_config.get('type') == 'oauth2':
            # Handle OAuth2 access token
            access_token = auth_config.get('access_token', '')
            if access_token:
                self.session.headers['Authorization'] = f"Bearer {access_token}"
        elif auth_config.get('type') == 'custom':
            headers = auth_config.get('headers', {})
            self.session.headers.update(headers)
    
    def detect_collection_format(self, collection_data: dict) -> str:
        """Detect the format of API collection"""
        if 'info' in collection_data and 'item' in collection_data:
            return 'postman'
        elif 'openapi' in collection_data or 'swagger' in collection_data:
            return 'openapi'
        elif 'requests' in collection_data:
            return 'insomnia'
        else:
            return 'generic'
    
    def parse_api_collection(self, collection_data: dict, format_type: str, base_url: str = None) -> list:
        """Parse API collection based on format"""
        if format_type == 'postman':
            return self._parse_postman_collection(collection_data, base_url)
        elif format_type == 'openapi':
            return self.parse_swagger_spec(collection_data, base_url)
        elif format_type == 'insomnia':
            return self._parse_insomnia_collection(collection_data, base_url)
        else:
            return self._parse_generic_collection(collection_data, base_url)
    
    def _parse_postman_collection(self, collection_data: dict, base_url: str = None) -> list:
        """Parse Postman collection"""
        endpoints = []
        
        def parse_items(items, base_url):
            for item in items:
                if 'request' in item:
                    request = item['request']
                    url_obj = request.get('url', {})
                    
                    # Handle different URL formats in Postman
                    if isinstance(url_obj, dict):
                        # URL object format
                        url_str = url_obj.get('raw', '')
                        if not url_str:
                            # Try other URL properties
                            protocol = url_obj.get('protocol', 'http')
                            host = url_obj.get('host', [])
                            if isinstance(host, list):
                                host = '.'.join(host)
                            path = url_obj.get('path', [])
                            if isinstance(path, list):
                                path = '/' + '/'.join(path)
                            else:
                                path = str(path) if path else ''
                            
                            url_str = f"{protocol}://{host}{path}"
                    else:
                        # String format
                        url_str = str(url_obj)
                    
                    # Apply base URL if provided and URL is relative
                    if base_url and url_str and not url_str.startswith(('http://', 'https://')):
                        if url_str.startswith('/'):
                            url_str = f"{base_url.rstrip('/')}{url_str}"
                        else:
                            url_str = f"{base_url.rstrip('/')}/{url_str}"
                    
                    # Skip if no valid URL
                    if not url_str or not url_str.startswith(('http://', 'https://')):
                        continue
                    
                    # Get method (default to GET)
                    method = request.get('method', 'GET').upper()
                    
                    # Get headers if available
                    headers = {}
                    if 'header' in request:
                        for header in request['header']:
                            if header.get('key') and header.get('value'):
                                headers[header['key']] = header['value']
                    
                    # Get body if available
                    body = None
                    if 'body' in request and request['body']:
                        body_mode = request['body'].get('mode', '')
                        if body_mode == 'raw':
                            body = request['body'].get('raw', '')
                        elif body_mode == 'formdata':
                            body = request['body'].get('formdata', [])
                        elif body_mode == 'urlencoded':
                            body = request['body'].get('urlencoded', [])
                    
                    endpoints.append({
                        'url': url_str,
                        'method': method,
                        'name': item.get('name', ''),
                        'description': request.get('description', ''),
                        'headers': headers,
                        'body': body,
                        'auth': request.get('auth', {})
                    })
                
                # Recursively parse nested items (folders)
                if 'item' in item:
                    parse_items(item['item'], base_url)
        
        # Parse all items in the collection
        parse_items(collection_data.get('item', []), base_url)
        
        print(f"📋 Parsed {len(endpoints)} endpoints from Postman collection")
        return endpoints
    
    def _parse_insomnia_collection(self, collection_data: dict, base_url: str = None) -> list:
        """Parse Insomnia collection"""
        endpoints = []
        
        for resource in collection_data.get('resources', []):
            if resource.get('_type') == 'request':
                url = resource.get('url', '')
                if base_url and not url.startswith('http'):
                    url = f"{base_url}{url}"
                
                endpoints.append({
                    'url': url,
                    'method': resource.get('method', 'GET').upper(),
                    'name': resource.get('name', ''),
                    'description': resource.get('description', '')
                })
        
        return endpoints
    
    def _parse_generic_collection(self, collection_data: dict, base_url: str = None) -> list:
        """Parse generic collection format"""
        endpoints = []
        
        # Try to extract endpoints from various common patterns
        if 'endpoints' in collection_data:
            for endpoint in collection_data['endpoints']:
                endpoints.append({
                    'url': endpoint.get('url', ''),
                    'method': endpoint.get('method', 'GET').upper(),
                    'name': endpoint.get('name', ''),
                    'description': endpoint.get('description', '')
                })
        
        return endpoints
    
    def parse_swagger_spec(self, spec: dict, base_url: str = None) -> list:
        """Parse Swagger/OpenAPI specification"""
        swagger_version = spec.get('swagger', '')
        openapi_version = spec.get('openapi', '')
        
        if swagger_version.startswith('2.'):
            return self.parse_swagger_2_0(spec, base_url)
        elif openapi_version.startswith('3.'):
            if openapi_version.startswith('3.1'):
                return self.parse_openapi_3_1(spec, base_url)
            else:
                return self.parse_openapi_3_0(spec, base_url)
        else:
            raise ValueError(f"Unsupported specification version: swagger={swagger_version}, openapi={openapi_version}")
    
    def parse_swagger_2_0(self, spec: dict, base_url: str = None) -> list:
        """Parse Swagger 2.0 specification"""
        endpoints = []
        base_url = base_url or spec.get('host', '') + spec.get('basePath', '')
        
        for path, path_item in spec.get('paths', {}).items():
            for method, operation in path_item.items():
                if method in ['get', 'post', 'put', 'delete', 'patch']:
                    endpoints.append({
                        'url': f"{base_url}{path}",
                        'method': method.upper(),
                        'operation_id': operation.get('operationId', ''),
                        'summary': operation.get('summary', ''),
                        'parameters': operation.get('parameters', [])
                    })
        
        return endpoints
    
    def parse_openapi_3_0(self, spec: dict, base_url: str = None) -> list:
        """Parse OpenAPI 3.0 specification"""
        endpoints = []
        servers = spec.get('servers', [])
        base_url = base_url or (servers[0].get('url') if servers else '')
        
        for path, path_item in spec.get('paths', {}).items():
            for method, operation in path_item.items():
                if method in ['get', 'post', 'put', 'delete', 'patch']:
                    endpoints.append({
                        'url': f"{base_url}{path}",
                        'method': method.upper(),
                        'operation_id': operation.get('operationId', ''),
                        'summary': operation.get('summary', ''),
                        'parameters': operation.get('parameters', [])
                    })
        
        return endpoints
    
    def parse_openapi_3_1(self, spec: dict, base_url: str = None) -> list:
        """Parse OpenAPI 3.1 specification"""
        # Similar to 3.0 for now
        return self.parse_openapi_3_0(spec, base_url)
    
    def generate_api_security_report(self, scan_results: Dict[str, Any], format: str = 'json') -> str:
        """Generate API security report"""
        try:
            # Handle nested scan_results structure
            if 'scan_results' in scan_results:
                actual_results = scan_results['scan_results']
            else:
                actual_results = scan_results
            
            if format == 'json':
                # Get project root directory (2 levels up from src/core/)
                project_root = Path(__file__).parent.parent.parent
                reports_dir = project_root / 'reports' / 'json'
                reports_dir.mkdir(parents=True, exist_ok=True)
                
                # Use scan_id if available, otherwise generate timestamp
                if 'scan_id' in actual_results:
                    scan_id = actual_results['scan_id']
                    report_file = reports_dir / f"api_security_scan_{scan_id}.json"
                else:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    report_file = reports_dir / f"api_security_scan_{timestamp}.json"
                
                # Prepare report data with all necessary fields
                report_data = {
                    'scan_id': actual_results.get('scan_id', f"scan_{int(time.time())}"),
                    'scan_start_time': actual_results.get('scan_start_time', datetime.now().isoformat()),
                    'scan_end_time': actual_results.get('scan_end_time', datetime.now().isoformat()),
                    'scan_type': actual_results.get('scan_type', 'unknown'),
                    'scan_status': actual_results.get('scan_status', 'completed'),
                    'endpoints_found': actual_results.get('endpoints_found', 0),
                    'endpoints_scanned': actual_results.get('endpoints_scanned', 0),
                    'vulnerabilities_found': actual_results.get('vulnerabilities_found', []),
                    'scan_duration': actual_results.get('scan_duration', 0),
                    'error_summary': actual_results.get('error_summary', []),
                    'error_summary_stats': actual_results.get('error_summary_stats', {}),
                    'endpoint_results': actual_results.get('endpoint_results', []),
                    'collection_file': actual_results.get('collection_file', ''),
                    'collection_format': actual_results.get('collection_format', ''),
                    'report_generated_at': datetime.now().isoformat()
                }
                
                with open(report_file, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2, ensure_ascii=False)
                
                print(f"📄 JSON report generated: {report_file}")
                return str(report_file)
            else:
                return self.generate_owasp_report(scan_results, format)
                
        except Exception as e:
            print(f"❌ Error generating report: {str(e)}")
            # Return a fallback report path
            project_root = Path(__file__).parent.parent.parent
            reports_dir = project_root / 'reports' / 'json'
            reports_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            fallback_file = reports_dir / f"api_security_scan_error_{timestamp}.json"
            
            error_report = {
                'scan_id': f"error_scan_{int(time.time())}",
                'scan_start_time': datetime.now().isoformat(),
                'scan_end_time': datetime.now().isoformat(),
                'scan_type': 'error',
                'scan_status': 'failed',
                'error': f"Report generation failed: {str(e)}",
                'original_data': str(scan_results)
            }
            
            with open(fallback_file, 'w', encoding='utf-8') as f:
                json.dump(error_report, f, indent=2, ensure_ascii=False)
            
            return str(fallback_file)
    
    def generate_owasp_report(self, scan_results: Dict[str, Any], format: str = 'html') -> str:
        """Generate comprehensive OWASP API security report with all issue types"""
        if format == 'html':
            # Get project root directory (2 levels up from src/core/)
            project_root = Path(__file__).parent.parent.parent
            reports_dir = project_root / 'reports' / 'html'
            reports_dir.mkdir(parents=True, exist_ok=True)
            
            # Use scan_id if available, otherwise generate timestamp
            if 'scan_id' in scan_results:
                scan_id = scan_results['scan_id']
                report_file = reports_dir / f"owasp_api_report_{scan_id}.html"
            else:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                report_file = reports_dir / f"owasp_api_report_{timestamp}.html"
            
            # Extract issue counts
            issue_summary = scan_results.get('issue_summary', {})
            vulnerabilities = scan_results.get('vulnerabilities_found', [])
            warnings = scan_results.get('warnings_found', [])
            performance_issues = scan_results.get('performance_issues_found', [])
            configuration_issues = scan_results.get('configuration_issues_found', [])
            connectivity_issues = scan_results.get('connectivity_issues_found', [])
            errors = scan_results.get('error_summary', [])
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Comprehensive API Security Scan Report</title>
                <style>
                    body {{ 
                        font-family: Arial, sans-serif; 
                        margin: 20px; 
                        background-color: #f5f5f5;
                    }}
                    .container {{
                        max-width: 1200px;
                        margin: 0 auto;
                        background: white;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }}
                    .header {{
                        text-align: center;
                        border-bottom: 2px solid #333;
                        padding-bottom: 20px;
                        margin-bottom: 30px;
                    }}
                    .summary-grid {{
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 15px;
                        margin-bottom: 30px;
                    }}
                    .summary-card {{
                        background: #f8f9fa;
                        padding: 15px;
                        border-radius: 5px;
                        text-align: center;
                        border-left: 4px solid #007bff;
                    }}
                    .summary-card.critical {{ border-left-color: #dc3545; }}
                    .summary-card.high {{ border-left-color: #fd7e14; }}
                    .summary-card.medium {{ border-left-color: #ffc107; }}
                    .summary-card.low {{ border-left-color: #28a745; }}
                    .summary-card.warning {{ border-left-color: #17a2b8; }}
                    .summary-card.error {{ border-left-color: #6c757d; }}
                    .summary-number {{
                        font-size: 2em;
                        font-weight: bold;
                        margin-bottom: 5px;
                    }}
                    .issue-section {{
                        margin: 30px 0;
                        padding: 20px;
                        background: #f8f9fa;
                        border-radius: 5px;
                    }}
                    .issue-item {{
                        margin: 10px 0;
                        padding: 15px;
                        border-left: 4px solid #ff4444;
                        background: white;
                        border-radius: 3px;
                    }}
                    .critical {{ border-left-color: #dc3545; }}
                    .high {{ border-left-color: #fd7e14; }}
                    .medium {{ border-left-color: #ffc107; }}
                    .low {{ border-left-color: #28a745; }}
                    .warning {{ border-left-color: #17a2b8; }}
                    .error {{ border-left-color: #6c757d; }}
                    .issue-title {{
                        font-weight: bold;
                        margin-bottom: 10px;
                        color: #333;
                    }}
                    .issue-details {{
                        margin: 5px 0;
                        color: #666;
                    }}
                    .severity-badge {{
                        display: inline-block;
                        padding: 2px 8px;
                        border-radius: 12px;
                        font-size: 0.8em;
                        font-weight: bold;
                        text-transform: uppercase;
                    }}
                    .severity-critical {{ background: #dc3545; color: white; }}
                    .severity-high {{ background: #fd7e14; color: white; }}
                    .severity-medium {{ background: #ffc107; color: black; }}
                    .severity-low {{ background: #28a745; color: white; }}
                    .severity-warning {{ background: #17a2b8; color: white; }}
                    .severity-error {{ background: #6c757d; color: white; }}
                    .no-issues {{
                        text-align: center;
                        color: #28a745;
                        font-style: italic;
                        padding: 20px;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔒 Comprehensive API Security Scan Report</h1>
                        <p><strong>Scan ID:</strong> {scan_results.get('scan_id', 'N/A')}</p>
                        <p><strong>Scan Start:</strong> {scan_results.get('scan_start_time', 'N/A')}</p>
                        <p><strong>Scan End:</strong> {scan_results.get('scan_end_time', 'N/A')}</p>
                        <p><strong>Endpoints Scanned:</strong> {scan_results.get('endpoints_scanned', 0)} / {scan_results.get('endpoints_found', 0)}</p>
                        <p><strong>Scan Duration:</strong> {scan_results.get('scan_duration', 0):.2f} seconds</p>
                    </div>
                    
                    <div class="summary-grid">
                        <div class="summary-card critical">
                            <div class="summary-number">{len(vulnerabilities)}</div>
                            <div>Vulnerabilities</div>
                        </div>
                        <div class="summary-card warning">
                            <div class="summary-number">{len(warnings)}</div>
                            <div>Warnings</div>
                        </div>
                        <div class="summary-card medium">
                            <div class="summary-number">{len(performance_issues)}</div>
                            <div>Performance Issues</div>
                        </div>
                        <div class="summary-card low">
                            <div class="summary-number">{len(configuration_issues)}</div>
                            <div>Configuration Issues</div>
                        </div>
                        <div class="summary-card high">
                            <div class="summary-number">{len(connectivity_issues)}</div>
                            <div>Connectivity Issues</div>
                        </div>
                        <div class="summary-card error">
                            <div class="summary-number">{len(errors)}</div>
                            <div>Errors</div>
                        </div>
                    </div>
                    
                    <div class="issue-section">
                        <h2>📋 Endpoints Scanned ({len(scan_results.get('endpoint_results', []))})</h2>
                        {self._generate_endpoints_list_html(scan_results)}
                    </div>
                    
                    <div class="issue-section">
                        <h2>🚨 Security Vulnerabilities ({len(vulnerabilities)})</h2>
                        {self._generate_issue_html(vulnerabilities, 'vulnerability')}
                    </div>
                    
                    <div class="issue-section">
                        <h2>⚠️ Warnings ({len(warnings)})</h2>
                        {self._generate_issue_html(warnings, 'warning')}
                    </div>
                    
                    <div class="issue-section">
                        <h2>⚡ Performance Issues ({len(performance_issues)})</h2>
                        {self._generate_issue_html(performance_issues, 'performance')}
                    </div>
                    
                    <div class="issue-section">
                        <h2>⚙️ Configuration Issues ({len(configuration_issues)})</h2>
                        {self._generate_issue_html(configuration_issues, 'configuration')}
                    </div>
                    
                    <div class="issue-section">
                        <h2>🌐 Connectivity Issues ({len(connectivity_issues)})</h2>
                        {self._generate_issue_html(connectivity_issues, 'connectivity')}
                    </div>
                    
                    <div class="issue-section">
                        <h2>❌ Errors ({len(errors)})</h2>
                        {self._generate_error_html(errors)}
                    </div>
                    
                    <div class="issue-section">
                        <h2>📊 Detailed Statistics</h2>
                        {self._generate_statistics_html(scan_results)}
                    </div>
                </div>
            </body>
            </html>
            """
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"📄 Comprehensive HTML report generated: {report_file}")
            return str(report_file)
        else:
            return self.generate_api_security_report(scan_results, 'json')
    
    def _generate_issue_html(self, issues: List[Dict[str, Any]], issue_type: str) -> str:
        """Generate HTML for any type of issues"""
        if not issues:
            return f'<div class="no-issues">✅ No {issue_type} issues found.</div>'
        
        html = ""
        for issue in issues:
            severity = issue.get('severity', 'medium').lower()
            html += f"""
            <div class="issue-item {severity}">
                <div class="issue-title">
                    <span class="severity-badge severity-{severity}">{severity}</span>
                    {issue.get('type', 'Unknown Issue')}
                </div>
                <div class="issue-details"><strong>Description:</strong> {issue.get('description', 'No description')}</div>
                <div class="issue-details"><strong>Evidence:</strong> {issue.get('evidence', 'No evidence')}</div>
                <div class="issue-details"><strong>Category:</strong> {issue.get('category', 'Unknown')}</div>
                {f'<div class="issue-details"><strong>URL:</strong> {issue.get("url", "N/A")}</div>' if issue.get('url') else ''}
                {f'<div class="issue-details"><strong>Method:</strong> {issue.get("method", "N/A")}</div>' if issue.get('method') else ''}
            </div>
            """
        
        return html
    
    def _generate_error_html(self, errors: List[str]) -> str:
        """Generate HTML for error summary"""
        if not errors:
            return '<div class="no-issues">✅ No errors encountered during scan.</div>'
        
        html = ""
        for error in errors:
            html += f"""
            <div class="issue-item error">
                <div class="issue-title">
                    <span class="severity-badge severity-error">Error</span>
                    Scan Error
                </div>
                <div class="issue-details">{error}</div>
            </div>
            """
        
        return html
    
    def _generate_statistics_html(self, scan_results: Dict[str, Any]) -> str:
        """Generate HTML for detailed statistics"""
        issue_summary = scan_results.get('issue_summary', {})
        error_summary_stats = scan_results.get('error_summary_stats', {})
        
        html = f"""
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
                <h3>Issue Summary</h3>
                <ul>
                    <li><strong>Total Issues:</strong> {issue_summary.get('total_issues', 0)}</li>
                    <li><strong>Vulnerabilities:</strong> {issue_summary.get('vulnerabilities', 0)}</li>
                    <li><strong>Warnings:</strong> {issue_summary.get('warnings', 0)}</li>
                    <li><strong>Performance Issues:</strong> {issue_summary.get('performance_issues', 0)}</li>
                    <li><strong>Configuration Issues:</strong> {issue_summary.get('configuration_issues', 0)}</li>
                    <li><strong>Connectivity Issues:</strong> {issue_summary.get('connectivity_issues', 0)}</li>
                    <li><strong>Errors:</strong> {issue_summary.get('errors', 0)}</li>
                </ul>
            </div>
            <div>
                <h3>Vulnerability Severity Breakdown</h3>
                <ul>
                    <li><strong>Critical:</strong> {error_summary_stats.get('severity_breakdown', {}).get('critical', 0)}</li>
                    <li><strong>High:</strong> {error_summary_stats.get('severity_breakdown', {}).get('high', 0)}</li>
                    <li><strong>Medium:</strong> {error_summary_stats.get('severity_breakdown', {}).get('medium', 0)}</li>
                    <li><strong>Low:</strong> {error_summary_stats.get('severity_breakdown', {}).get('low', 0)}</li>
                </ul>
            </div>
        </div>
        """
        
        return html
    
    def _generate_endpoints_list_html(self, scan_results: Dict[str, Any]) -> str:
        """Generate HTML for the list of scanned endpoints"""
        endpoint_results = scan_results.get('endpoint_results', [])
        
        if not endpoint_results:
            return '<div class="no-issues">No endpoints scanned</div>'
        
        html = '<div class="endpoints-table">'
        html += '<table style="width: 100%; border-collapse: collapse; margin-top: 10px;">'
        html += '''
            <thead>
                <tr style="background-color: #f8f9fa;">
                    <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">#</th>
                    <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Method</th>
                    <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">URL</th>
                    <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Name</th>
                    <th style="padding: 10px; border: 1px solid #ddd; text-align: center;">Status</th>
                    <th style="padding: 10px; border: 1px solid #ddd; text-align: center;">Issues</th>
                </tr>
            </thead>
            <tbody>
        '''
        
        for i, endpoint_result in enumerate(endpoint_results, 1):
            endpoint = endpoint_result.get('endpoint', {})
            url = endpoint.get('url', 'N/A')
            method = endpoint.get('method', 'GET')
            name = endpoint.get('name', 'N/A')
            scan_status = endpoint_result.get('scan_status', 'unknown')
            
            # Count total issues for this endpoint
            total_issues = 0
            if 'vulnerabilities' in endpoint_result:
                total_issues += len(endpoint_result['vulnerabilities'])
            if 'warnings' in endpoint_result:
                total_issues += len(endpoint_result['warnings'])
            if 'performance_issues' in endpoint_result:
                total_issues += len(endpoint_result['performance_issues'])
            if 'configuration_issues' in endpoint_result:
                total_issues += len(endpoint_result['configuration_issues'])
            if 'connectivity_issues' in endpoint_result:
                total_issues += len(endpoint_result['connectivity_issues'])
            if 'errors' in endpoint_result:
                total_issues += len(endpoint_result['errors'])
            
            # Status color
            status_color = '#28a745' if scan_status == 'completed' else '#ffc107' if scan_status == 'running' else '#dc3545'
            
            # Issues color
            issues_color = '#dc3545' if total_issues > 0 else '#28a745'
            
            html += f'''
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">{i}</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold; color: #007bff;">{method}</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace; word-break: break-all;">{url}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{name}</td>
                    <td style="padding: 8px; border: 1px solid #ddd; text-align: center;">
                        <span style="color: {status_color}; font-weight: bold;">{scan_status.upper()}</span>
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd; text-align: center;">
                        <span style="color: {issues_color}; font-weight: bold;">{total_issues}</span>
                    </td>
                </tr>
            '''
        
        html += '</tbody></table></div>'
        return html