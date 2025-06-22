#!/usr/bin/env python3
"""
API Security Scanner - Refactored Version
A comprehensive, modular API security scanning tool with improved error handling
"""

import requests
import json
import time
import os
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from src.config.app_config import get_config

# Setup logging
def setup_logger():
    """Setup application logger"""
    if config:
        log_config = config.get_logging_config()
        logging.basicConfig(
            level=getattr(logging, log_config['level']),
            format=log_config['format'],
            handlers=[
                logging.FileHandler(log_config['file']),
                logging.StreamHandler()
            ]
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    return logging.getLogger(__name__)

logger = setup_logger()

class ScanError(Exception):
    """Custom exception for scan errors"""
    pass

class ConfigurationError(Exception):
    """Custom exception for configuration errors"""
    pass

class SecurityTest:
    """Base class for security tests"""
    
    def __init__(self, name: str, description: str, severity: str, category: str):
        self.name = name
        self.description = description
        self.severity = severity
        self.category = category
    
    def run_test(self, url: str, method: str, session: requests.Session, **kwargs) -> Dict[str, Any]:
        """Run the security test"""
        raise NotImplementedError("Subclasses must implement run_test")

class AuthenticationTest(SecurityTest):
    """Test for authentication vulnerabilities"""
    
    def __init__(self):
        super().__init__(
            name="Missing Authentication",
            description="Test for endpoints that should require authentication",
            severity="High",
            category="authentication"
        )
    
    def run_test(self, url: str, method: str, session: requests.Session, **kwargs) -> Dict[str, Any]:
        """Test for missing authentication"""
        try:
            # Create a new session without authentication
            test_session = requests.Session()
            test_session.headers.update(session.headers)
            
            # Remove authentication headers
            for header in ['Authorization', 'X-API-Key', 'X-Auth-Token']:
                test_session.headers.pop(header, None)
            
            # Make request without authentication
            response = test_session.request(method, url, timeout=30)
            
            # Check if endpoint allows access without authentication
            if response.status_code in [200, 201, 202]:
                return {
                    'vulnerability_found': True,
                    'vulnerability': {
                        'name': self.name,
                        'description': self.description,
                        'severity': self.severity,
                        'category': self.category,
                        'url': url,
                        'method': method,
                        'status_code': response.status_code,
                        'details': f"Endpoint allows access without authentication (Status: {response.status_code})"
                    }
                }
            
            return {'vulnerability_found': False}
            
        except Exception as e:
            logger.error(f"Error in authentication test: {e}")
            return {'vulnerability_found': False, 'error': str(e)}

class InjectionTest(SecurityTest):
    """Test for injection vulnerabilities"""
    
    def __init__(self, payloads: List[str], injection_type: str):
        super().__init__(
            name=f"{injection_type} Injection",
            description=f"Test for {injection_type} injection vulnerabilities",
            severity="Critical" if injection_type == "SQL" else "High",
            category="injection"
        )
        self.payloads = payloads
        self.injection_type = injection_type
    
    def run_test(self, url: str, method: str, session: requests.Session, **kwargs) -> Dict[str, Any]:
        """Test for injection vulnerabilities"""
        for payload in self.payloads:
            try:
                # Prepare test data
                test_data = self._prepare_test_data(method, payload)
                
                # Make request with payload
                response = session.request(
                    method, 
                    url, 
                    **test_data,
                    timeout=30
                )
                
                # Check for injection indicators
                if self._detect_injection(response, payload):
                    return {
                        'vulnerability_found': True,
                        'vulnerability': {
                            'name': self.name,
                            'description': self.description,
                            'severity': self.severity,
                            'category': self.category,
                            'url': url,
                            'method': method,
                            'payload': payload,
                            'status_code': response.status_code,
                            'details': f"Potential {self.injection_type} injection detected with payload: {payload}"
                        }
                    }
            
            except Exception as e:
                logger.error(f"Error in injection test: {e}")
                continue
        
        return {'vulnerability_found': False}
    
    def _prepare_test_data(self, method: str, payload: str) -> Dict[str, Any]:
        """Prepare test data based on HTTP method"""
        if method.upper() in ['GET', 'DELETE']:
            return {'params': {'test': payload}}
        else:
            return {'json': {'test': payload}}
    
    def _detect_injection(self, response: requests.Response, payload: str) -> bool:
        """Detect injection based on response"""
        # Check for SQL error messages
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'oracle error', 'postgresql error',
            'sql server error', 'sqlite error', 'database error'
        ]
        
        response_text = response.text.lower()
        
        # Check for SQL error messages
        for error in sql_errors:
            if error in response_text:
                return True
        
        # Check for unusual response codes
        if response.status_code in [500, 502, 503]:
            return True
        
        return False

class InformationDisclosureTest(SecurityTest):
    """Test for information disclosure vulnerabilities"""
    
    def __init__(self):
        super().__init__(
            name="Information Disclosure",
            description="Test for sensitive information in error messages",
            severity="Medium",
            category="information_disclosure"
        )
    
    def run_test(self, url: str, method: str, session: requests.Session, **kwargs) -> Dict[str, Any]:
        """Test for information disclosure"""
        try:
            # Make request with invalid data to trigger errors
            test_data = {'invalid': 'data' * 1000}  # Large invalid data
            
            response = session.request(
                method,
                url,
                json=test_data,
                timeout=30
            )
            
            # Check for sensitive information in response
            sensitive_patterns = [
                'password', 'secret', 'key', 'token', 'api_key',
                'database', 'connection', 'stack trace', 'error details',
                'file path', 'internal', 'debug'
            ]
            
            response_text = response.text.lower()
            
            for pattern in sensitive_patterns:
                if pattern in response_text:
                    return {
                        'vulnerability_found': True,
                        'vulnerability': {
                            'name': self.name,
                            'description': self.description,
                            'severity': self.severity,
                            'category': self.category,
                            'url': url,
                            'method': method,
                            'status_code': response.status_code,
                            'details': f"Sensitive information disclosed: {pattern}"
                        }
                    }
            
            return {'vulnerability_found': False}
            
        except Exception as e:
            logger.error(f"Error in information disclosure test: {e}")
            return {'vulnerability_found': False, 'error': str(e)}

class RateLimitingTest(SecurityTest):
    """Test for rate limiting vulnerabilities"""
    
    def __init__(self):
        super().__init__(
            name="Rate Limiting Bypass",
            description="Test for rate limiting vulnerabilities",
            severity="Medium",
            category="rate_limiting"
        )
    
    def run_test(self, url: str, method: str, session: requests.Session, **kwargs) -> Dict[str, Any]:
        """Test for rate limiting"""
        try:
            # Make multiple rapid requests
            responses = []
            for i in range(10):
                response = session.request(method, url, timeout=30)
                responses.append(response)
                time.sleep(0.1)  # Small delay between requests
            
            # Check if all requests succeeded (potential rate limiting bypass)
            successful_requests = sum(1 for r in responses if r.status_code in [200, 201, 202])
            
            if successful_requests >= 8:  # 80% success rate
                return {
                    'vulnerability_found': True,
                    'vulnerability': {
                        'name': self.name,
                        'description': self.description,
                        'severity': self.severity,
                        'category': self.category,
                        'url': url,
                        'method': method,
                        'details': f"Rate limiting may be insufficient ({successful_requests}/10 requests succeeded)"
                    }
                }
            
            return {'vulnerability_found': False}
            
        except Exception as e:
            logger.error(f"Error in rate limiting test: {e}")
            return {'vulnerability_found': False, 'error': str(e)}

class SecurityTestSuite:
    """Collection of security tests"""
    
    def __init__(self):
        self.tests = [
            AuthenticationTest(),
            InformationDisclosureTest(),
            RateLimitingTest(),
            InjectionTest(
                payloads=["' OR '1'='1", "'; DROP TABLE users; --", "1' UNION SELECT * FROM users --"],
                injection_type="SQL"
            ),
            InjectionTest(
                payloads=["<script>alert('XSS')</script>", "javascript:alert('XSS')", "onerror=alert('XSS')"],
                injection_type="XSS"
            )
        ]
    
    def get_tests_by_category(self, category: str) -> List[SecurityTest]:
        """Get tests by category"""
        return [test for test in self.tests if test.category == category]
    
    def get_all_tests(self) -> List[SecurityTest]:
        """Get all tests"""
        return self.tests

class ScanMetrics:
    """Track scanning metrics"""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.vulnerabilities_found = 0
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
    
    def start_scan(self):
        """Start the scan timer"""
        self.start_time = time.time()
    
    def end_scan(self):
        """End the scan timer"""
        self.end_time = time.time()
    
    def get_duration(self) -> float:
        """Get scan duration in seconds"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0
    
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary"""
        return {
            'duration': self.get_duration(),
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'vulnerabilities_found': self.vulnerabilities_found,
            'tests_run': self.tests_run,
            'tests_passed': self.tests_passed,
            'tests_failed': self.tests_failed,
            'success_rate': (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0
        }

class APISecurityScannerRefactored:
    """Refactored API Security Scanner with improved modularity and error handling"""
    
    def __init__(self, session: Optional[requests.Session] = None, 
                 auth_config: Optional[Dict[str, Any]] = None,
                 max_workers: int = 10):
        
        # Initialize session
        self.session = session or requests.Session()
        self._setup_session()
        
        # Configuration
        self.auth_config = auth_config or {}
        self.max_workers = max_workers
        
        # Components
        self.test_suite = SecurityTestSuite()
        self.metrics = ScanMetrics()
        self.scan_results = {}
        
        # Threading
        self.lock = threading.Lock()
        
        logger.info("API Security Scanner initialized successfully")
    
    def _setup_session(self):
        """Setup the HTTP session"""
        if config:
            scanner_config = config.get_scanner_config()
            self.session.headers.update({
                'User-Agent': scanner_config['user_agent']
            })
        else:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
    
    def set_auth_config(self, auth_config: Dict[str, Any]):
        """Set authentication configuration"""
        self.auth_config = auth_config
        self._apply_auth_config()
    
    def _apply_auth_config(self):
        """Apply authentication configuration to session"""
        try:
            auth_type = self.auth_config.get('type', 'none')
            
            if auth_type == 'bearer':
                token = self.auth_config.get('token')
                if token:
                    self.session.headers['Authorization'] = f'Bearer {token}'
            
            elif auth_type == 'api_key':
                key = self.auth_config.get('key')
                value = self.auth_config.get('value')
                location = self.auth_config.get('location', 'header')
                
                if key and value:
                    if location == 'header':
                        self.session.headers[key] = value
                    elif location == 'query':
                        self.session.params[key] = value
            
            elif auth_type == 'basic':
                username = self.auth_config.get('username')
                password = self.auth_config.get('password')
                if username and password:
                    self.session.auth = (username, password)
            
            logger.info(f"Authentication configured: {auth_type}")
            
        except Exception as e:
            logger.error(f"Error applying auth config: {e}")
            raise ConfigurationError(f"Failed to apply authentication configuration: {e}")
    
    def scan_api_endpoints(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan multiple API endpoints for security vulnerabilities"""
        logger.info(f"Starting security scan of {len(endpoints)} endpoints")
        
        self.metrics.start_scan()
        
        scan_results = {
            'scan_id': f"scan_{int(time.time())}",
            'timestamp': datetime.now().isoformat(),
            'endpoints_scanned': len(endpoints),
            'vulnerabilities_found': [],
            'error_summary': [],
            'endpoint_results': [],
            'metrics': {}
        }
        
        try:
            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all endpoint scans
                future_to_endpoint = {
                    executor.submit(self._scan_single_endpoint, endpoint): endpoint 
                    for endpoint in endpoints
                }
                
                # Collect results
                for future in as_completed(future_to_endpoint):
                    endpoint = future_to_endpoint[future]
                    try:
                        endpoint_result = future.result()
                        scan_results['endpoint_results'].append(endpoint_result)
                        
                        # Add vulnerabilities
                        if 'vulnerabilities' in endpoint_result:
                            scan_results['vulnerabilities_found'].extend(endpoint_result['vulnerabilities'])
                        
                        # Add errors
                        if 'errors' in endpoint_result:
                            scan_results['error_summary'].extend(endpoint_result['errors'])
                        
                    except Exception as e:
                        error_msg = f"Error scanning endpoint {endpoint.get('url', 'unknown')}: {str(e)}"
                        logger.error(error_msg)
                        scan_results['error_summary'].append(error_msg)
        
        except Exception as e:
            error_msg = f"Unexpected error during scan: {str(e)}"
            logger.error(error_msg)
            scan_results['error_summary'].append(error_msg)
        
        finally:
            self.metrics.end_scan()
            scan_results['metrics'] = self.metrics.get_summary()
        
        logger.info(f"Scan completed. Found {len(scan_results['vulnerabilities_found'])} vulnerabilities")
        return scan_results
    
    def _scan_single_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a single API endpoint for security vulnerabilities"""
        endpoint_result = {
            'endpoint': endpoint,
            'vulnerabilities': [],
            'errors': [],
            'tests_run': 0,
            'tests_passed': 0,
            'tests_failed': 0
        }
        
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET').upper()
        
        if not url:
            endpoint_result['errors'].append("No URL provided")
            return endpoint_result
        
        logger.debug(f"Scanning endpoint: {method} {url}")
        
        # Run all security tests
        for test in self.test_suite.get_all_tests():
            try:
                with self.lock:
                    self.metrics.tests_run += 1
                    endpoint_result['tests_run'] += 1
                
                # Run the security test
                test_result = test.run_test(url, method, self.session)
                
                if test_result.get('vulnerability_found'):
                    endpoint_result['vulnerabilities'].append(test_result['vulnerability'])
                    endpoint_result['tests_failed'] += 1
                    
                    with self.lock:
                        self.metrics.vulnerabilities_found += 1
                        self.metrics.tests_failed += 1
                else:
                    endpoint_result['tests_passed'] += 1
                    
                    with self.lock:
                        self.metrics.tests_passed += 1
                
                # Add test errors
                if 'error' in test_result:
                    endpoint_result['errors'].append(f"{test.name}: {test_result['error']}")
                    
            except Exception as e:
                error_msg = f"Error running {test.name}: {str(e)}"
                logger.error(error_msg)
                endpoint_result['errors'].append(error_msg)
                endpoint_result['tests_failed'] += 1
                
                with self.lock:
                    self.metrics.tests_failed += 1
        
        return endpoint_result
    
    def upload_and_scan_collection(self, file_path: str, base_url: str = None, 
                                 auth_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Upload and scan an API collection file"""
        try:
            # Set authentication if provided
            if auth_config:
                self.set_auth_config(auth_config)
            
            # Parse the collection file
            endpoints = self._parse_collection_file(file_path, base_url)
            
            if not endpoints:
                return {'error': 'No endpoints found in collection file'}
            
            # Scan the endpoints
            return self.scan_api_endpoints(endpoints)
            
        except Exception as e:
            logger.error(f"Error in upload_and_scan_collection: {e}")
            return {'error': str(e)}
    
    def _parse_collection_file(self, file_path: str, base_url: str = None) -> List[Dict[str, Any]]:
        """Parse API collection file and extract endpoints"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                collection_data = json.load(f)
            
            # Detect collection format
            format_type = self._detect_collection_format(collection_data)
            
            # Parse based on format
            if format_type == 'postman':
                return self._parse_postman_collection(collection_data, base_url)
            elif format_type == 'insomnia':
                return self._parse_insomnia_collection(collection_data, base_url)
            else:
                return self._parse_generic_collection(collection_data, base_url)
                
        except Exception as e:
            logger.error(f"Error parsing collection file: {e}")
            raise ScanError(f"Failed to parse collection file: {e}")
    
    def _detect_collection_format(self, collection_data: dict) -> str:
        """Detect the format of the API collection"""
        if 'info' in collection_data and 'schema' in collection_data.get('info', {}):
            return 'postman'
        elif 'resources' in collection_data:
            return 'insomnia'
        else:
            return 'generic'
    
    def _parse_postman_collection(self, collection_data: dict, base_url: str = None) -> List[Dict[str, Any]]:
        """Parse Postman collection format"""
        endpoints = []
        
        def parse_items(items, base_url):
            for item in items:
                if 'request' in item:
                    request = item['request']
                    url = request.get('url', {})
                    
                    if isinstance(url, dict):
                        endpoint_url = url.get('raw', '')
                        if base_url and not endpoint_url.startswith('http'):
                            endpoint_url = f"{base_url.rstrip('/')}/{endpoint_url.lstrip('/')}"
                    else:
                        endpoint_url = str(url)
                        if base_url and not endpoint_url.startswith('http'):
                            endpoint_url = f"{base_url.rstrip('/')}/{endpoint_url.lstrip('/')}"
                    
                    endpoints.append({
                        'name': item.get('name', 'Unknown'),
                        'url': endpoint_url,
                        'method': request.get('method', 'GET'),
                        'headers': request.get('header', []),
                        'body': request.get('body', {})
                    })
                
                if 'item' in item:
                    parse_items(item['item'], base_url)
        
        parse_items(collection_data.get('item', []), base_url)
        return endpoints
    
    def _parse_insomnia_collection(self, collection_data: dict, base_url: str = None) -> List[Dict[str, Any]]:
        """Parse Insomnia collection format"""
        endpoints = []
        
        for resource in collection_data.get('resources', []):
            if resource.get('_type') == 'request':
                url = resource.get('url', '')
                if base_url and not url.startswith('http'):
                    url = f"{base_url.rstrip('/')}/{url.lstrip('/')}"
                
                endpoints.append({
                    'name': resource.get('name', 'Unknown'),
                    'url': url,
                    'method': resource.get('method', 'GET'),
                    'headers': resource.get('headers', []),
                    'body': resource.get('body', {})
                })
        
        return endpoints
    
    def _parse_generic_collection(self, collection_data: dict, base_url: str = None) -> List[Dict[str, Any]]:
        """Parse generic collection format"""
        endpoints = []
        
        # Try to extract endpoints from various common structures
        if 'endpoints' in collection_data:
            items = collection_data['endpoints']
        elif 'items' in collection_data:
            items = collection_data['items']
        elif 'requests' in collection_data:
            items = collection_data['requests']
        else:
            items = collection_data
        
        for item in items:
            if isinstance(item, dict):
                url = item.get('url', item.get('path', ''))
                if base_url and not url.startswith('http'):
                    url = f"{base_url.rstrip('/')}/{url.lstrip('/')}"
                
                endpoints.append({
                    'name': item.get('name', 'Unknown'),
                    'url': url,
                    'method': item.get('method', 'GET'),
                    'headers': item.get('headers', []),
                    'body': item.get('body', {})
                })
        
        return endpoints
    
    def generate_api_security_report(self, scan_results: Dict[str, Any], format: str = 'json') -> str:
        """Generate API security report"""
        try:
            if not config:
                raise ConfigurationError("Configuration not available")
            
            reports_config = config.get_reports_config()
            paths_config = config.get_paths_config()
            
            # Ensure reports directory exists
            reports_dir = Path(paths_config['reports_dir'])
            json_dir = reports_dir / 'json'
            json_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate report filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_filename = f"api_security_report_{timestamp}.json"
            report_path = json_dir / report_filename
            
            # Prepare report data
            report_data = {
                'scan_id': scan_results.get('scan_id'),
                'scan_start_time': scan_results.get('timestamp'),
                'scan_end_time': datetime.now().isoformat(),
                'endpoints_found': scan_results.get('endpoints_scanned', 0),
                'vulnerabilities_found': len(scan_results.get('vulnerabilities_found', [])),
                'vulnerabilities': scan_results.get('vulnerabilities_found', []),
                'error_summary': scan_results.get('error_summary', []),
                'metrics': scan_results.get('metrics', {}),
                'endpoint_results': scan_results.get('endpoint_results', [])
            }
            
            # Write report
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"API security report generated: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"Error generating API security report: {e}")
            raise ScanError(f"Failed to generate report: {e}")
    
    def generate_owasp_report(self, scan_results: Dict[str, Any], format: str = 'html') -> str:
        """Generate OWASP Top 10 report"""
        try:
            if not config:
                raise ConfigurationError("Configuration not available")
            
            paths_config = config.get_paths_config()
            
            # Ensure reports directory exists
            reports_dir = Path(paths_config['reports_dir'])
            html_dir = reports_dir / 'html'
            html_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate report filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_filename = f"owasp_report_{timestamp}.html"
            report_path = html_dir / report_filename
            
            # Generate HTML content
            html_content = self._generate_owasp_html(scan_results)
            
            # Write report
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"OWASP report generated: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"Error generating OWASP report: {e}")
            raise ScanError(f"Failed to generate OWASP report: {e}")
    
    def _generate_owasp_html(self, scan_results: Dict[str, Any]) -> str:
        """Generate OWASP HTML report content"""
        vulnerabilities = scan_results.get('vulnerabilities_found', [])
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP API Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .vulnerability {{ margin: 10px 0; padding: 15px; border-left: 4px solid #ff4444; background-color: #fff5f5; }}
        .high {{ border-left-color: #ff4444; }}
        .medium {{ border-left-color: #ffaa00; }}
        .low {{ border-left-color: #44aa44; }}
        .summary {{ background-color: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 OWASP API Security Report</h1>
        <p><strong>Scan ID:</strong> {scan_results.get('scan_id', 'Unknown')}</p>
        <p><strong>Scan Date:</strong> {scan_results.get('timestamp', 'Unknown')}</p>
        <p><strong>Endpoints Scanned:</strong> {scan_results.get('endpoints_scanned', 0)}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Scan Summary</h2>
        <p><strong>Total Vulnerabilities Found:</strong> {len(vulnerabilities)}</p>
        <p><strong>High Severity:</strong> {len([v for v in vulnerabilities if v.get('severity') == 'High'])}</p>
        <p><strong>Medium Severity:</strong> {len([v for v in vulnerabilities if v.get('severity') == 'Medium'])}</p>
        <p><strong>Low Severity:</strong> {len([v for v in vulnerabilities if v.get('severity') == 'Low'])}</p>
    </div>
    
    <h2>🚨 Vulnerabilities Found</h2>
"""
        
        if vulnerabilities:
            for vuln in vulnerabilities:
                severity_class = vuln.get('severity', 'medium').lower()
                html += f"""
    <div class="vulnerability {severity_class}">
        <h3>{vuln.get('name', 'Unknown Vulnerability')}</h3>
        <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>
        <p><strong>Category:</strong> {vuln.get('category', 'Unknown')}</p>
        <p><strong>URL:</strong> {vuln.get('url', 'Unknown')}</p>
        <p><strong>Method:</strong> {vuln.get('method', 'Unknown')}</p>
        <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
        <p><strong>Details:</strong> {vuln.get('details', 'No details available')}</p>
    </div>
"""
        else:
            html += """
    <div class="vulnerability low">
        <h3>✅ No Vulnerabilities Found</h3>
        <p>Congratulations! No security vulnerabilities were detected in this scan.</p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        return html 