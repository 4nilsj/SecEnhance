#!/usr/bin/env python3
"""
Advanced API Security Scanner Demo
Comprehensive security testing with detailed analysis and reporting
"""

import time
import json
import requests
import concurrent.futures
from datetime import datetime
from urllib.parse import urljoin, urlparse

class AdvancedAPIScanner:
    def __init__(self, base_url="http://localhost:5001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Advanced-API-Scanner/1.0'
        })
        self.results = {
            'scan_info': {
                'start_time': datetime.now().isoformat(),
                'base_url': base_url,
                'scanner_version': '1.0'
            },
            'endpoints': {},
            'vulnerabilities': [],
            'performance_metrics': {},
            'recommendations': []
        }
    
    def scan_endpoint(self, path, method='GET', **kwargs):
        """Scan a single endpoint with comprehensive testing"""
        url = urljoin(self.base_url, path)
        
        try:
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = self.session.get(url, timeout=10, **kwargs)
            elif method.upper() == 'POST':
                response = self.session.post(url, timeout=10, **kwargs)
            elif method.upper() == 'PUT':
                response = self.session.put(url, timeout=10, **kwargs)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, timeout=10, **kwargs)
            else:
                response = self.session.request(method, url, timeout=10, **kwargs)
            
            duration = time.time() - start_time
            
            return {
                'url': url,
                'method': method,
                'status_code': response.status_code,
                'duration': duration,
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'content': response.text[:1000],  # First 1000 chars
                'accessible': True
            }
            
        except Exception as e:
            return {
                'url': url,
                'method': method,
                'error': str(e),
                'accessible': False
            }
    
    def test_sql_injection(self, endpoint):
        """Test for SQL injection vulnerabilities"""
        print(f"🔍 Testing SQL Injection on {endpoint}")
        
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "' UNION SELECT username,password FROM users--",
            "admin'--",
            "admin' OR '1'='1'--"
        ]
        
        vulnerabilities = []
        
        for payload in payloads:
            try:
                # Test in query parameters
                url = f"{self.base_url}{endpoint}?search={payload}"
                response = self.session.get(url, timeout=5)
                
                # Check for SQL injection indicators
                indicators = [
                    'sql', 'mysql', 'oracle', 'postgresql', 'sqlite',
                    'syntax error', 'mysql_fetch', 'ora-', 'sql server'
                ]
                
                content_lower = response.text.lower()
                for indicator in indicators:
                    if indicator in content_lower:
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'payload': payload,
                            'url': url,
                            'status_code': response.status_code,
                            'indicator': indicator,
                            'severity': 'Critical',
                            'description': f'Potential SQL injection detected with payload: {payload}'
                        })
                        break
                
                # Check for unusual response patterns
                if response.status_code == 200 and len(response.content) > 0:
                    if 'error' not in content_lower and 'exception' not in content_lower:
                        # Check if response contains data that shouldn't be there
                        if len(response.content) > 100:  # Unusually large response
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'payload': payload,
                                'url': url,
                                'status_code': response.status_code,
                                'severity': 'High',
                                'description': f'Potential SQL injection - unusual response size with payload: {payload}'
                            })
                
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def test_xss(self, endpoint):
        """Test for Cross-Site Scripting vulnerabilities"""
        print(f"🔍 Testing XSS on {endpoint}")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>"
        ]
        
        vulnerabilities = []
        
        for payload in payloads:
            try:
                # Test in query parameters
                url = f"{self.base_url}{endpoint}?name={payload}&search={payload}"
                response = self.session.get(url, timeout=5)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'payload': payload,
                        'url': url,
                        'status_code': response.status_code,
                        'severity': 'High',
                        'description': f'XSS payload reflected in response: {payload}'
                    })
                
                # Test in JSON body for POST requests
                if endpoint.startswith('/api/'):
                    try:
                        response = self.session.post(
                            f"{self.base_url}{endpoint}",
                            json={"name": payload, "data": payload},
                            timeout=5
                        )
                        
                        if payload in response.text:
                            vulnerabilities.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'payload': payload,
                                'url': f"{self.base_url}{endpoint}",
                                'method': 'POST',
                                'status_code': response.status_code,
                                'severity': 'High',
                                'description': f'XSS payload reflected in POST response: {payload}'
                            })
                    except:
                        pass
                
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def test_authentication_bypass(self, endpoint):
        """Test for authentication bypass vulnerabilities"""
        print(f"🔍 Testing Authentication Bypass on {endpoint}")
        
        bypass_attempts = [
            # Common admin endpoints
            {'url': f"{self.base_url}/api/admin/users", 'method': 'GET'},
            {'url': f"{self.base_url}/api/admin/config", 'method': 'GET'},
            {'url': f"{self.base_url}/api/admin/settings", 'method': 'GET'},
            
            # Common auth endpoints
            {'url': f"{self.base_url}/api/auth/login", 'method': 'POST', 'json': {'username': 'admin', 'password': 'admin'}},
            {'url': f"{self.base_url}/api/auth/login", 'method': 'POST', 'json': {'username': 'admin', 'password': ''}},
            {'url': f"{self.base_url}/api/auth/login", 'method': 'POST', 'json': {'username': 'admin', 'password': 'password'}},
            
            # Common bypass patterns
            {'url': f"{self.base_url}/api/users?admin=true", 'method': 'GET'},
            {'url': f"{self.base_url}/api/users?role=admin", 'method': 'GET'},
            {'url': f"{self.base_url}/api/users?debug=true", 'method': 'GET'},
        ]
        
        vulnerabilities = []
        
        for attempt in bypass_attempts:
            try:
                if attempt['method'] == 'GET':
                    response = self.session.get(attempt['url'], timeout=5)
                else:
                    response = self.session.post(attempt['url'], json=attempt.get('json', {}), timeout=5)
                
                # Check if we got access to sensitive data
                if response.status_code == 200:
                    content = response.text.lower()
                    sensitive_indicators = ['admin', 'password', 'secret', 'config', 'settings', 'user']
                    
                    for indicator in sensitive_indicators:
                        if indicator in content:
                            vulnerabilities.append({
                                'type': 'Authentication Bypass',
                                'url': attempt['url'],
                                'method': attempt['method'],
                                'status_code': response.status_code,
                                'indicator': indicator,
                                'severity': 'Critical',
                                'description': f'Potential authentication bypass - sensitive data accessible: {indicator}'
                            })
                            break
                
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def test_information_disclosure(self, endpoint):
        """Test for information disclosure vulnerabilities"""
        print(f"🔍 Testing Information Disclosure on {endpoint}")
        
        # Common sensitive files and endpoints
        sensitive_paths = [
            '/.env',
            '/config.json',
            '/config.php',
            '/.git/config',
            '/debug',
            '/api/debug',
            '/api/health',
            '/api/status',
            '/api/version',
            '/api/info'
        ]
        
        vulnerabilities = []
        
        for path in sensitive_paths:
            try:
                url = f"{self.base_url}{path}"
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200 and len(response.content) > 0:
                    content = response.text.lower()
                    
                    # Check for sensitive information
                    sensitive_patterns = [
                        'password', 'secret', 'key', 'token', 'database', 'config',
                        'api_key', 'private_key', 'ssh_key', 'aws_key', 'mysql',
                        'postgresql', 'mongodb', 'redis', 'elasticsearch'
                    ]
                    
                    for pattern in sensitive_patterns:
                        if pattern in content:
                            vulnerabilities.append({
                                'type': 'Information Disclosure',
                                'url': url,
                                'pattern': pattern,
                                'status_code': response.status_code,
                                'severity': 'Medium',
                                'description': f'Sensitive information disclosed: {pattern}'
                            })
                            break
                
            except Exception as e:
                continue
        
        # Test debug parameters
        debug_params = ['debug', 'verbose', 'trace', 'log', 'test']
        for param in debug_params:
            try:
                url = f"{self.base_url}{endpoint}?{param}=true"
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    if any(pattern in content for pattern in ['debug', 'trace', 'log', 'error']):
                        vulnerabilities.append({
                            'type': 'Information Disclosure',
                            'url': url,
                            'parameter': param,
                            'status_code': response.status_code,
                            'severity': 'Medium',
                            'description': f'Debug information disclosed via parameter: {param}'
                        })
                
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def test_rate_limiting(self, endpoint):
        """Test for rate limiting vulnerabilities"""
        print(f"🔍 Testing Rate Limiting on {endpoint}")
        
        url = f"{self.base_url}{endpoint}"
        vulnerabilities = []
        
        # Send multiple rapid requests
        start_time = time.time()
        responses = []
        
        for i in range(20):  # Send 20 requests rapidly
            try:
                response = self.session.get(url, timeout=2)
                responses.append(response.status_code)
            except:
                responses.append('error')
        
        duration = time.time() - start_time
        
        # Check if all requests succeeded (no rate limiting)
        successful_requests = sum(1 for r in responses if r == 200)
        
        if successful_requests >= 15:  # If most requests succeeded
            vulnerabilities.append({
                'type': 'Rate Limiting Bypass',
                'url': url,
                'requests_sent': 20,
                'successful_requests': successful_requests,
                'duration': duration,
                'severity': 'Medium',
                'description': f'No rate limiting detected - {successful_requests}/20 requests succeeded'
            })
        
        return vulnerabilities
    
    def run_comprehensive_scan(self):
        """Run comprehensive security scan"""
        print("🚀 Advanced API Security Scanner")
        print("=" * 50)
        print(f"Target: {self.base_url}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Define endpoints to scan
        endpoints = [
            '/api/users',
            '/api/users/1',
            '/api/auth/login',
            '/api/admin/users',
            '/api/files/upload',
            '/api/search',
            '/api/data/records'
        ]
        
        all_vulnerabilities = []
        
        # Scan each endpoint
        for endpoint in endpoints:
            print(f"📍 Scanning endpoint: {endpoint}")
            
            # Basic connectivity test
            basic_result = self.scan_endpoint(endpoint)
            self.results['endpoints'][endpoint] = basic_result
            
            if basic_result.get('accessible', False):
                print(f"   ✅ Accessible (Status: {basic_result['status_code']})")
                
                # Run security tests
                sql_vulns = self.test_sql_injection(endpoint)
                xss_vulns = self.test_xss(endpoint)
                auth_vulns = self.test_authentication_bypass(endpoint)
                info_vulns = self.test_information_disclosure(endpoint)
                rate_vulns = self.test_rate_limiting(endpoint)
                
                # Combine all vulnerabilities
                endpoint_vulns = sql_vulns + xss_vulns + auth_vulns + info_vulns + rate_vulns
                all_vulnerabilities.extend(endpoint_vulns)
                
                print(f"   🚨 Vulnerabilities found: {len(endpoint_vulns)}")
            else:
                print(f"   ❌ Not accessible: {basic_result.get('error', 'Unknown error')}")
        
        self.results['vulnerabilities'] = all_vulnerabilities
        
        # Performance testing
        print("\n⚡ Performance Testing...")
        performance_results = self.test_performance()
        self.results['performance_metrics'] = performance_results
        
        # Generate recommendations
        self.generate_recommendations()
        
        # Generate report
        self.generate_report()
        
        return self.results
    
    def test_performance(self):
        """Test performance with parallel requests"""
        endpoints = ['/api/users', '/api/users/1', '/api/auth/login', '/api/admin/users']
        
        # Sequential requests
        start_time = time.time()
        for endpoint in endpoints:
            try:
                self.scan_endpoint(endpoint)
            except:
                pass
        sequential_time = time.time() - start_time
        
        # Parallel requests
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(self.scan_endpoint, endpoint) for endpoint in endpoints]
            concurrent.futures.wait(futures)
        parallel_time = time.time() - start_time
        
        improvement = ((sequential_time - parallel_time) / sequential_time * 100) if sequential_time > 0 else 0
        
        return {
            'sequential_time': sequential_time,
            'parallel_time': parallel_time,
            'improvement_percentage': improvement,
            'requests_per_second': len(endpoints) / parallel_time if parallel_time > 0 else 0
        }
    
    def generate_recommendations(self):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Count vulnerabilities by type
        vuln_types = {}
        for vuln in self.results['vulnerabilities']:
            vuln_type = vuln['type']
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        # Generate specific recommendations
        if 'SQL Injection' in vuln_types:
            recommendations.extend([
                "🔐 Implement parameterized queries to prevent SQL injection",
                "🛡️ Use input validation and sanitization",
                "🔒 Apply the principle of least privilege to database users"
            ])
        
        if 'Cross-Site Scripting (XSS)' in vuln_types:
            recommendations.extend([
                "🛡️ Implement proper output encoding",
                "🔒 Use Content Security Policy (CSP) headers",
                "✅ Validate and sanitize all user inputs"
            ])
        
        if 'Authentication Bypass' in vuln_types:
            recommendations.extend([
                "🔐 Implement proper authentication mechanisms",
                "🛡️ Use multi-factor authentication where possible",
                "🔒 Apply proper session management"
            ])
        
        if 'Information Disclosure' in vuln_types:
            recommendations.extend([
                "🔒 Remove debug information from production",
                "🛡️ Implement proper error handling",
                "🔐 Use environment variables for sensitive configuration"
            ])
        
        if 'Rate Limiting Bypass' in vuln_types:
            recommendations.extend([
                "🛡️ Implement rate limiting on all endpoints",
                "🔒 Use API keys and request throttling",
                "📊 Monitor for unusual traffic patterns"
            ])
        
        # General recommendations
        recommendations.extend([
            "🔒 Implement HTTPS/TLS encryption",
            "🛡️ Use security headers (HSTS, CSP, X-Frame-Options)",
            "📋 Regular security audits and penetration testing",
            "🔄 Keep all dependencies updated",
            "📊 Implement comprehensive logging and monitoring"
        ])
        
        self.results['recommendations'] = recommendations
    
    def generate_report(self):
        """Generate comprehensive security report"""
        print("\n📊 Advanced Security Scan Report")
        print("=" * 50)
        
        # Summary
        total_endpoints = len(self.results['endpoints'])
        accessible_endpoints = sum(1 for e in self.results['endpoints'].values() if e.get('accessible', False))
        total_vulnerabilities = len(self.results['vulnerabilities'])
        
        print(f"📍 Endpoints tested: {total_endpoints}")
        print(f"✅ Accessible endpoints: {accessible_endpoints}")
        print(f"🚨 Total vulnerabilities: {total_vulnerabilities}")
        
        # Vulnerability breakdown
        if self.results['vulnerabilities']:
            print("\n🚨 Vulnerability Breakdown:")
            by_severity = {}
            by_type = {}
            
            for vuln in self.results['vulnerabilities']:
                severity = vuln.get('severity', 'Unknown')
                vuln_type = vuln.get('type', 'Unknown')
                
                by_severity[severity] = by_severity.get(severity, 0) + 1
                by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
            
            print("   By Severity:")
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                if severity in by_severity:
                    print(f"     {severity}: {by_severity[severity]}")
            
            print("   By Type:")
            for vuln_type, count in by_type.items():
                print(f"     {vuln_type}: {count}")
        
        # Performance metrics
        if self.results['performance_metrics']:
            metrics = self.results['performance_metrics']
            print(f"\n⚡ Performance Metrics:")
            print(f"   Sequential time: {metrics['sequential_time']:.3f}s")
            print(f"   Parallel time: {metrics['parallel_time']:.3f}s")
            print(f"   Performance improvement: {metrics['improvement_percentage']:.1f}%")
            print(f"   Requests per second: {metrics['requests_per_second']:.2f}")
        
        # Top recommendations
        if self.results['recommendations']:
            print(f"\n💡 Top Recommendations:")
            for i, rec in enumerate(self.results['recommendations'][:5], 1):
                print(f"   {i}. {rec}")
        
        # Save detailed report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"advanced_security_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"\n📄 Detailed report saved to: {filename}")
        
        # Risk assessment
        critical_count = sum(1 for v in self.results['vulnerabilities'] if v.get('severity') == 'Critical')
        high_count = sum(1 for v in self.results['vulnerabilities'] if v.get('severity') == 'High')
        
        if critical_count > 0:
            print(f"🚨 CRITICAL RISK: {critical_count} critical vulnerabilities found!")
        elif high_count > 0:
            print(f"⚠️ HIGH RISK: {high_count} high severity vulnerabilities found!")
        elif total_vulnerabilities > 0:
            print(f"⚠️ MEDIUM RISK: {total_vulnerabilities} vulnerabilities found!")
        else:
            print(f"✅ LOW RISK: No obvious vulnerabilities detected!")

def main():
    """Main function"""
    scanner = AdvancedAPIScanner("http://localhost:5001")
    results = scanner.run_comprehensive_scan()
    
    print(f"\n✅ Advanced security scan completed!")
    print(f"📊 Found {len(results['vulnerabilities'])} vulnerabilities")
    print(f"⚡ Performance improvement: {results['performance_metrics']['improvement_percentage']:.1f}%")

if __name__ == "__main__":
    main() 