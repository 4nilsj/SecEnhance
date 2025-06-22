#!/usr/bin/env python3
"""
Simple API Security Scan Demo
Tests basic scanning functionality with the insecure API
"""

import time
import json
import requests
from datetime import datetime

def test_basic_connectivity():
    """Test basic connectivity to the insecure API"""
    print("🔍 Testing Basic Connectivity")
    print("-" * 40)
    
    base_url = "http://localhost:5001"
    endpoints = [
        "/api/users",
        "/api/users/1", 
        "/api/auth/login",
        "/api/admin/users"
    ]
    
    results = {}
    
    for endpoint in endpoints:
        url = base_url + endpoint
        try:
            start_time = time.time()
            response = requests.get(url, timeout=10)
            duration = time.time() - start_time
            
            results[endpoint] = {
                'status': response.status_code,
                'duration': duration,
                'content_length': len(response.content),
                'accessible': True
            }
            
            print(f"✅ {endpoint}: {response.status_code} ({duration:.3f}s)")
            
        except Exception as e:
            results[endpoint] = {
                'status': 'error',
                'error': str(e),
                'accessible': False
            }
            print(f"❌ {endpoint}: Error - {e}")
    
    return results

def test_security_vulnerabilities():
    """Test for common security vulnerabilities"""
    print("\n🚨 Testing Security Vulnerabilities")
    print("-" * 40)
    
    base_url = "http://localhost:5001"
    vulnerabilities = []
    
    # Test 1: SQL Injection
    print("🔍 Testing SQL Injection...")
    sql_payloads = [
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "' UNION SELECT * FROM users--"
    ]
    
    for payload in sql_payloads:
        try:
            url = f"{base_url}/api/users?search={payload}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200 and len(response.content) > 0:
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'payload': payload,
                    'url': url,
                    'status': response.status_code,
                    'severity': 'High'
                })
                print(f"🚨 Potential SQL Injection: {payload}")
        except:
            pass
    
    # Test 2: NoSQL Injection
    print("🔍 Testing NoSQL Injection...")
    nosql_payloads = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "1==1"}'
    ]
    
    for payload in nosql_payloads:
        try:
            url = f"{base_url}/api/users"
            response = requests.post(url, json={"id": payload}, timeout=5)
            
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'NoSQL Injection',
                    'payload': payload,
                    'url': url,
                    'status': response.status_code,
                    'severity': 'High'
                })
                print(f"🚨 Potential NoSQL Injection: {payload}")
        except:
            pass
    
    # Test 3: XSS
    print("🔍 Testing XSS...")
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>"
    ]
    
    for payload in xss_payloads:
        try:
            url = f"{base_url}/api/users?name={payload}"
            response = requests.get(url, timeout=5)
            
            if payload in response.text:
                vulnerabilities.append({
                    'type': 'XSS',
                    'payload': payload,
                    'url': url,
                    'status': response.status_code,
                    'severity': 'Medium'
                })
                print(f"🚨 Potential XSS: {payload}")
        except:
            pass
    
    # Test 4: Authentication Bypass
    print("🔍 Testing Authentication Bypass...")
    auth_bypass_tests = [
        {"url": f"{base_url}/api/admin/users", "method": "GET"},
        {"url": f"{base_url}/api/admin/users", "method": "POST", "json": {"action": "create"}},
        {"url": f"{base_url}/api/auth/login", "method": "POST", "json": {"username": "admin", "password": "admin"}}
    ]
    
    for test in auth_bypass_tests:
        try:
            if test['method'] == 'GET':
                response = requests.get(test['url'], timeout=5)
            else:
                response = requests.post(test['url'], json=test.get('json', {}), timeout=5)
            
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Authentication Bypass',
                    'url': test['url'],
                    'method': test['method'],
                    'status': response.status_code,
                    'severity': 'Critical'
                })
                print(f"🚨 Potential Auth Bypass: {test['method']} {test['url']}")
        except:
            pass
    
    # Test 5: Information Disclosure
    print("🔍 Testing Information Disclosure...")
    info_disclosure_tests = [
        f"{base_url}/.env",
        f"{base_url}/config.json",
        f"{base_url}/debug",
        f"{base_url}/api/users?debug=true"
    ]
    
    for url in info_disclosure_tests:
        try:
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200 and len(response.content) > 0:
                content = response.text.lower()
                sensitive_patterns = ['password', 'secret', 'key', 'token', 'database', 'config']
                
                for pattern in sensitive_patterns:
                    if pattern in content:
                        vulnerabilities.append({
                            'type': 'Information Disclosure',
                            'url': url,
                            'pattern': pattern,
                            'status': response.status_code,
                            'severity': 'Medium'
                        })
                        print(f"🚨 Info Disclosure: {url} (contains '{pattern}')")
                        break
        except:
            pass
    
    return vulnerabilities

def test_performance():
    """Test performance with parallel requests"""
    print("\n⚡ Testing Performance")
    print("-" * 40)
    
    import concurrent.futures
    
    base_url = "http://localhost:5001"
    endpoints = ["/api/users", "/api/users/1", "/api/auth/login", "/api/admin/users"]
    
    # Sequential requests
    print("📊 Sequential requests...")
    start_time = time.time()
    
    for endpoint in endpoints:
        try:
            requests.get(base_url + endpoint, timeout=5)
        except:
            pass
    
    sequential_time = time.time() - start_time
    print(f"⏱️ Sequential time: {sequential_time:.3f}s")
    
    # Parallel requests
    print("📊 Parallel requests...")
    start_time = time.time()
    
    def make_request(endpoint):
        try:
            return requests.get(base_url + endpoint, timeout=5)
        except:
            return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(make_request, endpoint) for endpoint in endpoints]
        concurrent.futures.wait(futures)
    
    parallel_time = time.time() - start_time
    print(f"⏱️ Parallel time: {parallel_time:.3f}s")
    
    if sequential_time > 0:
        improvement = ((sequential_time - parallel_time) / sequential_time) * 100
        print(f"📈 Performance improvement: {improvement:.1f}%")
    
    return {
        'sequential_time': sequential_time,
        'parallel_time': parallel_time,
        'improvement': improvement if sequential_time > 0 else 0
    }

def generate_report(connectivity_results, vulnerabilities, performance_results):
    """Generate a comprehensive security report"""
    print("\n📊 Security Scan Report")
    print("=" * 50)
    
    # Summary
    accessible_endpoints = sum(1 for r in connectivity_results.values() if r.get('accessible', False))
    total_endpoints = len(connectivity_results)
    total_vulnerabilities = len(vulnerabilities)
    
    print(f"📍 Endpoints tested: {total_endpoints}")
    print(f"✅ Accessible endpoints: {accessible_endpoints}")
    print(f"🚨 Vulnerabilities found: {total_vulnerabilities}")
    
    # Vulnerability breakdown
    if vulnerabilities:
        print("\n🚨 Vulnerability Breakdown:")
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity in by_severity:
                count = len(by_severity[severity])
                print(f"   {severity}: {count}")
    
    # Performance summary
    if performance_results:
        print(f"\n⚡ Performance Summary:")
        print(f"   Sequential time: {performance_results['sequential_time']:.3f}s")
        print(f"   Parallel time: {performance_results['parallel_time']:.3f}s")
        print(f"   Improvement: {performance_results['improvement']:.1f}%")
    
    # Recommendations
    print(f"\n💡 Recommendations:")
    if total_vulnerabilities > 0:
        print("   🚨 Immediate action required - vulnerabilities detected!")
        print("   🔒 Implement proper input validation")
        print("   🛡️ Add authentication and authorization")
        print("   🔐 Use parameterized queries")
    else:
        print("   ✅ No obvious vulnerabilities detected")
        print("   🔍 Consider deeper security testing")
    
    print("   📋 Regular security audits recommended")
    print("   🛠️ Implement security headers")
    
    # Save report
    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_endpoints': total_endpoints,
            'accessible_endpoints': accessible_endpoints,
            'total_vulnerabilities': total_vulnerabilities
        },
        'connectivity_results': connectivity_results,
        'vulnerabilities': vulnerabilities,
        'performance_results': performance_results
    }
    
    with open('security_scan_report.json', 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n📄 Report saved to: security_scan_report.json")

def main():
    """Main function to run the security scan"""
    print("🚀 Simple API Security Scanner Demo")
    print("=" * 50)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    try:
        # Run all tests
        connectivity_results = test_basic_connectivity()
        vulnerabilities = test_security_vulnerabilities()
        performance_results = test_performance()
        
        # Generate report
        generate_report(connectivity_results, vulnerabilities, performance_results)
        
        print(f"\n✅ Security scan completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error during security scan: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 