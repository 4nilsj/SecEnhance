#!/usr/bin/env python3
"""
Final Performance Demo
Showcases key optimization features
"""

import time
import json
import requests
import concurrent.futures
from datetime import datetime

def final_performance_demo():
    """Final demonstration of performance features"""
    print("🚀 Final Performance Features Demo")
    print("=" * 50)
    print(f"Target: http://localhost:5001")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    base_url = "http://localhost:5001"
    session = requests.Session()
    cache = {}
    vulnerabilities = []
    
    endpoints = [
        '/api/users',
        '/api/users/1',
        '/api/search',
        '/api/auth/login',
        '/api/admin/users'
    ]
    
    # Test 1: Sequential Scanning
    print("🔍 Test 1: Sequential Scanning")
    print("-" * 30)
    start_time = time.time()
    
    for endpoint in endpoints:
        try:
            url = f"{base_url}{endpoint}"
            response = session.get(url, timeout=5)
            print(f"✅ {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"❌ {endpoint}: Error")
    
    sequential_time = time.time() - start_time
    print(f"⏱️ Sequential time: {sequential_time:.3f}s")
    
    # Test 2: Parallel Scanning
    print("\n🔍 Test 2: Parallel Scanning")
    print("-" * 30)
    start_time = time.time()
    
    def scan_endpoint(endpoint):
        try:
            url = f"{base_url}{endpoint}"
            response = session.get(url, timeout=5)
            return f"✅ {endpoint}: {response.status_code}"
        except:
            return f"❌ {endpoint}: Error"
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(scan_endpoint, endpoint) for endpoint in endpoints]
        for future in concurrent.futures.as_completed(futures):
            print(future.result())
    
    parallel_time = time.time() - start_time
    print(f"⏱️ Parallel time: {parallel_time:.3f}s")
    
    # Test 3: Cached Requests
    print("\n🔍 Test 3: Cached Requests")
    print("-" * 30)
    start_time = time.time()
    
    for endpoint in endpoints:
        url = f"{base_url}{endpoint}"
        if url in cache:
            print(f"💾 Cache HIT: {endpoint}")
        else:
            print(f"❌ Cache MISS: {endpoint}")
            try:
                response = session.get(url, timeout=5)
                cache[url] = response.status_code
            except:
                cache[url] = 'error'
    
    cached_time = time.time() - start_time
    print(f"⏱️ Cached time: {cached_time:.3f}s")
    
    # Test 4: Security Testing
    print("\n🔍 Test 4: Security Testing")
    print("-" * 30)
    
    # SQL Injection test
    sql_payloads = ["' OR 1=1--", "'; DROP TABLE users--"]
    for payload in sql_payloads:
        try:
            url = f"{base_url}/api/users?search={payload}"
            response = session.get(url, timeout=3)
            if response.status_code == 200:
                print(f"🚨 Potential SQL Injection: {payload}")
                vulnerabilities.append(f"SQL Injection: {payload}")
        except:
            pass
    
    # XSS test
    xss_payloads = ["<script>alert('XSS')</script>", "javascript:alert('XSS')"]
    for payload in xss_payloads:
        try:
            url = f"{base_url}/api/users?name={payload}"
            response = session.get(url, timeout=3)
            if payload in response.text:
                print(f"🚨 Potential XSS: {payload}")
                vulnerabilities.append(f"XSS: {payload}")
        except:
            pass
    
    # Auth bypass test
    auth_tests = [
        f"{base_url}/api/users?admin=true",
        f"{base_url}/api/users?debug=true"
    ]
    for url in auth_tests:
        try:
            response = session.get(url, timeout=3)
            if response.status_code == 200:
                print(f"🚨 Potential Auth Bypass: {url}")
                vulnerabilities.append(f"Auth Bypass: {url}")
        except:
            pass
    
    # Calculate improvements
    if sequential_time > 0:
        parallel_improvement = ((sequential_time - parallel_time) / sequential_time) * 100
        cache_improvement = ((sequential_time - cached_time) / sequential_time) * 100
        
        print(f"\n📈 Performance Improvements:")
        print(f"   Parallel: {parallel_improvement:.1f}%")
        print(f"   Caching: {cache_improvement:.1f}%")
        
        # Calculate requests per second
        total_requests = len(endpoints) * 3
        total_time = sequential_time + parallel_time + cached_time
        rps = total_requests / total_time if total_time > 0 else 0
        print(f"   Requests/sec: {rps:.2f}")
    
    # Final summary
    print(f"\n🎉 Final Summary")
    print("=" * 30)
    print(f"✅ Performance improvement: {parallel_improvement:.1f}%")
    print(f"🚨 Vulnerabilities found: {len(vulnerabilities)}")
    print(f"💾 Cache efficiency: {cache_improvement:.1f}%")
    
    # Save results
    results = {
        'timestamp': datetime.now().isoformat(),
        'performance': {
            'sequential_time': sequential_time,
            'parallel_time': parallel_time,
            'cached_time': cached_time,
            'parallel_improvement': parallel_improvement,
            'cache_improvement': cache_improvement,
            'requests_per_second': rps
        },
        'security': {
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        },
        'endpoints_tested': len(endpoints)
    }
    
    filename = f"final_demo_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"📄 Results saved to: {filename}")
    print(f"\n✅ Final demo completed successfully!")

if __name__ == "__main__":
    final_performance_demo() 