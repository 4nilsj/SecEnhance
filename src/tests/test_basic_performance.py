#!/usr/bin/env python3
"""
Basic Performance Test for API Security Scanner
Tests core functionality without complex imports
"""

import time
import json
import requests
from datetime import datetime

def test_basic_scanner():
    """Test basic scanner functionality"""
    print("🚀 Testing Basic API Security Scanner")
    print("=" * 50)
    
    # Test endpoints
    test_endpoints = [
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
    
    try:
        # Test basic connectivity
        print("\n🔍 Test 1: Basic Connectivity")
        session = requests.Session()
        
        for endpoint in test_endpoints:
            url = f"{endpoint['base_url']}{endpoint['path']}"
            print(f"   Testing: {endpoint['method']} {url}")
            
            try:
                start_time = time.time()
                response = session.request(
                    method=endpoint['method'],
                    url=url,
                    timeout=10
                )
                response_time = time.time() - start_time
                
                print(f"   ✅ Status: {response.status_code}")
                print(f"   ⏱️  Response time: {response_time:.3f}s")
                print(f"   📏 Content length: {len(response.content)} bytes")
                
            except Exception as e:
                print(f"   ❌ Error: {e}")
        
        # Test parallel requests
        print("\n🚀 Test 2: Parallel Requests")
        import concurrent.futures
        
        def make_request(endpoint):
            url = f"{endpoint['base_url']}{endpoint['path']}"
            try:
                start_time = time.time()
                response = session.request(
                    method=endpoint['method'],
                    url=url,
                    timeout=10
                )
                response_time = time.time() - start_time
                return {
                    'url': url,
                    'status': response.status_code,
                    'time': response_time,
                    'success': True
                }
            except Exception as e:
                return {
                    'url': url,
                    'error': str(e),
                    'success': False
                }
        
        # Sequential requests
        print("   Sequential requests:")
        start_time = time.time()
        sequential_results = []
        for endpoint in test_endpoints:
            result = make_request(endpoint)
            sequential_results.append(result)
        sequential_time = time.time() - start_time
        print(f"   ⏱️  Total time: {sequential_time:.3f}s")
        
        # Parallel requests
        print("   Parallel requests:")
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            parallel_results = list(executor.map(make_request, test_endpoints))
        parallel_time = time.time() - start_time
        print(f"   ⏱️  Total time: {parallel_time:.3f}s")
        
        # Calculate improvement
        if sequential_time > 0:
            improvement = ((sequential_time - parallel_time) / sequential_time) * 100
            print(f"   📈 Parallel improvement: {improvement:.1f}%")
        
        # Test caching simulation
        print("\n💾 Test 3: Caching Simulation")
        cache = {}
        
        def cached_request(endpoint):
            url = f"{endpoint['base_url']}{endpoint['path']}"
            cache_key = f"{endpoint['method']}:{url}"
            
            if cache_key in cache:
                print(f"   💾 Cache HIT: {url}")
                return cache[cache_key]
            
            print(f"   ❌ Cache MISS: {url}")
            try:
                start_time = time.time()
                response = session.request(
                    method=endpoint['method'],
                    url=url,
                    timeout=10
                )
                response_time = time.time() - start_time
                
                result = {
                    'status': response.status_code,
                    'time': response_time,
                    'content_length': len(response.content)
                }
                
                cache[cache_key] = result
                return result
                
            except Exception as e:
                return {'error': str(e)}
        
        # First requests (cache miss)
        print("   First requests (cache miss):")
        start_time = time.time()
        for endpoint in test_endpoints:
            cached_request(endpoint)
        first_time = time.time() - start_time
        
        # Second requests (cache hit)
        print("   Second requests (cache hit):")
        start_time = time.time()
        for endpoint in test_endpoints:
            cached_request(endpoint)
        second_time = time.time() - start_time
        
        if first_time > 0:
            cache_improvement = ((first_time - second_time) / first_time) * 100
            print(f"   📈 Cache improvement: {cache_improvement:.1f}%")
        
        # Performance summary
        print("\n📊 Performance Summary:")
        print("-" * 30)
        print(f"Sequential time: {sequential_time:.3f}s")
        print(f"Parallel time: {parallel_time:.3f}s")
        print(f"Parallel improvement: {improvement:.1f}%" if sequential_time > 0 else "N/A")
        print(f"Cache improvement: {cache_improvement:.1f}%" if first_time > 0 else "N/A")
        
        # Save results
        results = {
            'timestamp': datetime.now().isoformat(),
            'sequential_time': sequential_time,
            'parallel_time': parallel_time,
            'parallel_improvement': improvement if sequential_time > 0 else 0,
            'cache_improvement': cache_improvement if first_time > 0 else 0,
            'endpoints_tested': len(test_endpoints),
            'sequential_results': sequential_results,
            'parallel_results': parallel_results
        }
        
        with open('basic_performance_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print("\n✅ Basic performance test completed!")
        print("📄 Results saved to: basic_performance_results.json")
        
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_basic_scanner() 