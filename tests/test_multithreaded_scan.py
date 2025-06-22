import sys
import time
sys.path.insert(0, 'src')

from core.api_security_scanner import APISecurityScanner

def test_multithreaded_scan():
    """Test multi-threaded scanning performance"""
    print("🚀 Testing Multi-Threaded API Security Scanner")
    print("=" * 50)
    
    # Test with different thread configurations
    thread_configs = [1, 5, 10]
    
    for max_workers in thread_configs:
        print(f"\n🔧 Testing with {max_workers} threads...")
        
        # Initialize scanner with specific thread count
        scanner = APISecurityScanner(max_workers=max_workers)
        
        # Test endpoints (using httpbin.org for safe testing)
        test_endpoints = [
            {'url': 'https://httpbin.org/get', 'method': 'GET'},
            {'url': 'https://httpbin.org/post', 'method': 'POST'},
            {'url': 'https://httpbin.org/put', 'method': 'PUT'},
            {'url': 'https://httpbin.org/delete', 'method': 'DELETE'},
            {'url': 'https://httpbin.org/status/200', 'method': 'GET'},
            {'url': 'https://httpbin.org/status/404', 'method': 'GET'},
            {'url': 'https://httpbin.org/delay/1', 'method': 'GET'},
            {'url': 'https://httpbin.org/delay/2', 'method': 'GET'}
        ]
        
        print(f"📡 Scanning {len(test_endpoints)} endpoints...")
        
        # Time the scan
        start_time = time.time()
        results = scanner.scan_api_endpoints(test_endpoints)
        end_time = time.time()
        
        scan_duration = end_time - start_time
        
        print(f"✅ Scan completed in {scan_duration:.2f} seconds")
        print(f"📊 Results:")
        print(f"   - Endpoints Scanned: {results.get('endpoints_scanned', 0)}")
        print(f"   - Vulnerabilities Found: {len(results.get('vulnerabilities_found', []))}")
        print(f"   - Warnings Found: {len(results.get('warnings_found', []))}")
        print(f"   - Performance Issues: {len(results.get('performance_issues_found', []))}")
        print(f"   - Configuration Issues: {len(results.get('configuration_issues_found', []))}")
        print(f"   - Total Issues: {results.get('issue_summary', {}).get('total_issues', 0)}")
        
        # Calculate throughput
        throughput = len(test_endpoints) / scan_duration
        print(f"   - Throughput: {throughput:.2f} endpoints/second")

if __name__ == "__main__":
    test_multithreaded_scan() 