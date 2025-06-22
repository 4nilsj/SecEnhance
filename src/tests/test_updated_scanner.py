#!/usr/bin/env python3
"""
Test Updated API Security Scanner
Comprehensive testing of all features and performance optimizations
"""

import time
import json
from datetime import datetime
from src.core.api_security_scanner import APISecurityScanner

def test_basic_functionality():
    """Test basic scanner functionality"""
    print("🔍 Test 1: Basic Functionality")
    print("-" * 40)
    
    # Create scanner with optimization enabled
    scanner = APISecurityScanner(enable_optimization=True, max_workers=8)
    
    # Test endpoints
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
        },
        {
            'path': '/api/search',
            'method': 'GET',
            'base_url': 'http://localhost:5001',
            'description': 'Search endpoint'
        }
    ]
    
    print(f"📍 Testing {len(endpoints)} endpoints...")
    
    # Run optimized scan
    start_time = time.time()
    results = scanner.scan_api_endpoints_optimized(endpoints)
    scan_duration = time.time() - start_time
    
    print(f"✅ Scan completed in {scan_duration:.3f}s")
    print(f"🚨 Vulnerabilities found: {len(results['vulnerabilities'])}")
    print(f"📊 Performance: {results['performance_metrics'].get('requests_per_second', 0):.2f} req/s")
    
    return results

def test_performance_comparison():
    """Compare performance with and without optimization"""
    print("\n🔍 Test 2: Performance Comparison")
    print("-" * 40)
    
    endpoints = [
        {
            'path': '/api/users',
            'method': 'GET',
            'base_url': 'http://localhost:5001'
        },
        {
            'path': '/api/users/1',
            'method': 'GET',
            'base_url': 'http://localhost:5001'
        },
        {
            'path': '/api/search',
            'method': 'GET',
            'base_url': 'http://localhost:5001'
        }
    ]
    
    # Test without optimization
    print("📊 Testing without optimization...")
    scanner_basic = APISecurityScanner(enable_optimization=False)
    start_time = time.time()
    basic_results = scanner_basic.scan_api_endpoints(endpoints)
    basic_duration = time.time() - start_time
    
    # Test with optimization
    print("📊 Testing with optimization...")
    scanner_optimized = APISecurityScanner(enable_optimization=True, max_workers=8)
    start_time = time.time()
    optimized_results = scanner_optimized.scan_api_endpoints_optimized(endpoints)
    optimized_duration = time.time() - start_time
    
    # Calculate improvement
    if basic_duration > 0:
        improvement = ((basic_duration - optimized_duration) / basic_duration) * 100
        print(f"📈 Performance improvement: {improvement:.1f}%")
        print(f"   Basic scan: {basic_duration:.3f}s")
        print(f"   Optimized scan: {optimized_duration:.3f}s")
    
    return {
        'basic_duration': basic_duration,
        'optimized_duration': optimized_duration,
        'improvement': improvement if basic_duration > 0 else 0
    }

def test_security_vulnerabilities():
    """Test specific security vulnerability detection"""
    print("\n🔍 Test 3: Security Vulnerability Detection")
    print("-" * 40)
    
    scanner = APISecurityScanner(enable_optimization=True, max_workers=4)
    
    # Test endpoints that should trigger vulnerabilities
    test_endpoints = [
        {
            'path': '/api/users',
            'method': 'GET',
            'base_url': 'http://localhost:5001'
        },
        {
            'path': '/api/users',
            'method': 'POST',
            'base_url': 'http://localhost:5001'
        }
    ]
    
    print("🔍 Running security tests...")
    results = scanner.scan_api_endpoints_optimized(test_endpoints)
    
    # Analyze vulnerabilities
    vulnerabilities = results['vulnerabilities']
    summary = results['summary']
    
    print(f"🚨 Total vulnerabilities: {len(vulnerabilities)}")
    print("📊 Vulnerability breakdown:")
    for severity, count in summary.items():
        if count > 0:
            print(f"   {severity.upper()}: {count}")
    
    # Show specific vulnerabilities
    if vulnerabilities:
        print("\n🔍 Specific vulnerabilities found:")
        for i, vuln in enumerate(vulnerabilities[:5], 1):  # Show first 5
            print(f"   {i}. {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
            print(f"      {vuln.get('description', 'No description')}")
    
    return results

def test_performance_features():
    """Test specific performance optimization features"""
    print("\n🔍 Test 4: Performance Features")
    print("-" * 40)
    
    scanner = APISecurityScanner(enable_optimization=True, max_workers=8)
    
    # Test performance report
    print("📊 Getting performance report...")
    perf_report = scanner.get_performance_report()
    
    if 'error' not in perf_report:
        metrics = perf_report.get('metrics', {})
        print(f"📈 Performance Metrics:")
        print(f"   Total requests: {metrics.get('total_requests', 0)}")
        print(f"   Avg response time: {metrics.get('avg_response_time', 0):.3f}s")
        print(f"   Requests per second: {metrics.get('requests_per_second', 0):.2f}")
        print(f"   Cache hit rate: {metrics.get('cache_hit_rate', 0):.1%}")
        
        cache_perf = perf_report.get('cache_performance', {})
        print(f"💾 Cache Performance:")
        print(f"   Hit rate: {cache_perf.get('hit_rate', 0):.1%}")
        print(f"   Total hits: {cache_perf.get('total_hits', 0)}")
        print(f"   Total misses: {cache_perf.get('total_misses', 0)}")
        
        recommendations = perf_report.get('recommendations', [])
        print(f"💡 Recommendations: {len(recommendations)}")
        for i, rec in enumerate(recommendations[:3], 1):
            print(f"   {i}. {rec}")
    else:
        print(f"❌ Error: {perf_report['error']}")
    
    return perf_report

def test_configuration_optimization():
    """Test configuration optimization"""
    print("\n🔍 Test 5: Configuration Optimization")
    print("-" * 40)
    
    scanner = APISecurityScanner(enable_optimization=True, max_workers=8)
    
    # Test endpoints for optimization
    test_endpoints = [
        {
            'path': '/api/users',
            'method': 'GET',
            'base_url': 'http://localhost:5001'
        },
        {
            'path': '/api/users/1',
            'method': 'GET',
            'base_url': 'http://localhost:5001'
        },
        {
            'path': '/api/search',
            'method': 'GET',
            'base_url': 'http://localhost:5001'
        }
    ]
    
    print("⚙️ Optimizing configuration...")
    opt_config = scanner.optimize_configuration(test_endpoints)
    
    if 'error' not in opt_config:
        config = opt_config.get('optimal_configuration', {})
        print(f"🎯 Optimal Configuration:")
        print(f"   Workers: {config.get('max_workers', 'N/A')}")
        print(f"   Connections: {config.get('max_connections', 'N/A')}")
        print(f"   Cache Size: {config.get('cache_size', 'N/A')}")
        print(f"   Requests/sec: {config.get('max_requests_per_second', 'N/A')}")
        print(f"   Timeout: {config.get('timeout', 'N/A')}s")
        
        assessment = opt_config.get('assessment', {})
        print(f"📊 Assessment:")
        print(f"   Total endpoints: {assessment.get('total_endpoints', 0)}")
        print(f"   Avg response time: {assessment.get('avg_response_time', 0):.3f}s")
        print(f"   Recommended workers: {assessment.get('recommended_workers', 0)}")
        
        recommendations = opt_config.get('recommendations', [])
        print(f"💡 Optimization Recommendations: {len(recommendations)}")
        for i, rec in enumerate(recommendations, 1):
            print(f"   {i}. {rec}")
    else:
        print(f"❌ Error: {opt_config['error']}")
    
    return opt_config

def test_comprehensive_scan():
    """Run a comprehensive scan with all features"""
    print("\n🔍 Test 6: Comprehensive Scan")
    print("-" * 40)
    
    scanner = APISecurityScanner(enable_optimization=True, max_workers=8)
    
    # Comprehensive endpoint list
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
        },
        {
            'path': '/api/users',
            'method': 'POST',
            'base_url': 'http://localhost:5001',
            'description': 'User creation endpoint'
        },
        {
            'path': '/api/auth/login',
            'method': 'POST',
            'base_url': 'http://localhost:5001',
            'description': 'Authentication endpoint'
        },
        {
            'path': '/api/admin/users',
            'method': 'GET',
            'base_url': 'http://localhost:5001',
            'description': 'Admin endpoint'
        },
        {
            'path': '/api/search',
            'method': 'GET',
            'base_url': 'http://localhost:5001',
            'description': 'Search endpoint'
        }
    ]
    
    print(f"🚀 Starting comprehensive scan of {len(endpoints)} endpoints...")
    start_time = time.time()
    
    results = scanner.scan_api_endpoints_optimized(endpoints)
    
    scan_duration = time.time() - start_time
    
    print(f"✅ Comprehensive scan completed in {scan_duration:.3f}s")
    print(f"🚨 Vulnerabilities found: {len(results['vulnerabilities'])}")
    print(f"📊 Performance: {results['performance_metrics'].get('requests_per_second', 0):.2f} req/s")
    
    # Show detailed results
    summary = results['summary']
    print(f"\n📊 Vulnerability Summary:")
    for severity, count in summary.items():
        if count > 0:
            print(f"   {severity.upper()}: {count}")
    
    # Show performance metrics
    perf_metrics = results['performance_metrics']
    print(f"\n⚡ Performance Metrics:")
    print(f"   Total requests: {perf_metrics.get('total_requests', 0)}")
    print(f"   Avg response time: {perf_metrics.get('avg_response_time', 0):.3f}s")
    print(f"   Requests per second: {perf_metrics.get('requests_per_second', 0):.2f}")
    print(f"   Cache hit rate: {perf_metrics.get('cache_hit_rate', 0):.1%}")
    
    return results

def generate_final_report(all_results):
    """Generate comprehensive final report"""
    print("\n📊 Final Test Report")
    print("=" * 50)
    
    # Summary statistics
    total_vulnerabilities = sum(len(result.get('vulnerabilities', [])) for result in all_results if isinstance(result, dict))
    total_tests = len(all_results)
    
    print(f"📋 Test Summary:")
    print(f"   Total tests run: {total_tests}")
    print(f"   Total vulnerabilities found: {total_vulnerabilities}")
    
    # Performance summary
    performance_results = [r for r in all_results if isinstance(r, dict) and 'performance_metrics' in r]
    if performance_results:
        avg_rps = sum(r['performance_metrics'].get('requests_per_second', 0) for r in performance_results) / len(performance_results)
        print(f"   Average requests per second: {avg_rps:.2f}")
    
    # Save comprehensive results
    final_report = {
        'timestamp': datetime.now().isoformat(),
        'test_summary': {
            'total_tests': total_tests,
            'total_vulnerabilities': total_vulnerabilities,
            'scanner_version': '2.0'
        },
        'test_results': all_results
    }
    
    filename = f"comprehensive_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(final_report, f, indent=2, default=str)
    
    print(f"📄 Comprehensive report saved to: {filename}")
    
    return final_report

def main():
    """Main test function"""
    print("🚀 Updated API Security Scanner - Comprehensive Testing")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    all_results = []
    
    try:
        # Run all tests
        print("🧪 Running comprehensive test suite...")
        
        # Test 1: Basic functionality
        result1 = test_basic_functionality()
        all_results.append(result1)
        
        # Test 2: Performance comparison
        result2 = test_performance_comparison()
        all_results.append(result2)
        
        # Test 3: Security vulnerability detection
        result3 = test_security_vulnerabilities()
        all_results.append(result3)
        
        # Test 4: Performance features
        result4 = test_performance_features()
        all_results.append(result4)
        
        # Test 5: Configuration optimization
        result5 = test_configuration_optimization()
        all_results.append(result5)
        
        # Test 6: Comprehensive scan
        result6 = test_comprehensive_scan()
        all_results.append(result6)
        
        # Generate final report
        final_report = generate_final_report(all_results)
        
        print(f"\n✅ All tests completed successfully!")
        print(f"📊 Total vulnerabilities found: {final_report['test_summary']['total_vulnerabilities']}")
        print(f"📄 Final report saved to: {final_report.get('filename', 'N/A')}")
        
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 