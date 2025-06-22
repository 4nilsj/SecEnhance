#!/usr/bin/env python3
"""
Simple Performance Test for API Security Scanner
Tests the basic performance improvements
"""

import time
import json
from datetime import datetime
from src.core.api_security_scanner import APISecurityScanner

def test_basic_performance():
    """Test basic performance improvements"""
    print("🚀 Testing API Security Scanner Performance Improvements")
    print("=" * 60)
    
    # Create test endpoints
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
        },
        {
            'path': '/api/auth/login',
            'method': 'POST',
            'base_url': 'http://localhost:5001',
            'description': 'Authentication endpoint'
        }
    ]
    
    try:
        # Test 1: Standard scan (no optimization)
        print("\n🔍 Test 1: Standard Scan (No Optimization)")
        scanner_standard = APISecurityScanner(enable_optimization=False)
        
        start_time = time.time()
        standard_results = scanner_standard.scan_api_endpoints(test_endpoints)
        standard_duration = time.time() - start_time
        
        print(f"   ⏱️  Duration: {standard_duration:.2f} seconds")
        print(f"   📍 Endpoints scanned: {standard_results.get('scanned_endpoints', 0)}")
        print(f"   🚨 Vulnerabilities found: {len(standard_results.get('vulnerabilities', []))}")
        
        # Test 2: Optimized scan
        print("\n🚀 Test 2: Optimized Scan")
        scanner_optimized = APISecurityScanner(enable_optimization=True, max_workers=5)
        
        start_time = time.time()
        optimized_results = scanner_optimized.scan_api_endpoints_optimized(test_endpoints)
        optimized_duration = time.time() - start_time
        
        print(f"   ⏱️  Duration: {optimized_duration:.2f} seconds")
        print(f"   📍 Endpoints scanned: {optimized_results.get('scanned_endpoints', 0)}")
        print(f"   🚨 Vulnerabilities found: {len(optimized_results.get('vulnerabilities', []))}")
        
        if 'performance_metrics' in optimized_results:
            metrics = optimized_results['performance_metrics']
            print(f"   ⚡ Requests/sec: {metrics.get('requests_per_second', 0):.2f}")
            print(f"   ✅ Success Rate: {metrics.get('success_rate', 0):.1f}%")
            print(f"   ⏳ Avg Response Time: {metrics.get('avg_response_time', 0):.3f}s")
        
        if 'optimization_stats' in optimized_results:
            stats = optimized_results['optimization_stats']
            print(f"   💾 Cache Hit Rate: {stats.get('cache_hit_rate', 0):.1f}%")
        
        # Calculate improvement
        if standard_duration > 0:
            improvement = ((standard_duration - optimized_duration) / standard_duration) * 100
            print(f"\n📈 Performance Improvement: {improvement:.1f}%")
        
        # Test 3: Performance report
        print("\n📊 Test 3: Performance Report")
        if scanner_optimized.performance_optimizer:
            report = scanner_optimized.get_performance_report()
            print(f"   📋 Report generated: {len(report)} sections")
            if 'recommendations' in report:
                print(f"   💡 Recommendations: {len(report['recommendations'])}")
        
        # Test 4: Configuration optimization
        print("\n⚙️ Test 4: Configuration Optimization")
        opt_config = scanner_optimized.optimize_configuration(test_endpoints)
        print(f"   🎯 Optimal workers: {opt_config.get('optimal_configuration', {}).get('max_workers', 'N/A')}")
        print(f"   📊 Recommendations: {len(opt_config.get('recommendations', []))}")
        
        print("\n✅ All performance tests completed successfully!")
        
        # Save results
        results = {
            'timestamp': datetime.now().isoformat(),
            'standard_scan': {
                'duration': standard_duration,
                'endpoints': standard_results.get('scanned_endpoints', 0),
                'vulnerabilities': len(standard_results.get('vulnerabilities', []))
            },
            'optimized_scan': {
                'duration': optimized_duration,
                'endpoints': optimized_results.get('scanned_endpoints', 0),
                'vulnerabilities': len(optimized_results.get('vulnerabilities', [])),
                'performance_metrics': optimized_results.get('performance_metrics', {}),
                'optimization_stats': optimized_results.get('optimization_stats', {})
            },
            'improvement_percentage': improvement if standard_duration > 0 else 0,
            'optimization_config': opt_config.get('optimal_configuration', {})
        }
        
        with open('performance_test_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print("📄 Results saved to: performance_test_results.json")
        
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_basic_performance() 