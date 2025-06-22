#!/usr/bin/env python3
"""
Comprehensive API Security Scanner Demo
Demonstrates all performance optimization features
"""

import time
import json
import sys
import os
from datetime import datetime

# Add current directory to path to import clean modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the clean version
try:
    from api_security_scanner_clean import APISecurityScanner
except ImportError:
    print("❌ Could not import clean API security scanner")
    sys.exit(1)

def run_comprehensive_scan():
    """Run comprehensive security scan with performance optimizations"""
    print("🚀 Comprehensive API Security Scanner Demo")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Create test endpoints for comprehensive scanning
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
            'path': '/api/files/upload',
            'method': 'POST',
            'base_url': 'http://localhost:5001',
            'description': 'File upload endpoint'
        },
        {
            'path': '/api/search',
            'method': 'GET',
            'base_url': 'http://localhost:5001',
            'description': 'Search endpoint'
        },
        {
            'path': '/api/data/records',
            'method': 'GET',
            'base_url': 'http://localhost:5001',
            'description': 'Data records endpoint'
        }
    ]
    
    try:
        # Test 1: Standard Scan (No Optimization)
        print("🔍 Test 1: Standard Security Scan (No Optimization)")
        print("-" * 50)
        
        scanner_standard = APISecurityScanner(enable_optimization=False)
        
        start_time = time.time()
        standard_results = scanner_standard.scan_api_endpoints(test_endpoints)
        standard_duration = time.time() - start_time
        
        print(f"✅ Standard scan completed in {standard_duration:.2f} seconds")
        print(f"📍 Endpoints scanned: {standard_results.get('scanned_endpoints', 0)}")
        print(f"🚨 Vulnerabilities found: {len(standard_results.get('vulnerabilities', []))}")
        
        # Show vulnerability summary
        summary = standard_results.get('summary', {})
        if summary:
            print("📊 Vulnerability Summary:")
            for severity, count in summary.items():
                if count > 0:
                    print(f"   {severity.upper()}: {count}")
        
        print()
        
        # Test 2: Optimized Scan
        print("🚀 Test 2: Optimized Security Scan")
        print("-" * 50)
        
        scanner_optimized = APISecurityScanner(enable_optimization=True, max_workers=8)
        
        start_time = time.time()
        optimized_results = scanner_optimized.scan_api_endpoints_optimized(test_endpoints)
        optimized_duration = time.time() - start_time
        
        print(f"✅ Optimized scan completed in {optimized_duration:.2f} seconds")
        print(f"📍 Endpoints scanned: {optimized_results.get('scanned_endpoints', 0)}")
        print(f"🚨 Vulnerabilities found: {len(optimized_results.get('vulnerabilities', []))}")
        
        # Show performance metrics
        if 'performance_metrics' in optimized_results:
            metrics = optimized_results['performance_metrics']
            print("📊 Performance Metrics:")
            print(f"   ⚡ Requests/sec: {metrics.get('requests_per_second', 0):.2f}")
            print(f"   ✅ Success Rate: {metrics.get('success_rate', 0):.1f}%")
            print(f"   ⏳ Avg Response Time: {metrics.get('avg_response_time', 0):.3f}s")
            print(f"   📈 P95 Response Time: {metrics.get('p95_response_time', 0):.3f}s")
        
        # Show optimization stats
        if 'optimization_stats' in optimized_results:
            stats = optimized_results['optimization_stats']
            print("🔧 Optimization Stats:")
            print(f"   💾 Cache Hit Rate: {stats.get('cache_hit_rate', 0):.1f}%")
            print(f"   🎯 Test Effectiveness: {len(stats.get('test_effectiveness', {}))} categories")
        
        # Show vulnerability summary
        summary = optimized_results.get('summary', {})
        if summary:
            print("📊 Vulnerability Summary:")
            for severity, count in summary.items():
                if count > 0:
                    print(f"   {severity.upper()}: {count}")
        
        print()
        
        # Test 3: Performance Comparison
        print("📈 Test 3: Performance Comparison")
        print("-" * 50)
        
        if standard_duration > 0:
            improvement = ((standard_duration - optimized_duration) / standard_duration) * 100
            
            print(f"📊 Scan Performance Comparison:")
            print(f"   Standard scan: {standard_duration:.2f}s")
            print(f"   Optimized scan: {optimized_duration:.2f}s")
            print(f"   📈 Performance improvement: {improvement:.1f}%")
            
            if improvement > 0:
                print(f"   🎉 Optimized scan is {improvement:.1f}% faster!")
            else:
                print(f"   ⚠️ No improvement detected")
        
        # Test 4: Configuration Optimization
        print("\n⚙️ Test 4: Configuration Optimization")
        print("-" * 50)
        
        opt_config = scanner_optimized.optimize_configuration(test_endpoints)
        
        if 'optimal_configuration' in opt_config:
            config = opt_config['optimal_configuration']
            print("🎯 Optimal Configuration:")
            print(f"   Workers: {config.get('max_workers', 'N/A')}")
            print(f"   Connections: {config.get('max_connections', 'N/A')}")
            print(f"   Cache Size: {config.get('cache_size', 'N/A')}")
            print(f"   Requests/sec: {config.get('max_requests_per_second', 'N/A')}")
            print(f"   Timeout: {config.get('timeout', 'N/A')}s")
        
        if 'recommendations' in opt_config:
            print(f"💡 Optimization Recommendations: {len(opt_config['recommendations'])}")
            for i, rec in enumerate(opt_config['recommendations'], 1):
                print(f"   {i}. {rec}")
        
        # Test 5: Performance Report
        print("\n📊 Test 5: Comprehensive Performance Report")
        print("-" * 50)
        
        report = scanner_optimized.get_performance_report()
        
        if 'error' not in report:
            print("✅ Performance report generated successfully")
            
            if 'metrics' in report:
                metrics = report['metrics']
                print("📈 Performance Metrics:")
                print(f"   Total requests: {metrics.get('total_requests', 0)}")
                print(f"   Successful requests: {metrics.get('successful_requests', 0)}")
                print(f"   Failed requests: {metrics.get('failed_requests', 0)}")
                print(f"   Success rate: {metrics.get('success_rate', 0):.1f}%")
                print(f"   Duration: {metrics.get('duration_seconds', 0):.2f}s")
                print(f"   Requests/sec: {metrics.get('requests_per_second', 0):.2f}")
                print(f"   Avg response time: {metrics.get('avg_response_time', 0):.3f}s")
                print(f"   P95 response time: {metrics.get('p95_response_time', 0):.3f}s")
            
            if 'cache_performance' in report:
                cache = report['cache_performance']
                print("💾 Cache Performance:")
                print(f"   Hit rate: {cache.get('hit_rate', 0):.1f}%")
                print(f"   Total hits: {cache.get('total_hits', 0)}")
                print(f"   Total misses: {cache.get('total_misses', 0)}")
            
            if 'recommendations' in report:
                print(f"💡 Performance Recommendations: {len(report['recommendations'])}")
                for i, rec in enumerate(report['recommendations'], 1):
                    print(f"   {i}. {rec}")
        else:
            print(f"❌ Error: {report['error']}")
        
        print()
        
        # Test 6: Vulnerability Analysis
        print("🚨 Test 6: Vulnerability Analysis")
        print("-" * 50)
        
        vulnerabilities = optimized_results.get('vulnerabilities', [])
        
        if vulnerabilities:
            print(f"🚨 Found {len(vulnerabilities)} vulnerabilities:")
            
            # Group by severity
            by_severity = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'info').lower()
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(vuln)
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in by_severity:
                    vulns = by_severity[severity]
                    print(f"\n   {severity.upper()} ({len(vulns)}):")
                    for i, vuln in enumerate(vulns[:3], 1):  # Show first 3 of each severity
                        print(f"     {i}. {vuln.get('description', 'No description')}")
                        if 'test_category' in vuln:
                            print(f"        Category: {vuln['test_category']}")
                    if len(vulns) > 3:
                        print(f"     ... and {len(vulns) - 3} more")
        else:
            print("✅ No vulnerabilities detected")
        
        print()
        
        # Test 7: Test Results Analysis
        print("🧪 Test 7: Test Results Analysis")
        print("-" * 50)
        
        test_results = optimized_results.get('test_results', {})
        
        if test_results:
            print(f"📋 Test Categories Executed: {len(test_results)}")
            
            for category, result in test_results.items():
                if isinstance(result, dict):
                    tests_run = result.get('tests_run', 0)
                    tests_skipped = result.get('tests_skipped', 0)
                    vulns_found = len(result.get('vulnerabilities', []))
                    
                    print(f"   {category}:")
                    print(f"     Tests run: {tests_run}")
                    print(f"     Tests skipped: {tests_skipped}")
                    print(f"     Vulnerabilities: {vulns_found}")
        else:
            print("📋 No test results available")
        
        print()
        
        # Final Summary
        print("🎉 Final Summary")
        print("-" * 50)
        
        print("✅ All tests completed successfully!")
        print(f"📊 Performance improvement: {improvement:.1f}%" if standard_duration > 0 else "N/A")
        print(f"🚨 Total vulnerabilities found: {len(vulnerabilities)}")
        print(f"📋 Test categories executed: {len(test_results)}")
        
        # Save comprehensive results
        comprehensive_results = {
            'timestamp': datetime.now().isoformat(),
            'test_summary': {
                'standard_duration': standard_duration,
                'optimized_duration': optimized_duration,
                'performance_improvement': improvement if standard_duration > 0 else 0,
                'vulnerabilities_found': len(vulnerabilities),
                'test_categories': len(test_results)
            },
            'standard_results': standard_results,
            'optimized_results': optimized_results,
            'optimization_config': opt_config.get('optimal_configuration', {}),
            'performance_report': report if 'error' not in report else None
        }
        
        with open('comprehensive_scan_results.json', 'w') as f:
            json.dump(comprehensive_results, f, indent=2, default=str)
        
        print("📄 Comprehensive results saved to: comprehensive_scan_results.json")
        
    except Exception as e:
        print(f"\n❌ Error during comprehensive scan: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_comprehensive_scan() 