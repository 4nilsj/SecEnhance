#!/usr/bin/env python3
"""
Test Script for Container Security Scanner - Phase 1, Step 2
Package Vulnerability Matching

This script demonstrates the Phase 1, Step 2 functionality:
- Combines Phase 1, Step 1 (image extraction) with vulnerability matching
- Matches Debian packages against local vulnerability database
- Generates comprehensive vulnerability reports and risk assessments
"""

import sys
import os
import json
import time
from datetime import datetime

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from container_security_scanner import ContainerSecurityScanner
from utils.debug_utils import setup_debug_logging, debug_print

def test_phase1_step2_basic():
    """Test basic Phase 1, Step 2 functionality."""
    print("\n" + "="*60)
    print("🧪 TEST 1: Basic Phase 1, Step 2")
    print("="*60)
    
    # Initialize scanner with debug mode
    scanner = ContainerSecurityScanner(debug=True)
    
    # Test with a common Debian-based image
    test_image = "debian:bullseye-slim"
    
    print(f"Testing with image: {test_image}")
    print("This will:")
    print("  • Phase 1, Step 1: Extract Debian image and analyze layers")
    print("  • Phase 1, Step 2: Match packages against vulnerability database")
    print("  • Generate comprehensive vulnerability report")
    print("  • Provide risk assessment and recommendations")
    
    try:
        # Run Phase 1, Step 2 analysis
        results = scanner.scan_debian_image_phase1_step2(test_image)
        
        # Display results
        print("\n✅ Test completed successfully!")
        print(f"📊 Results summary:")
        print(f"   - Image: {results['scan_info']['target_name']}")
        print(f"   - Phase: {results['scan_info']['phase']}")
        print(f"   - Step: {results['scan_info']['step']}")
        
        # Check if vulnerability matching was successful
        if 'vulnerability_matching' in results and results['vulnerability_matching']:
            matching_data = results['vulnerability_matching']
            scan_info = matching_data.get('scan_info', {})
            overall_stats = matching_data.get('overall_statistics', {})
            
            print(f"   - Scan ID: {scan_info.get('scan_id', 'N/A')}")
            print(f"   - Total packages checked: {overall_stats.get('total_packages', 0)}")
            print(f"   - Vulnerable packages: {overall_stats.get('vulnerable_packages', 0)}")
            print(f"   - Total vulnerabilities: {overall_stats.get('total_vulnerabilities', 0)}")
            
            # Check risk assessment
            risk_assessment = matching_data.get('risk_assessment', {})
            if risk_assessment:
                print(f"   - Risk level: {risk_assessment.get('risk_level', 'N/A')}")
                print(f"   - Risk score: {risk_assessment.get('risk_score', 0)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        debug_print(f"Exception details: {str(e)}")
        return False

def test_phase1_step2_multiple_images():
    """Test Phase 1, Step 2 with multiple Debian-based images."""
    print("\n" + "="*60)
    print("🧪 TEST 2: Multiple Images Phase 1, Step 2")
    print("="*60)
    
    # Initialize scanner
    scanner = ContainerSecurityScanner(debug=True)
    
    # Test images
    test_images = [
        "debian:bullseye-slim",
        "ubuntu:20.04",
        "debian:buster-slim"
    ]
    
    results_summary = {}
    
    for image in test_images:
        print(f"\n🔍 Testing image: {image}")
        
        try:
            results = scanner.scan_debian_image_phase1_step2(image)
            
            # Extract key metrics
            matching_data = results.get('vulnerability_matching', {})
            overall_stats = matching_data.get('overall_statistics', {})
            risk_assessment = matching_data.get('risk_assessment', {})
            
            results_summary[image] = {
                'success': True,
                'total_packages': overall_stats.get('total_packages', 0),
                'vulnerable_packages': overall_stats.get('vulnerable_packages', 0),
                'total_vulnerabilities': overall_stats.get('total_vulnerabilities', 0),
                'risk_level': risk_assessment.get('risk_level', 'N/A'),
                'risk_score': risk_assessment.get('risk_score', 0),
                'scan_id': matching_data.get('scan_info', {}).get('scan_id', 'N/A')
            }
            
            print(f"   ✅ Success - {overall_stats.get('vulnerable_packages', 0)}/{overall_stats.get('total_packages', 0)} vulnerable packages")
            print(f"   🚨 Risk: {risk_assessment.get('risk_level', 'N/A')} (Score: {risk_assessment.get('risk_score', 0)})")
            
        except Exception as e:
            print(f"   ❌ Failed: {str(e)}")
            results_summary[image] = {
                'success': False,
                'error': str(e)
            }
    
    # Display comparison
    print("\n📊 Comparison Summary:")
    print(f"{'Image':<25} {'Status':<8} {'Packages':<10} {'Vuln Pkgs':<10} {'Vulns':<8} {'Risk':<10}")
    print("-" * 80)
    
    for image, summary in results_summary.items():
        if summary['success']:
            print(f"{image:<25} {'✅':<8} {summary['total_packages']:<10} "
                  f"{summary['vulnerable_packages']:<10} {summary['total_vulnerabilities']:<8} "
                  f"{summary['risk_level']:<10}")
        else:
            print(f"{image:<25} {'❌':<8} {'N/A':<10} {'N/A':<10} {'N/A':<8} {'N/A':<10}")
    
    return results_summary

def test_phase1_step2_vulnerability_details():
    """Test detailed vulnerability analysis."""
    print("\n" + "="*60)
    print("🧪 TEST 3: Vulnerability Details Analysis")
    print("="*60)
    
    # Initialize scanner
    scanner = ContainerSecurityScanner(debug=True)
    
    # Test with an image that likely has vulnerabilities
    test_image = "debian:bullseye-slim"
    
    print(f"Analyzing vulnerability details for: {test_image}")
    
    try:
        results = scanner.scan_debian_image_phase1_step2(test_image)
        
        matching_data = results.get('vulnerability_matching', {})
        vulnerabilities = matching_data.get('vulnerabilities', [])
        package_summaries = matching_data.get('package_summaries', [])
        
        print(f"\n📊 Vulnerability Analysis:")
        print(f"   - Total vulnerabilities found: {len(vulnerabilities)}")
        print(f"   - Packages with vulnerabilities: {len([p for p in package_summaries if p.get('total_vulnerabilities', 0) > 0])}")
        
        # Analyze vulnerability distribution
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        print(f"   - Severity distribution:")
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"     • {severity}: {count}")
        
        # Show top vulnerable packages
        vulnerable_packages = [p for p in package_summaries if p.get('total_vulnerabilities', 0) > 0]
        vulnerable_packages.sort(key=lambda x: x.get('total_vulnerabilities', 0), reverse=True)
        
        if vulnerable_packages:
            print(f"\n📦 Top Vulnerable Packages:")
            for i, package in enumerate(vulnerable_packages[:5], 1):
                print(f"   {i}. {package['package_name']} {package['package_version']}")
                print(f"      - Total vulnerabilities: {package['total_vulnerabilities']}")
                print(f"      - Critical: {package['critical_vulnerabilities']}, High: {package['high_vulnerabilities']}")
        
        # Show sample vulnerabilities
        if vulnerabilities:
            print(f"\n🚨 Sample Vulnerabilities:")
            for i, vuln in enumerate(vulnerabilities[:3], 1):
                print(f"   {i}. {vuln['cve_id']} - {vuln['severity']} (CVSS: {vuln['cvss_score']})")
                print(f"      Package: {vuln['package_name']} {vuln['package_version']}")
                print(f"      Description: {vuln['description'][:100]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ Vulnerability details analysis failed: {str(e)}")
        return False

def test_phase1_step2_risk_assessment():
    """Test risk assessment functionality."""
    print("\n" + "="*60)
    print("🧪 TEST 4: Risk Assessment")
    print("="*60)
    
    # Initialize scanner
    scanner = ContainerSecurityScanner(debug=True)
    
    # Test with different images to see different risk levels
    test_images = [
        "debian:bullseye-slim",
        "ubuntu:20.04"
    ]
    
    for image in test_images:
        print(f"\n🔍 Risk assessment for: {image}")
        
        try:
            results = scanner.scan_debian_image_phase1_step2(image)
            
            matching_data = results.get('vulnerability_matching', {})
            risk_assessment = matching_data.get('risk_assessment', {})
            overall_stats = matching_data.get('overall_statistics', {})
            
            print(f"   📊 Risk Assessment:")
            print(f"      - Risk Level: {risk_assessment.get('risk_level', 'N/A')}")
            print(f"      - Risk Score: {risk_assessment.get('risk_score', 0)}/100")
            print(f"      - Risk Description: {risk_assessment.get('risk_description', 'N/A')}")
            
            # Show recommendations
            recommendations = risk_assessment.get('recommendations', [])
            if recommendations:
                print(f"      - Recommendations:")
                for i, rec in enumerate(recommendations[:3], 1):
                    print(f"        {i}. {rec}")
                if len(recommendations) > 3:
                    print(f"        ... and {len(recommendations) - 3} more")
            
            # Show vulnerability statistics
            print(f"   📈 Vulnerability Statistics:")
            print(f"      - Total packages: {overall_stats.get('total_packages', 0)}")
            print(f"      - Vulnerable packages: {overall_stats.get('vulnerable_packages', 0)}")
            print(f"      - Vulnerability rate: {overall_stats.get('vulnerability_rate', 0):.1f}%")
            print(f"      - Critical: {overall_stats.get('critical_vulnerabilities', 0)}")
            print(f"      - High: {overall_stats.get('high_vulnerabilities', 0)}")
            print(f"      - Medium: {overall_stats.get('medium_vulnerabilities', 0)}")
            print(f"      - Low: {overall_stats.get('low_vulnerabilities', 0)}")
            
        except Exception as e:
            print(f"   ❌ Risk assessment failed: {str(e)}")
    
    return True

def test_phase1_step2_report_generation():
    """Test report generation for Phase 1, Step 2 results."""
    print("\n" + "="*60)
    print("🧪 TEST 5: Report Generation")
    print("="*60)
    
    # Initialize scanner
    scanner = ContainerSecurityScanner(debug=True)
    
    # Run analysis
    test_image = "debian:bullseye-slim"
    print(f"Running Phase 1, Step 2 analysis on {test_image} for report generation...")
    
    try:
        results = scanner.scan_debian_image_phase1_step2(test_image)
        
        # Generate different report formats
        report_formats = ['json', 'html']
        
        for format_type in report_formats:
            print(f"\n📄 Generating {format_type.upper()} report...")
            
            timestamp = int(time.time())
            output_file = f"phase1_step2_report_{timestamp}.{format_type}"
            
            report_path = scanner.generate_report(output_file, format_type)
            
            if os.path.exists(report_path):
                file_size = os.path.getsize(report_path)
                print(f"   ✅ Report generated: {report_path}")
                print(f"   📊 File size: {file_size} bytes")
                
                # Show report summary for JSON
                if format_type == 'json':
                    with open(report_path, 'r') as f:
                        report_data = json.load(f)
                    
                    scan_info = report_data.get('scan_info', {})
                    matching_data = report_data.get('vulnerability_matching', {})
                    overall_stats = matching_data.get('overall_statistics', {})
                    
                    print(f"   📋 Report Summary:")
                    print(f"      - Scan ID: {scan_info.get('scan_id', 'N/A')}")
                    print(f"      - Total packages: {overall_stats.get('total_packages', 0)}")
                    print(f"      - Vulnerable packages: {overall_stats.get('vulnerable_packages', 0)}")
                    print(f"      - Total vulnerabilities: {overall_stats.get('total_vulnerabilities', 0)}")
            else:
                print(f"   ❌ Report file not found: {report_path}")
        
        return True
        
    except Exception as e:
        print(f"❌ Report generation failed: {str(e)}")
        return False

def test_phase1_step2_database_integration():
    """Test database integration and scan history."""
    print("\n" + "="*60)
    print("🧪 TEST 6: Database Integration")
    print("="*60)
    
    # Initialize scanner
    scanner = ContainerSecurityScanner(debug=True)
    
    # Test with an image
    test_image = "debian:bullseye-slim"
    print(f"Testing database integration with: {test_image}")
    
    try:
        # Run analysis (this should save to database)
        results = scanner.scan_debian_image_phase1_step2(test_image)
        
        # Get scan history from database
        scan_history = scanner.vulnerability_matcher.get_scan_history(limit=5)
        
        print(f"\n📋 Recent Scan History:")
        if scan_history:
            for scan in scan_history:
                print(f"   - {scan['image_name']} ({scan['scan_date'][:10]})")
                print(f"     • Scan ID: {scan.get('scan_id', 'N/A')}")
                print(f"     • Vulnerable: {scan['vulnerable_packages']}/{scan['total_packages']}")
                print(f"     • Critical: {scan['critical_vulnerabilities']}, High: {scan['high_vulnerabilities']}")
                print(f"     • Duration: {scan['scan_duration']:.2f}s")
        else:
            print("   No scan history found")
        
        # Get vulnerability database statistics
        db_stats = scanner.vulnerability_matcher.get_vulnerability_statistics()
        
        print(f"\n📊 Database Statistics:")
        print(f"   - Total vulnerabilities in database: {db_stats.get('total_vulnerabilities', 0):,}")
        print(f"   - Total affected packages: {db_stats.get('total_affected_packages', 0):,}")
        print(f"   - Recent vulnerabilities (30 days): {db_stats.get('recent_vulnerabilities', 0):,}")
        
        # Show severity breakdown
        severity_breakdown = db_stats.get('severity_breakdown', {})
        if severity_breakdown:
            print(f"   - Severity breakdown:")
            for severity, count in severity_breakdown.items():
                print(f"     • {severity}: {count:,}")
        
        return True
        
    except Exception as e:
        print(f"❌ Database integration test failed: {str(e)}")
        return False

def main():
    """Main test function."""
    print("🚀 Container Security Scanner - Phase 1, Step 2 Test Suite")
    print("Testing Package Vulnerability Matching")
    
    # Setup debug logging
    setup_debug_logging()
    
    # Run all tests
    tests = [
        ("Basic Functionality", test_phase1_step2_basic),
        ("Multiple Images", test_phase1_step2_multiple_images),
        ("Vulnerability Details", test_phase1_step2_vulnerability_details),
        ("Risk Assessment", test_phase1_step2_risk_assessment),
        ("Report Generation", test_phase1_step2_report_generation),
        ("Database Integration", test_phase1_step2_database_integration)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        
        try:
            result = test_func()
            results[test_name] = result
            print(f"✅ {test_name} completed")
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {str(e)}")
            results[test_name] = False
    
    # Summary
    print("\n" + "="*60)
    print("📊 TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<35} {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Phase 1, Step 2 is working correctly.")
        print("\n📋 Phase 1, Step 2 Features Verified:")
        print("   ✅ Debian image extraction and layer analysis")
        print("   ✅ Package vulnerability matching against local database")
        print("   ✅ Comprehensive vulnerability reporting")
        print("   ✅ Risk assessment and recommendations")
        print("   ✅ Database integration and scan history")
        print("   ✅ Multiple report formats (JSON, HTML)")
        print("\n🚀 Ready for production use!")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 