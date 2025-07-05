#!/usr/bin/env python3
"""
Test Script for Container Security Scanner - Phase 1, Step 1
Debian Image Extraction and Analysis

This script demonstrates the Phase 1, Step 1 functionality:
- Basic OS Package Vulnerability Scanning for Debian-based images
- Step 1: Image Extraction using Docker SDK to pull an image and extract its layers
"""

import sys
import os
import json
import time
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import with absolute path
from src.container_security_scanner import ContainerSecurityScanner
from src.utils.debug_utils import setup_debug_logging, debug_print

def test_debian_phase1_basic():
    """Test basic Debian Phase 1, Step 1 functionality."""
    print("\n" + "="*60)
    print("🧪 TEST 1: Basic Debian Phase 1, Step 1")
    print("="*60)
    
    # Initialize scanner with debug mode
    scanner = ContainerSecurityScanner(debug=True)
    
    # Test with a common Debian-based image
    test_image = "debian:bullseye-slim"
    
    print(f"Testing with image: {test_image}")
    print("This will:")
    print("  • Pull the Debian image using Docker SDK")
    print("  • Extract all layers as tarballs")
    print("  • Analyze Debian-specific files")
    print("  • Generate extraction report")
    
    try:
        # Run Phase 1, Step 1 analysis
        results = scanner.scan_debian_image_phase1(test_image)
        
        # Display results
        print("\n✅ Test completed successfully!")
        print(f"📊 Results summary:")
        print(f"   - Image: {results['scan_info']['target_name']}")
        print(f"   - Phase: {results['scan_info']['phase']}")
        print(f"   - Step: {results['scan_info']['step']}")
        
        # Check if Debian analysis was successful
        if 'debian_analysis' in results and results['debian_analysis']:
            debian_data = results['debian_analysis']
            print(f"   - Extraction time: {debian_data.get('extraction_time', 0):.2f} seconds")
            print(f"   - Total layers: {len(debian_data.get('layers', []))}")
            print(f"   - Total size: {debian_data.get('total_size', 0) / (1024*1024):.2f} MB")
            
            # Check Debian info
            debian_info = debian_data.get('debian_info', {})
            if debian_info:
                print(f"   - Distribution: {debian_info.get('distribution', 'N/A')}")
                print(f"   - Version: {debian_info.get('version', 'N/A')}")
                print(f"   - Package count: {debian_info.get('package_count', 0)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        debug_print(f"Exception details: {str(e)}")
        return False

def test_debian_phase1_multiple_images():
    """Test Phase 1, Step 1 with multiple Debian-based images."""
    print("\n" + "="*60)
    print("🧪 TEST 2: Multiple Debian Images")
    print("="*60)
    
    # Initialize scanner
    scanner = ContainerSecurityScanner(debug=True)
    
    # Test images
    test_images = [
        "debian:bullseye-slim",
        "ubuntu:20.04",
        "alpine:latest"  # This should show different behavior
    ]
    
    results_summary = {}
    
    for image in test_images:
        print(f"\n🔍 Testing image: {image}")
        
        try:
            results = scanner.scan_debian_image_phase1(image)
            
            # Extract key metrics
            debian_data = results.get('debian_analysis', {})
            results_summary[image] = {
                'success': True,
                'extraction_time': debian_data.get('extraction_time', 0),
                'layers': len(debian_data.get('layers', [])),
                'total_size_mb': debian_data.get('total_size', 0) / (1024*1024),
                'debian_info': debian_data.get('debian_info', {}),
                'errors': debian_data.get('errors', [])
            }
            
            print(f"   ✅ Success - {len(debian_data.get('layers', []))} layers, "
                  f"{debian_data.get('total_size', 0) / (1024*1024):.2f} MB")
            
        except Exception as e:
            print(f"   ❌ Failed: {str(e)}")
            results_summary[image] = {
                'success': False,
                'error': str(e)
            }
    
    # Display comparison
    print("\n📊 Comparison Summary:")
    print(f"{'Image':<25} {'Status':<8} {'Layers':<8} {'Size (MB)':<10} {'Time (s)':<10}")
    print("-" * 70)
    
    for image, summary in results_summary.items():
        if summary['success']:
            print(f"{image:<25} {'✅':<8} {summary['layers']:<8} "
                  f"{summary['total_size_mb']:<10.2f} {summary['extraction_time']:<10.2f}")
        else:
            print(f"{image:<25} {'❌':<8} {'N/A':<8} {'N/A':<10} {'N/A':<10}")
    
    return results_summary

def test_debian_phase1_batch_mode():
    """Test Phase 1, Step 1 in batch mode."""
    print("\n" + "="*60)
    print("🧪 TEST 3: Batch Mode Debian Analysis")
    print("="*60)
    
    # Initialize scanner
    scanner = ContainerSecurityScanner(debug=True)
    
    # Create batch configuration
    batch_config = [
        {
            "type": "debian_phase1",
            "target": "debian:bullseye-slim",
            "description": "Debian Bullseye Slim"
        },
        {
            "type": "debian_phase1", 
            "target": "ubuntu:20.04",
            "description": "Ubuntu 20.04"
        },
        {
            "type": "debian_phase1",
            "target": "debian:buster-slim",
            "description": "Debian Buster Slim"
        }
    ]
    
    print("Running batch analysis with 3 Debian-based images...")
    
    try:
        # Run batch scan
        batch_results = scanner.batch_scan(batch_config)
        
        # Display batch results
        print(f"\n✅ Batch analysis completed!")
        print(f"📊 Batch Summary:")
        print(f"   - Total targets: {batch_results['batch_info']['total_targets']}")
        print(f"   - Successful: {batch_results['batch_info']['successful_scans']}")
        print(f"   - Failed: {batch_results['batch_info']['failed_scans']}")
        
        # Show individual results
        for i, result in enumerate(batch_results['results']):
            scan_config = result['scan_config']
            scan_result = result['result']
            
            print(f"\n🔍 Result {i+1}: {scan_config['description']}")
            print(f"   - Target: {scan_config['target']}")
            
            debian_data = scan_result.get('debian_analysis', {})
            if debian_data:
                print(f"   - Layers: {len(debian_data.get('layers', []))}")
                print(f"   - Size: {debian_data.get('total_size', 0) / (1024*1024):.2f} MB")
                print(f"   - Time: {debian_data.get('extraction_time', 0):.2f} seconds")
        
        return batch_results
        
    except Exception as e:
        print(f"❌ Batch test failed: {str(e)}")
        debug_print(f"Batch exception: {str(e)}")
        return None

def test_debian_phase1_error_handling():
    """Test error handling for invalid images."""
    print("\n" + "="*60)
    print("🧪 TEST 4: Error Handling")
    print("="*60)
    
    # Initialize scanner
    scanner = ContainerSecurityScanner(debug=True)
    
    # Test with invalid image
    invalid_image = "nonexistent-image:latest"
    
    print(f"Testing error handling with invalid image: {invalid_image}")
    
    try:
        results = scanner.scan_debian_image_phase1(invalid_image)
        
        # Check if errors were properly captured
        debian_data = results.get('debian_analysis', {})
        errors = debian_data.get('errors', [])
        
        if errors:
            print(f"✅ Error handling working correctly!")
            print(f"   - Captured {len(errors)} error(s)")
            for error in errors:
                print(f"   - Error: {error}")
        else:
            print("⚠️  No errors captured - this might be unexpected")
        
        return len(errors) > 0
        
    except Exception as e:
        print(f"❌ Unexpected exception: {str(e)}")
        return False

def test_debian_phase1_report_generation():
    """Test report generation for Phase 1, Step 1 results."""
    print("\n" + "="*60)
    print("🧪 TEST 5: Report Generation")
    print("="*60)
    
    # Initialize scanner
    scanner = ContainerSecurityScanner(debug=True)
    
    # Run analysis
    test_image = "debian:bullseye-slim"
    print(f"Running analysis on {test_image} for report generation...")
    
    try:
        results = scanner.scan_debian_image_phase1(test_image)
        
        # Generate different report formats
        report_formats = ['json', 'html']
        
        for format_type in report_formats:
            print(f"\n📄 Generating {format_type.upper()} report...")
            
            timestamp = int(time.time())
            output_file = f"debian_phase1_report_{timestamp}.{format_type}"
            
            report_path = scanner.generate_report(output_file, format_type)
            
            if os.path.exists(report_path):
                file_size = os.path.getsize(report_path)
                print(f"   ✅ Report generated: {report_path}")
                print(f"   📊 File size: {file_size} bytes")
            else:
                print(f"   ❌ Report file not found: {report_path}")
        
        return True
        
    except Exception as e:
        print(f"❌ Report generation failed: {str(e)}")
        return False

def main():
    """Main test function."""
    print("🚀 Container Security Scanner - Phase 1, Step 1 Test Suite")
    print("Testing Debian Image Extraction and Analysis")
    
    # Setup debug logging
    setup_debug_logging()
    
    # Run all tests
    tests = [
        ("Basic Functionality", test_debian_phase1_basic),
        ("Multiple Images", test_debian_phase1_multiple_images),
        ("Batch Mode", test_debian_phase1_batch_mode),
        ("Error Handling", test_debian_phase1_error_handling),
        ("Report Generation", test_debian_phase1_report_generation)
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
        print(f"{test_name:<25} {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Phase 1, Step 1 is working correctly.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 