#!/usr/bin/env python3
"""
Simple API Security Scanner Demo
A basic demonstration of the API Security Scanner functionality
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path (updated for examples/ directory location)
src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from core.api_security_scanner import APISecurityScanner

def run_demo_scan():
    """Run a simple demo scan"""
    print("🔍 API Security Scanner - Vulnerable API Demo")
    print("=" * 50)
    
    # Initialize scanner
    scanner = APISecurityScanner()
    print("✅ Scanner initialized")
    
    # Test vulnerable API endpoints
    test_endpoints = [
        {
            'url': 'http://localhost:5001/api/users',
            'method': 'GET',
            'description': 'Get users - vulnerable to SQL injection'
        },
        {
            'url': 'http://localhost:5001/api/users/1',
            'method': 'GET',
            'description': 'Get user by ID - vulnerable to SQL injection'
        },
        {
            'url': 'http://localhost:5001/api/search',
            'method': 'GET',
            'description': 'Search endpoint - vulnerable to SQL injection'
        },
        {
            'url': 'http://localhost:5001/api/admin',
            'method': 'GET',
            'description': 'Admin endpoint - missing authentication'
        },
        {
            'url': 'http://localhost:5001/api/users',
            'method': 'POST',
            'description': 'Create user - missing authentication'
        }
    ]
    
    print(f"📡 Testing {len(test_endpoints)} vulnerable endpoints...")
    print("   This will test for:")
    print("   - SQL Injection vulnerabilities")
    print("   - XSS vulnerabilities")
    print("   - Authentication bypass")
    print("   - Information disclosure")
    print("   - Rate limiting issues")
    print()
    
    # Run the scan
    results = scanner.scan_api_endpoints(test_endpoints)
    
    # Display results
    print("📊 Scan Results:")
    print(f"   Scan ID: {results.get('scan_id', 'N/A')}")
    print(f"   Duration: {results.get('scan_duration', 0):.2f} seconds")
    print(f"   Endpoints Scanned: {results.get('endpoints_scanned', 0)}")
    print(f"   Vulnerabilities Found: {len(results.get('vulnerabilities_found', []))}")
    print(f"   Errors: {len(results.get('error_summary', []))}")
    
    # Show vulnerabilities if any
    vulnerabilities = results.get('vulnerabilities_found', [])
    if vulnerabilities:
        print("\n🚨 Vulnerabilities Found:")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"   {i}. {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
            print(f"      URL: {vuln.get('url', 'N/A')}")
            print(f"      Evidence: {vuln.get('evidence', 'N/A')}")
            
            # Show if request/response data is captured
            if vuln.get('request_data'):
                print(f"      📤 Request data captured")
            if vuln.get('response_data'):
                print(f"      📥 Response data captured")
            print()
    else:
        print("\n✅ No vulnerabilities found in this scan")
    
    # Show errors if any
    errors = results.get('error_summary', [])
    if errors:
        print("\n⚠️  Errors Encountered:")
        for i, error in enumerate(errors, 1):
            print(f"   {i}. {error}")
    
    # Generate report
    print("\n📄 Generating report...")
    try:
        report_path = scanner.generate_api_security_report(results, 'json')
        print(f"   JSON Report saved to: {report_path}")
        
        # Also generate HTML report
        html_report_path = scanner.generate_owasp_report(results, 'html')
        print(f"   HTML report saved to: {html_report_path}")
        
        # Generate PDF report
        try:
            from web.app import generate_pdf_from_json
            pdf_path, error = generate_pdf_from_json(results, 'vulnerable_api_scan')
            if pdf_path and not error:
                print(f"   PDF Report saved to: {pdf_path}")
            else:
                print(f"   PDF generation failed: {error}")
        except Exception as e:
            print(f"   PDF generation error: {e}")
        
    except Exception as e:
        print(f"   Error generating report: {e}")
    
    print("\n🎉 Demo completed!")
    print("💡 Check the generated reports for detailed vulnerability information with request/response data!")

if __name__ == "__main__":
    try:
        run_demo_scan()
    except KeyboardInterrupt:
        print("\n👋 Demo stopped by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        print("💡 Make sure all dependencies are installed: pip install -r requirements.txt") 