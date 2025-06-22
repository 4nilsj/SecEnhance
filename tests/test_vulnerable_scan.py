#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script to scan the vulnerable API and generate enhanced reports
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from core.api_security_scanner import APISecurityScanner
import json
from datetime import datetime

def scan_vulnerable_api():
    """Scan the vulnerable test API"""
    print("Scanning Vulnerable Test API")
    print("=" * 50)
    
    # Initialize scanner
    scanner = APISecurityScanner()
    
    # Define vulnerable API endpoints
    vulnerable_endpoints = [
        {
            "url": "http://localhost:5001/api/users",
            "method": "GET",
            "description": "Get users - vulnerable to SQL injection"
        },
        {
            "url": "http://localhost:5001/api/users/1",
            "method": "GET", 
            "description": "Get user by ID - vulnerable to SQL injection"
        },
        {
            "url": "http://localhost:5001/api/search",
            "method": "GET",
            "description": "Search endpoint - vulnerable to SQL injection"
        },
        {
            "url": "http://localhost:5001/api/admin",
            "method": "GET",
            "description": "Admin endpoint - missing authentication"
        },
        {
            "url": "http://localhost:5001/api/users",
            "method": "POST",
            "description": "Create user - missing authentication"
        }
    ]
    
    print(f"Scanning {len(vulnerable_endpoints)} endpoints...")
    
    try:
        # Run the scan
        scan_results = scanner.scan_api_endpoints(vulnerable_endpoints)
        
        print("\nScan completed!")
        print(f"Results Summary:")
        print(f"   - Endpoints Scanned: {scan_results.get('endpoints_scanned', 0)}")
        print(f"   - Vulnerabilities Found: {len(scan_results.get('vulnerabilities_found', []))}")
        print(f"   - Scan Duration: {scan_results.get('scan_duration', 0):.2f} seconds")
        
        # Display vulnerabilities found
        vulnerabilities = scan_results.get('vulnerabilities_found', [])
        if vulnerabilities:
            print(f"\nVulnerabilities Detected:")
            for i, vuln in enumerate(vulnerabilities, 1):
                vuln_type = vuln.get('type', 'Unknown')
                severity = vuln.get('severity', 'Unknown')
                url = vuln.get('url', 'N/A')
                print(f"   {i}. {vuln_type} ({severity}) - {url}")
                
                # Show if request/response data is captured
                if vuln.get('request_data'):
                    print(f"      Request data captured")
                if vuln.get('response_data'):
                    print(f"      Response data captured")
        else:
            print("No vulnerabilities found")
        
        # Generate reports
        print(f"\nGenerating Reports...")
        
        # Generate JSON report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_filename = f"vulnerable_api_scan_{timestamp}.json"
        
        with open(json_filename, 'w') as f:
            json.dump(scan_results, f, indent=2, default=str)
        
        print(f"   JSON Report: {json_filename}")
        
        # Generate PDF report using the web app function
        try:
            from web.app import generate_pdf_from_json
            pdf_path, error = generate_pdf_from_json(scan_results, f"scan_{timestamp}")
            
            if pdf_path and not error:
                print(f"   PDF Report: {pdf_path}")
                
                # Check file size
                if os.path.exists(pdf_path):
                    file_size = os.path.getsize(pdf_path)
                    print(f"   PDF Size: {file_size} bytes")
            else:
                print(f"   PDF generation failed: {error}")
        except Exception as e:
            print(f"   PDF generation error: {e}")
        
        # Generate HTML report
        try:
            from web.app_enhanced import generate_html_report_from_json
            html_path = generate_html_report_from_json(scan_results, f"scan_{timestamp}")
            print(f"   HTML Report: {html_path}")
        except Exception as e:
            print(f"   HTML generation error: {e}")
        
        print(f"\nScan and report generation completed!")
        print(f"Check the generated files for detailed vulnerability information with request/response data!")
        
        return scan_results, json_filename
        
    except Exception as e:
        print(f"Scan error: {e}")
        import traceback
        traceback.print_exc()
        return None, None

if __name__ == "__main__":
    scan_vulnerable_api() 