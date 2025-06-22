#!/usr/bin/env python3
"""
Demonstration: Using Swagger/OpenAPI with Web UI
"""

import requests
import json
import time

def demo_swagger_ui_scan():
    """Demonstrate scanning Swagger/OpenAPI through web UI API"""
    print("🌐 Demonstrating Swagger/OpenAPI with Web UI")
    print("=" * 50)
    
    base_url = "http://localhost:5000"
    
    # Test 1: Swagger URL scan
    print("1. Testing Swagger URL scan through web UI...")
    
    swagger_scan_config = {
        "scan_type": "swagger_url",
        "swagger_url": "https://petstore.swagger.io/v2/swagger.json",
        "base_url": "https://petstore.swagger.io"
    }
    
    try:
        # Start scan through web UI API
        response = requests.post(f"{base_url}/api/scan", json=swagger_scan_config)
        
        if response.status_code == 200:
            data = response.json()
            scan_id = data['scan_id']
            print(f"   ✅ Scan started successfully!")
            print(f"   Scan ID: {scan_id}")
            print(f"   Status: {data['status']}")
            
            # Monitor scan progress
            print(f"\n2. Monitoring scan progress...")
            max_attempts = 30  # Wait up to 30 seconds
            attempts = 0
            
            while attempts < max_attempts:
                try:
                    # Check scan status
                    status_response = requests.get(f"{base_url}/api/scan/{scan_id}")
                    if status_response.status_code == 200:
                        scan_data = status_response.json()
                        status = scan_data.get('status', 'unknown')
                        
                        print(f"   Status: {status}")
                        
                        if status == 'completed':
                            print(f"   ✅ Scan completed!")
                            print(f"   Endpoints scanned: {scan_data.get('endpoints_scanned', 0)}")
                            print(f"   Vulnerabilities found: {len(scan_data.get('vulnerabilities_found', []))}")
                            
                            # Check for reports
                            if 'reports' in scan_data:
                                print(f"   Reports available:")
                                for report_type, report_path in scan_data['reports'].items():
                                    print(f"     - {report_type}: {report_path}")
                            
                            break
                        elif status == 'failed':
                            print(f"   ❌ Scan failed: {scan_data.get('error', 'Unknown error')}")
                            break
                        else:
                            # Check progress
                            progress_response = requests.get(f"{base_url}/api/scan/{scan_id}/progress")
                            if progress_response.status_code == 200:
                                progress_data = progress_response.json()
                                if 'percentage' in progress_data:
                                    print(f"   Progress: {progress_data['percentage']}%")
                                if 'current_endpoint' in progress_data and progress_data['current_endpoint']:
                                    print(f"   Current: {progress_data['current_method']} {progress_data['current_endpoint']}")
                    
                    time.sleep(2)  # Wait 2 seconds before next check
                    attempts += 1
                    
                except Exception as e:
                    print(f"   Error checking status: {e}")
                    break
            
            if attempts >= max_attempts:
                print(f"   ⏰ Scan still running after {max_attempts * 2} seconds")
            
        else:
            print(f"   ❌ Failed to start scan: {response.status_code}")
            print(f"   Response: {response.text}")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Test 2: Check scan history
    print(f"\n3. Checking scan history...")
    try:
        history_response = requests.get(f"{base_url}/api/scans")
        if history_response.status_code == 200:
            scans = history_response.json()
            print(f"   Total scans in history: {len(scans)}")
            
            # Show recent scans
            recent_scans = scans[:3]  # Show last 3 scans
            for scan in recent_scans:
                print(f"   - {scan.get('id', 'N/A')}: {scan.get('scan_type', 'N/A')} ({scan.get('status', 'N/A')})")
        else:
            print(f"   ❌ Failed to get scan history: {history_response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print(f"\n🎉 Web UI Swagger/OpenAPI demonstration completed!")
    print(f"\n💡 Next steps:")
    print(f"   1. Open browser to: http://localhost:5000")
    print(f"   2. Try the 'Swagger URL' option manually")
    print(f"   3. Enter: https://petstore.swagger.io/v2/swagger.json")
    print(f"   4. Base URL: https://petstore.swagger.io")
    print(f"   5. Click 'Start Security Scan'")

def show_web_ui_features():
    """Show web UI features for Swagger/OpenAPI"""
    print("\n📋 Web UI Features for Swagger/OpenAPI:")
    print("=" * 40)
    
    features = [
        {
            "feature": "Swagger URL Input",
            "description": "Direct URL to Swagger/OpenAPI specification",
            "example": "https://api.example.com/swagger.json",
            "supported": "✅ Yes"
        },
        {
            "feature": "JSON File Upload",
            "description": "Upload OpenAPI JSON/YAML files",
            "example": "my-api-spec.json",
            "supported": "✅ Yes"
        },
        {
            "feature": "Real-time Progress",
            "description": "See scan progress in real-time",
            "example": "Scanning endpoint 5/20...",
            "supported": "✅ Yes"
        },
        {
            "feature": "Authentication Support",
            "description": "API Key, Bearer Token, Basic Auth, OAuth2",
            "example": "Bearer token authentication",
            "supported": "✅ Yes"
        },
        {
            "feature": "Report Generation",
            "description": "JSON and HTML reports",
            "example": "OWASP Top 10 compliance report",
            "supported": "✅ Yes"
        },
        {
            "feature": "Scan History",
            "description": "View all previous scans",
            "example": "List of completed scans",
            "supported": "✅ Yes"
        }
    ]
    
    for feature in features:
        print(f"\n🔹 {feature['feature']}")
        print(f"   Description: {feature['description']}")
        print(f"   Example: {feature['example']}")
        print(f"   Supported: {feature['supported']}")

if __name__ == "__main__":
    print("🚀 Swagger/OpenAPI Web UI Demonstration")
    print("=" * 60)
    
    show_web_ui_features()
    demo_swagger_ui_scan() 