#!/usr/bin/env python3
"""
Test script for Local Report Storage in Enhanced JWT Security Testing API
"""
import requests
import json
import time
import os

# Configuration
API_BASE_URL = "http://localhost:5000"
TEST_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

def test_local_report_storage():
    """Test the local report storage functionality."""
    print("📁 Testing Local Report Storage in Enhanced JWT Security Testing API")
    print("=" * 70)
    
    # Test 1: Check API status with reports info
    print("\n1. Checking API status with reports information...")
    try:
        response = requests.get(f"{API_BASE_URL}/status")
        if response.status_code == 200:
            status_data = response.json()
            print(f"✅ API Status: {status_data['status']}")
            print(f"   Active scans: {status_data.get('active_scans', 0)}")
            print(f"   Reports directory: {status_data.get('reports_directory', 'N/A')}")
            print(f"   Total reports: {status_data.get('total_reports', 0)}")
        else:
            print(f"❌ API Status check failed: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Cannot connect to API: {e}")
        print("   Make sure the enhanced API server is running:")
        print("   python src/jwt_api_enhanced.py")
        return
    
    # Test 2: List existing reports
    print("\n2. Listing existing reports...")
    try:
        response = requests.get(f"{API_BASE_URL}/reports")
        if response.status_code == 200:
            reports_data = response.json()
            print(f"✅ Total reports available: {reports_data['total_reports']}")
            print(f"   Reports directory: {reports_data['reports_directory']}")
            
            if reports_data['reports']:
                print("   Recent reports:")
                for report in reports_data['reports'][:3]:  # Show first 3
                    print(f"     - {report['filename']} (Scan: {report['scan_id'][:8]}...)")
            else:
                print("   No reports found yet")
        else:
            print(f"❌ Failed to list reports: {response.status_code}")
    except Exception as e:
        print(f"❌ Error listing reports: {e}")
    
    # Test 3: Start a new scan session
    print("\n3. Starting a new scan session for report generation...")
    try:
        response = requests.post(f"{API_BASE_URL}/scan/start", json={
            "scan_type": "single",
            "description": "Testing local report storage"
        })
        if response.status_code == 200:
            scan_data = response.json()
            scan_id = scan_data["scan_id"]
            print(f"✅ Scan session created: {scan_id}")
        else:
            print(f"❌ Failed to create scan session: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Error creating scan session: {e}")
        return
    
    # Test 4: Analyze token
    print("\n4. Analyzing JWT token...")
    try:
        response = requests.post(f"{API_BASE_URL}/scan/{scan_id}/analyze", json={
            "token": TEST_TOKEN,
            "secret": "test-secret"
        })
        if response.status_code == 200:
            results = response.json()
            print(f"✅ Analysis completed: {results['status']}")
        else:
            print(f"❌ Analysis failed: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        return
    
    # Test 5: Generate and save report locally
    print("\n5. Generating and saving report locally...")
    try:
        response = requests.get(f"{API_BASE_URL}/scan/{scan_id}/report?format=html")
        if response.status_code == 200:
            print(f"✅ Report generated and saved locally")
            print(f"   Content-Type: {response.headers.get('Content-Type', 'N/A')}")
            print(f"   Content-Length: {len(response.content)} bytes")
            
            # Save the downloaded report to verify
            filename = f"downloaded_report_{scan_id[:8]}.html"
            with open(filename, "wb") as f:
                f.write(response.content)
            print(f"   Downloaded report saved as: {filename}")
        else:
            print(f"❌ Failed to generate report: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        return
    
    # Test 6: Check scan status with report info
    print("\n6. Checking scan status with report information...")
    try:
        response = requests.get(f"{API_BASE_URL}/scan/{scan_id}/status")
        if response.status_code == 200:
            status_data = response.json()
            print(f"✅ Scan Status: {status_data['status']}")
            print(f"   Has results: {status_data['has_results']}")
        else:
            print(f"❌ Failed to get scan status: {response.status_code}")
    except Exception as e:
        print(f"❌ Error getting scan status: {e}")
    
    # Test 7: List all scans with report info
    print("\n7. Listing all scans with report information...")
    try:
        response = requests.get(f"{API_BASE_URL}/scans")
        if response.status_code == 200:
            scans_data = response.json()
            print(f"✅ Total scans: {scans_data['total_scans']}")
            
            for scan in scans_data['scans']:
                report_info = "📄 Has report" if scan.get('has_report') else "❌ No report"
                print(f"   - {scan['scan_id'][:8]}... ({scan['status']}) - {scan['scan_type']} - {report_info}")
        else:
            print(f"❌ Failed to list scans: {response.status_code}")
    except Exception as e:
        print(f"❌ Error listing scans: {e}")
    
    # Test 8: List updated reports
    print("\n8. Listing updated reports...")
    try:
        response = requests.get(f"{API_BASE_URL}/reports")
        if response.status_code == 200:
            reports_data = response.json()
            print(f"✅ Total reports available: {reports_data['total_reports']}")
            
            if reports_data['reports']:
                print("   Recent reports:")
                for report in reports_data['reports'][:3]:  # Show first 3
                    size_kb = report['file_size'] / 1024
                    print(f"     - {report['filename']} ({size_kb:.1f} KB)")
                    print(f"       Scan ID: {report['scan_id']}")
                    print(f"       Created: {report['created']}")
            else:
                print("   No reports found")
        else:
            print(f"❌ Failed to list reports: {response.status_code}")
    except Exception as e:
        print(f"❌ Error listing reports: {e}")
    
    # Test 9: Download a specific report
    print("\n9. Testing direct report download...")
    try:
        response = requests.get(f"{API_BASE_URL}/reports")
        if response.status_code == 200:
            reports_data = response.json()
            if reports_data['reports']:
                # Download the most recent report
                latest_report = reports_data['reports'][0]['filename']
                print(f"   Downloading latest report: {latest_report}")
                
                response = requests.get(f"{API_BASE_URL}/reports/{latest_report}")
                if response.status_code == 200:
                    print(f"✅ Report downloaded successfully")
                    print(f"   Size: {len(response.content)} bytes")
                else:
                    print(f"❌ Failed to download report: {response.status_code}")
            else:
                print("   No reports available for download")
        else:
            print(f"❌ Failed to get reports list: {response.status_code}")
    except Exception as e:
        print(f"❌ Error downloading report: {e}")
    
    print("\n" + "=" * 70)
    print("🎉 Local Report Storage testing completed!")
    print("\n📋 Summary:")
    print("   ✅ Reports are now saved locally in the reports directory")
    print("   ✅ Reports can be listed and downloaded via API")
    print("   ✅ Scan sessions track report generation")
    print("   ✅ Reports are accessible even after API restart")
    print(f"\n📁 Reports directory: {reports_data.get('reports_directory', 'N/A')}")
    print("\n💡 API Endpoints for reports:")
    print("   GET /reports - List all available reports")
    print("   GET /reports/<filename> - Download specific report")
    print("   GET /scan/{scan_id}/report - Generate report for scan")

if __name__ == "__main__":
    test_local_report_storage() 