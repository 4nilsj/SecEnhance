#!/usr/bin/env python3
"""
Test Enhanced Mobile Security API Features
Demonstrates the new API endpoints and capabilities.
"""

import requests
import json
import time
import os
from pathlib import Path

# API Configuration
API_BASE_URL = "http://localhost:5001/api/v1"

def test_health_check():
    """Test the health check endpoint."""
    print("🔍 Testing Health Check...")
    response = requests.get(f"{API_BASE_URL}/health")
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Health Check: {data['status']} - Version {data['version']}")
        return True
    else:
        print(f"❌ Health Check Failed: {response.status_code}")
        return False

def test_stats():
    """Test the statistics endpoint."""
    print("\n📊 Testing Statistics Endpoint...")
    response = requests.get(f"{API_BASE_URL}/stats")
    if response.status_code == 200:
        data = response.json()
        stats = data['api_stats']
        vuln_stats = data['vulnerability_stats']
        print(f"✅ API Stats:")
        print(f"   • Total Scans: {stats['total_scans']}")
        print(f"   • Completed: {stats['completed_scans']}")
        print(f"   • Failed: {stats['failed_scans']}")
        print(f"   • Success Rate: {stats['success_rate']:.1f}%")
        print(f"✅ Vulnerability Stats:")
        print(f"   • Total Vulnerabilities: {vuln_stats['total_vulnerabilities']}")
        print(f"   • Critical: {vuln_stats['critical']}")
        print(f"   • High: {vuln_stats['high']}")
        print(f"   • Medium: {vuln_stats['medium']}")
        print(f"   • Low: {vuln_stats['low']}")
        return True
    else:
        print(f"❌ Stats Failed: {response.status_code}")
        return False

def test_batch_scan():
    """Test batch scanning functionality."""
    print("\n🔄 Testing Batch Scan...")
    
    # Create test files (dummy APKs)
    test_files = []
    for i in range(2):
        test_file = f"test_app_{i}.apk"
        with open(test_file, 'wb') as f:
            f.write(b"PK\x03\x04dummy APK content")
        test_files.append(test_file)
    
    batch_data = {
        "files": test_files,
        "tests": ["static", "network", "storage", "code"]
    }
    
    response = requests.post(f"{API_BASE_URL}/batch-scan", json=batch_data)
    if response.status_code == 202:
        data = response.json()
        batch_id = data['batch_id']
        print(f"✅ Batch Scan Started: {batch_id}")
        
        # Monitor batch progress
        print("📈 Monitoring batch progress...")
        for _ in range(10):  # Wait up to 10 seconds
            time.sleep(1)
            status_response = requests.get(f"{API_BASE_URL}/scan/{batch_id}/status")
            if status_response.status_code == 200:
                status_data = status_response.json()
                if status_data['status'] == 'completed':
                    print(f"✅ Batch Scan Completed!")
                    print(f"   • Total Files: {status_data['results']['total_files']}")
                    print(f"   • Completed: {status_data['results']['completed_files']}")
                    print(f"   • Failed: {status_data['results']['failed_files']}")
                    
                    # Clean up test files
                    for test_file in test_files:
                        if os.path.exists(test_file):
                            os.remove(test_file)
                    
                    return batch_id
                elif status_data['status'] == 'failed':
                    print(f"❌ Batch Scan Failed: {status_data.get('error', 'Unknown error')}")
                    break
        
        print("⏰ Batch scan taking longer than expected...")
        return batch_id
    else:
        print(f"❌ Batch Scan Failed: {response.status_code}")
        return None

def test_dashboard_report(scan_id):
    """Test dashboard report generation."""
    if not scan_id:
        print("⚠️  Skipping dashboard test - no scan ID available")
        return
    
    print(f"\n📊 Testing Dashboard Report for scan {scan_id}...")
    response = requests.get(f"{API_BASE_URL}/scan/{scan_id}/dashboard")
    if response.status_code == 200:
        # Save dashboard report
        dashboard_file = f"dashboard_report_{scan_id}.html"
        with open(dashboard_file, 'wb') as f:
            f.write(response.content)
        print(f"✅ Dashboard Report Saved: {dashboard_file}")
        return True
    else:
        print(f"❌ Dashboard Report Failed: {response.status_code}")
        return False

def test_ai_analysis(scan_id):
    """Test AI analysis endpoint."""
    if not scan_id:
        print("⚠️  Skipping AI analysis test - no scan ID available")
        return
    
    print(f"\n🤖 Testing AI Analysis for scan {scan_id}...")
    ai_data = {"scan_id": scan_id}
    response = requests.post(f"{API_BASE_URL}/ai-analysis", json=ai_data)
    if response.status_code == 200:
        data = response.json()
        ai_results = data['ai_analysis']
        print(f"✅ AI Analysis Completed!")
        print(f"   • AI Predictions: {len(ai_results)}")
        for result in ai_results:
            print(f"   • {result['type']}: {result['description']}")
        return True
    else:
        print(f"❌ AI Analysis Failed: {response.status_code}")
        return False

def test_list_scans():
    """Test listing all scans."""
    print("\n📋 Testing List Scans...")
    response = requests.get(f"{API_BASE_URL}/scans")
    if response.status_code == 200:
        data = response.json()
        scans = data['scans']
        print(f"✅ Found {len(scans)} scans:")
        for scan in scans[:5]:  # Show first 5 scans
            print(f"   • {scan['scan_id'][:8]}... - {scan['status']} - {scan.get('file_path', 'N/A')}")
        return True
    else:
        print(f"❌ List Scans Failed: {response.status_code}")
        return False

def main():
    """Run all API tests."""
    print("🚀 Enhanced Mobile Security API Test Suite")
    print("=" * 50)
    
    # Test basic functionality
    if not test_health_check():
        print("❌ API server not running. Please start the API server first.")
        return
    
    # Test statistics
    test_stats()
    
    # Test batch scanning
    batch_id = test_batch_scan()
    
    # Test dashboard report
    test_dashboard_report(batch_id)
    
    # Test AI analysis
    test_ai_analysis(batch_id)
    
    # Test listing scans
    test_list_scans()
    
    print("\n🎉 Enhanced API Test Suite Completed!")
    print("\n📚 New API Endpoints Available:")
    print("   • GET  /api/v1/stats - API statistics")
    print("   • POST /api/v1/batch-scan - Batch file scanning")
    print("   • GET  /api/v1/scan/{id}/dashboard - Interactive dashboard")
    print("   • POST /api/v1/ai-analysis - AI-powered analysis")
    print("   • GET  /api/v1/scans - List all scans")

if __name__ == "__main__":
    main() 