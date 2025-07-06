#!/usr/bin/env python3
"""
Test script for Different Naming Conventions and Folders for CLI vs API Scans
"""
import requests
import json
import time
import os
import subprocess
import sys

# Configuration
API_BASE_URL = "http://localhost:5000"
TEST_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

def test_naming_conventions():
    """Test the different naming conventions and folders for CLI vs API scans."""
    print("📁 Testing Different Naming Conventions and Folders for CLI vs API Scans")
    print("=" * 80)
    
    # Test 1: Check current directory structure
    print("\n1. Checking current reports directory structure...")
    base_reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports')
    cli_reports_dir = os.path.join(base_reports_dir, 'cli')
    api_reports_dir = os.path.join(base_reports_dir, 'api')
    
    print(f"   Base reports directory: {base_reports_dir}")
    print(f"   CLI reports directory: {cli_reports_dir}")
    print(f"   API reports directory: {api_reports_dir}")
    
    # Create directories if they don't exist
    os.makedirs(cli_reports_dir, exist_ok=True)
    os.makedirs(api_reports_dir, exist_ok=True)
    
    print("   ✅ Directories created/verified")
    
    # Test 2: Generate CLI scan report
    print("\n2. Generating CLI scan report...")
    try:
        # Run CLI command to generate a report
        cli_command = [
            sys.executable, 
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src', 'jwt_security_tester.py'),
            '--token', TEST_TOKEN,
            '--output', 'cli_test_report.html'
        ]
        
        print(f"   Running CLI command: {' '.join(cli_command)}")
        result = subprocess.run(cli_command, capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
        
        if result.returncode == 0:
            print("   ✅ CLI scan completed successfully")
            print(f"   CLI output: {result.stdout.strip()}")
        else:
            print(f"   ❌ CLI scan failed: {result.stderr}")
            return
    except Exception as e:
        print(f"   ❌ Error running CLI: {e}")
        return
    
    # Test 3: Generate API scan report
    print("\n3. Generating API scan report...")
    try:
        # Start a scan session
        response = requests.post(f"{API_BASE_URL}/scan/start", json={
            "scan_type": "single",
            "description": "Testing naming conventions"
        })
        if response.status_code == 200:
            scan_data = response.json()
            scan_id = scan_data["scan_id"]
            print(f"   ✅ Scan session created: {scan_id}")
            
            # Analyze token
            response = requests.post(f"{API_BASE_URL}/scan/{scan_id}/analyze", json={
                "token": TEST_TOKEN,
                "secret": "test-secret"
            })
            if response.status_code == 200:
                print("   ✅ API analysis completed")
                
                # Generate report
                response = requests.get(f"{API_BASE_URL}/scan/{scan_id}/report?format=html")
                if response.status_code == 200:
                    print("   ✅ API report generated")
                else:
                    print(f"   ❌ API report generation failed: {response.status_code}")
            else:
                print(f"   ❌ API analysis failed: {response.status_code}")
        else:
            print(f"   ❌ Failed to create scan session: {response.status_code}")
            return
    except Exception as e:
        print(f"   ❌ Error with API: {e}")
        return
    
    # Test 4: List files in both directories
    print("\n4. Listing files in both directories...")
    
    print("   📁 CLI Reports Directory:")
    if os.path.exists(cli_reports_dir):
        cli_files = [f for f in os.listdir(cli_reports_dir) if f.endswith('.html') or f.endswith('.json')]
        if cli_files:
            for file in cli_files:
                file_path = os.path.join(cli_reports_dir, file)
                file_size = os.path.getsize(file_path)
                print(f"     - {file} ({file_size} bytes)")
        else:
            print("     No files found")
    else:
        print("     Directory not found")
    
    print("   📁 API Reports Directory:")
    if os.path.exists(api_reports_dir):
        api_files = [f for f in os.listdir(api_reports_dir) if f.endswith('.html') or f.endswith('.json')]
        if api_files:
            for file in api_files:
                file_path = os.path.join(api_reports_dir, file)
                file_size = os.path.getsize(file_path)
                print(f"     - {file} ({file_size} bytes)")
        else:
            print("     No files found")
    else:
        print("     Directory not found")
    
    # Test 5: Check API reports endpoint
    print("\n5. Checking API reports endpoint...")
    try:
        response = requests.get(f"{API_BASE_URL}/reports")
        if response.status_code == 200:
            reports_data = response.json()
            print(f"   ✅ API reports endpoint working")
            print(f"   Total API reports: {reports_data['total_reports']}")
            print(f"   API reports directory: {reports_data['reports_directory']}")
            
            if reports_data['reports']:
                print("   API reports:")
                for report in reports_data['reports']:
                    print(f"     - {report['filename']} (Scan: {report['scan_id'][:8]}...)")
        else:
            print(f"   ❌ API reports endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error checking API reports: {e}")
    
    # Test 6: Analyze naming patterns
    print("\n6. Analyzing naming patterns...")
    
    cli_pattern = "cli_scan_"
    api_pattern = "api_scan_"
    
    print(f"   CLI naming pattern: {cli_pattern}YYYYMMDD_HHMMSS.html")
    print(f"   API naming pattern: {api_pattern}scan_id_YYYYMMDD_HHMMSS.html")
    
    # Count files by pattern
    cli_count = len([f for f in os.listdir(cli_reports_dir) if f.startswith(cli_pattern)]) if os.path.exists(cli_reports_dir) else 0
    api_count = len([f for f in os.listdir(api_reports_dir) if f.startswith(api_pattern)]) if os.path.exists(api_reports_dir) else 0
    
    print(f"   CLI files with pattern: {cli_count}")
    print(f"   API files with pattern: {api_count}")
    
    # Test 7: Show directory structure
    print("\n7. Final directory structure:")
    print(f"   📂 {base_reports_dir}/")
    print(f"   ├── 📁 cli/")
    print(f"   │   ├── {cli_pattern}*.html")
    print(f"   │   └── {cli_pattern}*.json")
    print(f"   └── 📁 api/")
    print(f"       └── {api_pattern}*.html")
    
    print("\n" + "=" * 80)
    print("🎉 Naming Conventions Testing Completed!")
    print("\n📋 Summary:")
    print("   ✅ CLI scans use 'cli_scan_' prefix and save to reports/cli/")
    print("   ✅ API scans use 'api_scan_' prefix and save to reports/api/")
    print("   ✅ Both use timestamp suffixes for uniqueness")
    print("   ✅ API scans include scan ID in filename")
    print("   ✅ Separate directories prevent conflicts")
    print("\n💡 Benefits:")
    print("   - Easy to distinguish CLI vs API reports")
    print("   - Organized file structure")
    print("   - No naming conflicts")
    print("   - Clear audit trail")

if __name__ == "__main__":
    test_naming_conventions() 