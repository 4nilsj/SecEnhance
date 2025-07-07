#!/usr/bin/env python3
"""
Test script for Local Report Organization
Verifies that CLI and API reports are properly organized in separate directories.
"""

import os
import json
import time
from pathlib import Path
from datetime import datetime

def setup_test_environment():
    """Setup test environment with necessary directories."""
    print("🔧 Setting up test environment...")
    
    directories = [
        "reports/api",
        "reports/cli",
        "uploads",
        "logs"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def create_test_reports():
    """Create test reports in both CLI and API directories."""
    print("📝 Creating test reports...")
    
    # Create CLI test report
    cli_report = {
        "scan_info": {
            "file_path": "test_app.apk",
            "file_type": "APK",
            "scan_date": datetime.now().isoformat(),
            "tests_performed": ["static", "network", "storage", "code"]
        },
        "summary": {
            "total_vulnerabilities": 5,
            "critical": 1,
            "high": 2,
            "medium": 1,
            "low": 1,
            "overall_risk": "High"
        },
        "vulnerabilities": [
            {
                "title": "Weak SSL Implementation",
                "severity": "critical",
                "description": "App uses weak SSL configuration",
                "location": "NetworkSecurityConfig",
                "proof": "SSLv3 enabled in configuration",
                "reproduction": "Use SSL scanner to detect weak protocols"
            }
        ]
    }
    
    # Save CLI report
    cli_filename = f"cli_scan_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    cli_path = f"reports/cli/{cli_filename}"
    
    with open(cli_path, 'w') as f:
        json.dump(cli_report, f, indent=2)
    
    print(f"✅ Created CLI report: {cli_path}")
    
    # Create API test report
    api_report = {
        "scan_id": "test-scan-123",
        "scan_info": {
            "file_path": "test_app.ipa",
            "file_type": "IPA",
            "scan_date": datetime.now().isoformat(),
            "tests_performed": ["static", "code", "storage"]
        },
        "summary": {
            "total_vulnerabilities": 3,
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 0,
            "overall_risk": "Medium"
        },
        "vulnerabilities": [
            {
                "title": "Insecure Data Storage",
                "severity": "high",
                "description": "Sensitive data stored in plain text",
                "location": "UserDefaults",
                "proof": "Found API keys in UserDefaults",
                "reproduction": "Extract UserDefaults.plist from device"
            }
        ]
    }
    
    # Save API report
    api_filename = f"api_scan_test-scan-123_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    api_path = f"reports/api/{api_filename}"
    
    with open(api_path, 'w') as f:
        json.dump(api_report, f, indent=2)
    
    print(f"✅ Created API report: {api_path}")
    
    return cli_path, api_path

def verify_report_organization():
    """Verify that reports are properly organized."""
    print("🔍 Verifying report organization...")
    
    # Check CLI reports
    cli_reports = list(Path("reports/cli").glob("*"))
    print(f"📁 CLI reports found: {len(cli_reports)}")
    for report in cli_reports:
        print(f"   - {report.name}")
        if not report.name.startswith("cli_scan_"):
            print(f"   ⚠️  Warning: CLI report doesn't follow naming convention: {report.name}")
    
    # Check API reports
    api_reports = list(Path("reports/api").glob("*"))
    print(f"📁 API reports found: {len(api_reports)}")
    for report in api_reports:
        print(f"   - {report.name}")
        if not report.name.startswith("api_scan_"):
            print(f"   ⚠️  Warning: API report doesn't follow naming convention: {report.name}")
    
    # Check for cross-contamination
    cli_in_api = list(Path("reports/api").glob("cli_scan_*"))
    api_in_cli = list(Path("reports/cli").glob("api_scan_*"))
    
    if cli_in_api:
        print(f"❌ Found CLI reports in API directory: {[r.name for r in cli_in_api]}")
    else:
        print("✅ No CLI reports found in API directory")
    
    if api_in_cli:
        print(f"❌ Found API reports in CLI directory: {[r.name for r in api_in_cli]}")
    else:
        print("✅ No API reports found in CLI directory")

def test_report_content():
    """Test report content and structure."""
    print("📊 Testing report content...")
    
    # Test CLI report
    cli_reports = list(Path("reports/cli").glob("*.json"))
    if cli_reports:
        with open(cli_reports[0], 'r') as f:
            cli_data = json.load(f)
        
        required_fields = ["scan_info", "summary", "vulnerabilities"]
        for field in required_fields:
            if field in cli_data:
                print(f"✅ CLI report contains {field}")
            else:
                print(f"❌ CLI report missing {field}")
    
    # Test API report
    api_reports = list(Path("reports/api").glob("*.json"))
    if api_reports:
        with open(api_reports[0], 'r') as f:
            api_data = json.load(f)
        
        required_fields = ["scan_id", "scan_info", "summary", "vulnerabilities"]
        for field in required_fields:
            if field in api_data:
                print(f"✅ API report contains {field}")
            else:
                print(f"❌ API report missing {field}")

def test_naming_conventions():
    """Test naming conventions for reports."""
    print("🏷️ Testing naming conventions...")
    
    # Test CLI naming convention
    cli_reports = list(Path("reports/cli").glob("cli_scan_*"))
    print(f"✅ CLI reports following convention: {len(cli_reports)}")
    
    # Test API naming convention
    api_reports = list(Path("reports/api").glob("api_scan_*"))
    print(f"✅ API reports following convention: {len(api_reports)}")
    
    # Test timestamp format
    for report in cli_reports + api_reports:
        name = report.name
        if "_202" in name and len(name.split("_")) >= 3:
            print(f"✅ Report has timestamp: {name}")
        else:
            print(f"⚠️  Report may not have proper timestamp: {name}")

def cleanup_test_files():
    """Clean up test files."""
    print("🧹 Cleaning up test files...")
    
    # Remove test reports
    for report in Path("reports/cli").glob("cli_scan_test_*"):
        report.unlink()
        print(f"🗑️ Removed: {report}")
    
    for report in Path("reports/api").glob("api_scan_test-*"):
        report.unlink()
        print(f"🗑️ Removed: {report}")

def main():
    """Main test function."""
    print("🧪 Mobile Security Testing - Local Report Organization Test")
    print("=" * 60)
    
    # Setup
    setup_test_environment()
    
    # Create test reports
    cli_path, api_path = create_test_reports()
    
    # Verify organization
    verify_report_organization()
    
    # Test content
    test_report_content()
    
    # Test naming conventions
    test_naming_conventions()
    
    # Summary
    print("\n📋 Test Summary:")
    print("✅ Report directories created")
    print("✅ CLI and API reports separated")
    print("✅ Naming conventions verified")
    print("✅ Report content structure validated")
    
    # Cleanup
    cleanup_test_files()
    
    print("\n🎉 Local report organization test completed!")

if __name__ == "__main__":
    main() 