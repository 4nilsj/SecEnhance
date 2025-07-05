#!/usr/bin/env python3
"""
Local Vulnerability Database Demo
Demonstrates the local database functionality for Phase 1, Step 2 vulnerability matching.
"""

import sys
import os
import json
from datetime import datetime

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from database.local_vulnerability_db import LocalVulnerabilityDB
from utils.debug_utils import setup_debug_logging, debug_print

def demo_database_initialization():
    """Demonstrate database initialization."""
    print("\n" + "="*60)
    print("🧪 DEMO 1: Database Initialization")
    print("="*60)
    
    try:
        # Initialize database
        print("📊 Initializing local vulnerability database...")
        db = LocalVulnerabilityDB(debug=True)
        
        # Show initial statistics
        stats = db.get_vulnerability_stats()
        print(f"✅ Database initialized successfully!")
        print(f"   - Database path: {db.db_path}")
        print(f"   - Total vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
        print(f"   - Total affected packages: {stats.get('total_affected_packages', 0)}")
        
        # Close database
        db.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Database initialization failed: {str(e)}")
        return False

def demo_nvd_data_download():
    """Demonstrate NVD data download."""
    print("\n" + "="*60)
    print("🧪 DEMO 2: NVD Data Download")
    print("="*60)
    
    try:
        # Initialize database
        db = LocalVulnerabilityDB(debug=True)
        
        # Download current year data
        current_year = datetime.now().year
        print(f"📥 Downloading NVD data for {current_year}...")
        
        success = db.download_nvd_data(current_year, force_update=False)
        
        if success:
            print(f"✅ Successfully downloaded NVD data for {current_year}")
            
            # Show updated statistics
            stats = db.get_vulnerability_stats()
            print(f"📊 Updated database statistics:")
            print(f"   - Total vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
            print(f"   - Total affected packages: {stats.get('total_affected_packages', 0)}")
            
            # Show severity breakdown
            severity_breakdown = stats.get('severity_breakdown', {})
            if severity_breakdown:
                print(f"   - Severity breakdown:")
                for severity, count in severity_breakdown.items():
                    print(f"     • {severity}: {count}")
            
            # Show package managers
            package_managers = stats.get('package_managers', {})
            if package_managers:
                print(f"   - Package managers:")
                for manager, count in package_managers.items():
                    print(f"     • {manager}: {count}")
        else:
            print(f"⚠️  NVD data download failed or data already exists")
        
        # Close database
        db.close()
        
        return success
        
    except Exception as e:
        print(f"❌ NVD data download failed: {str(e)}")
        return False

def demo_vulnerability_search():
    """Demonstrate vulnerability search functionality."""
    print("\n" + "="*60)
    print("🧪 DEMO 3: Vulnerability Search")
    print("="*60)
    
    try:
        # Initialize database
        db = LocalVulnerabilityDB(debug=True)
        
        # Test packages to search for
        test_packages = [
            {"name": "openssl", "version": "1.1.1", "manager": "dpkg"},
            {"name": "apache2", "version": "2.4.41", "manager": "dpkg"},
            {"name": "nginx", "version": "1.18.0", "manager": "dpkg"},
            {"name": "python3", "version": "3.8.5", "manager": "dpkg"},
            {"name": "nodejs", "version": "14.17.0", "manager": "npm"}
        ]
        
        print("🔍 Searching for vulnerabilities in test packages...")
        
        for package in test_packages:
            print(f"\n📦 Searching: {package['name']} {package['version']} ({package['manager']})")
            
            vulnerabilities = db.search_vulnerabilities(
                package['name'], 
                package['version'], 
                package['manager']
            )
            
            if vulnerabilities:
                print(f"   🚨 Found {len(vulnerabilities)} vulnerabilities:")
                for vuln in vulnerabilities[:3]:  # Show first 3
                    print(f"     • {vuln['cve_id']} - {vuln['severity']} (CVSS: {vuln['cvss_score']})")
                    print(f"       {vuln['description'][:100]}...")
                if len(vulnerabilities) > 3:
                    print(f"     ... and {len(vulnerabilities) - 3} more")
            else:
                print(f"   ✅ No vulnerabilities found")
        
        # Close database
        db.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Vulnerability search failed: {str(e)}")
        return False

def demo_scan_results_storage():
    """Demonstrate scan results storage functionality."""
    print("\n" + "="*60)
    print("🧪 DEMO 4: Scan Results Storage")
    print("="*60)
    
    try:
        # Initialize database
        db = LocalVulnerabilityDB(debug=True)
        
        # Create sample scan data
        scan_id = f"demo_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        image_name = "debian:bullseye-slim"
        
        sample_scan_data = {
            "total_packages": 156,
            "vulnerable_packages": 12,
            "critical_vulnerabilities": 2,
            "high_vulnerabilities": 5,
            "medium_vulnerabilities": 3,
            "low_vulnerabilities": 2,
            "scan_duration": 45.23,
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2023-1234",
                    "package_name": "openssl",
                    "package_version": "1.1.1n-0+deb11u4",
                    "severity": "HIGH",
                    "cvss_score": 8.1
                },
                {
                    "cve_id": "CVE-2023-5678",
                    "package_name": "apache2",
                    "package_version": "2.4.54-1~deb11u1",
                    "severity": "MEDIUM",
                    "cvss_score": 5.5
                }
            ]
        }
        
        print(f"💾 Saving scan results for: {image_name}")
        print(f"   - Scan ID: {scan_id}")
        print(f"   - Total packages: {sample_scan_data['total_packages']}")
        print(f"   - Vulnerable packages: {sample_scan_data['vulnerable_packages']}")
        
        # Save scan results
        success = db.save_scan_results(scan_id, image_name, sample_scan_data)
        
        if success:
            print(f"✅ Scan results saved successfully!")
            
            # Retrieve scan history
            scan_history = db.get_scan_history(limit=5)
            print(f"\n📋 Recent scan history:")
            for scan in scan_history:
                print(f"   - {scan['image_name']} ({scan['scan_date'][:10]})")
                print(f"     • Vulnerable: {scan['vulnerable_packages']}/{scan['total_packages']}")
                print(f"     • Critical: {scan['critical_vulnerabilities']}, High: {scan['high_vulnerabilities']}")
        else:
            print(f"❌ Failed to save scan results")
        
        # Close database
        db.close()
        
        return success
        
    except Exception as e:
        print(f"❌ Scan results storage failed: {str(e)}")
        return False

def demo_package_vulnerability_matching():
    """Demonstrate package vulnerability matching for Phase 1, Step 2."""
    print("\n" + "="*60)
    print("🧪 DEMO 5: Package Vulnerability Matching (Phase 1, Step 2)")
    print("="*60)
    
    try:
        # Initialize database
        db = LocalVulnerabilityDB(debug=True)
        
        # Sample Debian packages from Phase 1, Step 1
        debian_packages = [
            {"name": "base-files", "version": "11.1+deb11u7", "architecture": "amd64"},
            {"name": "openssl", "version": "1.1.1n-0+deb11u4", "architecture": "amd64"},
            {"name": "apache2", "version": "2.4.54-1~deb11u1", "architecture": "amd64"},
            {"name": "nginx", "version": "1.18.0-6.1+deb11u1", "architecture": "amd64"},
            {"name": "python3", "version": "3.9.2-3", "architecture": "amd64"},
            {"name": "curl", "version": "7.74.0-1.3+deb11u7", "architecture": "amd64"},
            {"name": "wget", "version": "1.21-1+deb11u1", "architecture": "amd64"},
            {"name": "git", "version": "1:2.30.2-1+deb11u2", "architecture": "amd64"}
        ]
        
        print("🔍 Matching packages against vulnerability database...")
        print(f"📦 Processing {len(debian_packages)} packages")
        
        total_vulnerabilities = 0
        vulnerable_packages = 0
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for package in debian_packages:
            print(f"\n📦 Checking: {package['name']} {package['version']}")
            
            # Search for vulnerabilities
            vulnerabilities = db.search_vulnerabilities(
                package['name'], 
                package['version'], 
                "dpkg"
            )
            
            if vulnerabilities:
                vulnerable_packages += 1
                package_vuln_count = len(vulnerabilities)
                total_vulnerabilities += package_vuln_count
                
                print(f"   🚨 Found {package_vuln_count} vulnerabilities:")
                
                for vuln in vulnerabilities:
                    severity = vuln['severity']
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    print(f"     • {vuln['cve_id']} - {severity} (CVSS: {vuln['cvss_score']})")
                    print(f"       {vuln['description'][:80]}...")
            else:
                print(f"   ✅ No vulnerabilities found")
        
        # Summary
        print(f"\n📊 Vulnerability Matching Summary")
        print("-" * 40)
        print(f"   - Total packages checked: {len(debian_packages)}")
        print(f"   - Vulnerable packages: {vulnerable_packages}")
        print(f"   - Total vulnerabilities found: {total_vulnerabilities}")
        print(f"   - Severity breakdown:")
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"     • {severity}: {count}")
        
        # Risk assessment
        if severity_counts["CRITICAL"] > 0:
            overall_risk = "CRITICAL"
        elif severity_counts["HIGH"] > 0:
            overall_risk = "HIGH"
        elif severity_counts["MEDIUM"] > 0:
            overall_risk = "MEDIUM"
        elif severity_counts["LOW"] > 0:
            overall_risk = "LOW"
        else:
            overall_risk = "SECURE"
        
        print(f"   - Overall risk level: {overall_risk}")
        
        # Close database
        db.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Package vulnerability matching failed: {str(e)}")
        return False

def demo_database_statistics():
    """Demonstrate database statistics and reporting."""
    print("\n" + "="*60)
    print("🧪 DEMO 6: Database Statistics and Reporting")
    print("="*60)
    
    try:
        # Initialize database
        db = LocalVulnerabilityDB(debug=True)
        
        # Get comprehensive statistics
        stats = db.get_vulnerability_stats()
        
        print("📊 Database Statistics")
        print("-" * 30)
        print(f"   - Total vulnerabilities: {stats.get('total_vulnerabilities', 0):,}")
        print(f"   - Total affected packages: {stats.get('total_affected_packages', 0):,}")
        print(f"   - Recent vulnerabilities (30 days): {stats.get('recent_vulnerabilities', 0):,}")
        
        # Severity breakdown
        severity_breakdown = stats.get('severity_breakdown', {})
        if severity_breakdown:
            print(f"\n🚨 Vulnerability Severity Distribution")
            print("-" * 40)
            total_vulns = sum(severity_breakdown.values())
            for severity, count in severity_breakdown.items():
                percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
                print(f"   - {severity}: {count:,} ({percentage:.1f}%)")
        
        # Package managers
        package_managers = stats.get('package_managers', {})
        if package_managers:
            print(f"\n📦 Package Manager Distribution")
            print("-" * 40)
            total_packages = sum(package_managers.values())
            for manager, count in package_managers.items():
                percentage = (count / total_packages * 100) if total_packages > 0 else 0
                print(f"   - {manager}: {count:,} ({percentage:.1f}%)")
        
        # Scan history
        scan_history = db.get_scan_history(limit=10)
        if scan_history:
            print(f"\n🔍 Recent Scan Activity")
            print("-" * 40)
            for scan in scan_history:
                print(f"   - {scan['image_name']} ({scan['scan_date'][:10]})")
                print(f"     • Duration: {scan['scan_duration']:.2f}s")
                print(f"     • Vulnerabilities: {scan['vulnerable_packages']}/{scan['total_packages']}")
        
        # Close database
        db.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Database statistics failed: {str(e)}")
        return False

def main():
    """Main demonstration function."""
    print("🚀 Local Vulnerability Database Demo")
    print("Phase 1, Step 2: Package Vulnerability Matching")
    print("=" * 60)
    
    # Setup debug logging
    setup_debug_logging()
    
    # Run all demos
    demos = [
        ("Database Initialization", demo_database_initialization),
        ("NVD Data Download", demo_nvd_data_download),
        ("Vulnerability Search", demo_vulnerability_search),
        ("Scan Results Storage", demo_scan_results_storage),
        ("Package Vulnerability Matching", demo_package_vulnerability_matching),
        ("Database Statistics", demo_database_statistics)
    ]
    
    results = {}
    
    for demo_name, demo_func in demos:
        print(f"\n{'='*20} {demo_name} {'='*20}")
        
        try:
            result = demo_func()
            results[demo_name] = result
            print(f"✅ {demo_name} completed")
        except Exception as e:
            print(f"❌ {demo_name} failed with exception: {str(e)}")
            results[demo_name] = False
    
    # Summary
    print("\n" + "="*60)
    print("📊 DEMO SUMMARY")
    print("="*60)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for demo_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{demo_name:<35} {status}")
    
    print(f"\nOverall: {passed}/{total} demos passed")
    
    if passed == total:
        print("🎉 All demos passed! Local vulnerability database is working correctly.")
        print("\n📋 Next Steps for Phase 1, Step 2:")
        print("   1. Initialize database with NVD data: python scripts/init_database.py init")
        print("   2. Integrate with Debian package analyzer")
        print("   3. Implement automated vulnerability matching")
        print("   4. Generate comprehensive vulnerability reports")
    else:
        print("⚠️  Some demos failed. Check the output above for details.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 