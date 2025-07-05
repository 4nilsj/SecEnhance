#!/usr/bin/env python3
"""
Storage Security Testing Tool
Specialized tool for comprehensive Android APK storage security analysis.
"""

import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from analyzers.storage_analyzer import StorageAnalyzer
from utils.debug_utils import setup_debug_logging, debug_print

def test_storage_security(apk_path: str, debug: bool = True):
    """Test comprehensive storage security analysis."""
    print("="*80)
    print("COMPREHENSIVE STORAGE SECURITY ANALYSIS")
    print("="*80)
    
    # Initialize storage analyzer with debug enabled
    storage_analyzer = StorageAnalyzer(debug=debug)
    
    print(f"Analyzing APK: {apk_path}")
    print(f"Debug mode: {'Enabled' if debug else 'Disabled'}")
    print("-" * 80)
    
    # Perform comprehensive storage analysis
    start_time = time.time()
    results = storage_analyzer.analyze_apk(apk_path)
    end_time = time.time()
    
    print(f"Analysis completed in {end_time - start_time:.2f} seconds")
    print("-" * 80)
    
    # Display detailed results
    display_storage_analysis_results(results)
    
    return results

def display_storage_analysis_results(results: dict):
    """Display comprehensive storage analysis results."""
    
    # Storage Configuration
    print("\n📁 STORAGE CONFIGURATION")
    print("-" * 40)
    storage_config = results.get("storage_config", {})
    print(f"Backup Enabled: {'❌ Yes' if storage_config.get('backup_enabled') else '✅ No'}")
    print(f"Allow Backup: {'❌ Yes' if storage_config.get('allow_backup') else '✅ No'}")
    print(f"Full Backup Content: {'⚠️  Yes' if storage_config.get('full_backup_content') else '✅ No'}")
    print(f"External Storage: {'⚠️  Yes' if storage_config.get('external_storage') else '✅ No'}")
    
    # Secure Storage Analysis
    print("\n🔐 SECURE STORAGE ANALYSIS")
    print("-" * 40)
    secure_storage = results.get("secure_storage_analysis", {})
    keystore_usage = secure_storage.get("keystore_usage", False)
    secure_patterns = secure_storage.get("secure_storage_patterns", [])
    insecure_patterns = secure_storage.get("insecure_storage_patterns", [])
    
    print(f"Android Keystore Usage: {'✅ Yes' if keystore_usage else '❌ No'}")
    print(f"Secure Storage Patterns: {len(secure_patterns)}")
    print(f"Insecure Storage Patterns: {len(insecure_patterns)}")
    
    if secure_patterns:
        print("\nSecure Storage Implementations:")
        for pattern in secure_patterns[:3]:  # Show first 3
            print(f"  • {pattern.get('file', 'N/A')}: {pattern.get('pattern', 'N/A')}")
        if len(secure_patterns) > 3:
            print(f"  ... and {len(secure_patterns) - 3} more")
    
    if insecure_patterns:
        print(f"\n🚨 Insecure Storage Patterns:")
        for pattern in insecure_patterns[:3]:  # Show first 3
            print(f"  • {pattern.get('file', 'N/A')}: {pattern.get('pattern', 'N/A')}")
        if len(insecure_patterns) > 3:
            print(f"  ... and {len(insecure_patterns) - 3} more")
    
    # Data Leakage Analysis
    print("\n🔍 DATA LEAKAGE ANALYSIS")
    print("-" * 40)
    data_leakage = results.get("data_leakage_analysis", {})
    leakage_patterns = data_leakage.get("leakage_patterns", [])
    sensitive_logging = data_leakage.get("sensitive_data_logging", [])
    
    print(f"Data Leakage Patterns: {len(leakage_patterns)}")
    print(f"Sensitive Data Logging: {len(sensitive_logging)}")
    
    if leakage_patterns:
        print(f"\n🚨 Data Leakage Patterns:")
        for pattern in leakage_patterns[:3]:  # Show first 3
            print(f"  • {pattern.get('file', 'N/A')}: {pattern.get('match', 'N/A')}")
        if len(leakage_patterns) > 3:
            print(f"  ... and {len(leakage_patterns) - 3} more")
    
    if sensitive_logging:
        print(f"\n⚠️  Sensitive Data Logging:")
        for log in sensitive_logging[:3]:  # Show first 3
            print(f"  • {log.get('file', 'N/A')}: {log.get('keyword', 'N/A')}")
        if len(sensitive_logging) > 3:
            print(f"  ... and {len(sensitive_logging) - 3} more")
    
    # External Storage Analysis
    print("\n💾 EXTERNAL STORAGE ANALYSIS")
    print("-" * 40)
    external_storage = results.get("external_storage_analysis", {})
    external_usage = external_storage.get("external_storage_usage", False)
    storage_permissions = external_storage.get("storage_permissions", [])
    file_operations = external_storage.get("file_operations", [])
    
    print(f"External Storage Usage: {'⚠️  Yes' if external_usage else '✅ No'}")
    print(f"Storage Permissions: {len(storage_permissions)}")
    print(f"File Operations: {len(file_operations)}")
    
    if storage_permissions:
        print(f"\nExternal Storage Permissions:")
        for perm in storage_permissions:
            print(f"  • {perm.get('permission', 'N/A')}")
    
    if file_operations:
        print(f"\nExternal Storage Operations:")
        for op in file_operations[:3]:  # Show first 3
            print(f"  • {op.get('file', 'N/A')}: {op.get('operation', 'N/A')}")
        if len(file_operations) > 3:
            print(f"  ... and {len(file_operations) - 3} more")
    
    # Cache Analysis
    print("\n🗂️  CACHE ANALYSIS")
    print("-" * 40)
    cache_analysis = results.get("cache_analysis", {})
    cache_usage = cache_analysis.get("cache_usage", False)
    cache_operations = cache_analysis.get("cache_operations", [])
    sensitive_cache = cache_analysis.get("sensitive_data_in_cache", [])
    
    print(f"Cache Usage: {'⚠️  Yes' if cache_usage else '✅ No'}")
    print(f"Cache Operations: {len(cache_operations)}")
    print(f"Sensitive Data in Cache: {len(sensitive_cache)}")
    
    if sensitive_cache:
        print(f"\n🚨 Sensitive Data in Cache:")
        for cache in sensitive_cache[:3]:  # Show first 3
            print(f"  • {cache.get('file', 'N/A')}: {cache.get('pattern', 'N/A')}")
        if len(sensitive_cache) > 3:
            print(f"  ... and {len(sensitive_cache) - 3} more")
    
    # Database Analysis
    print("\n🗄️  DATABASE ANALYSIS")
    print("-" * 40)
    databases = results.get("databases", [])
    print(f"Total Databases: {len(databases)}")
    
    encrypted_dbs = 0
    unencrypted_dbs = 0
    
    for db in databases:
        if db.get("encrypted", False):
            encrypted_dbs += 1
        else:
            unencrypted_dbs += 1
    
    print(f"Encrypted Databases: {encrypted_dbs}")
    print(f"Unencrypted Databases: {unencrypted_dbs}")
    
    if databases:
        print(f"\nDatabase Details:")
        for db in databases:
            encryption_status = "✅ Encrypted" if db.get("encrypted", False) else "❌ Unencrypted"
            print(f"  • {db.get('name', 'N/A')}: {encryption_status}")
    
    # Shared Preferences Analysis
    print("\n⚙️  SHARED PREFERENCES ANALYSIS")
    print("-" * 40)
    shared_prefs = results.get("shared_preferences", [])
    print(f"Total SharedPreferences: {len(shared_prefs)}")
    
    encrypted_prefs = 0
    unencrypted_prefs = 0
    
    for pref in shared_prefs:
        if pref.get("encrypted", False):
            encrypted_prefs += 1
        else:
            unencrypted_prefs += 1
    
    print(f"Encrypted SharedPreferences: {encrypted_prefs}")
    print(f"Unencrypted SharedPreferences: {unencrypted_prefs}")
    
    if shared_prefs:
        print(f"\nSharedPreferences Details:")
        for pref in shared_prefs:
            encryption_status = "✅ Encrypted" if pref.get("encrypted", False) else "❌ Unencrypted"
            print(f"  • {pref.get('name', 'N/A')}: {encryption_status}")
    
    # File Storage Analysis
    print("\n📄 FILE STORAGE ANALYSIS")
    print("-" * 40)
    file_storage = results.get("file_storage", [])
    print(f"Total File Storage Operations: {len(file_storage)}")
    
    encrypted_files = 0
    unencrypted_files = 0
    
    for file in file_storage:
        if file.get("encrypted", False):
            encrypted_files += 1
        else:
            unencrypted_files += 1
    
    print(f"Encrypted File Operations: {encrypted_files}")
    print(f"Unencrypted File Operations: {unencrypted_files}")
    
    if file_storage:
        print(f"\nFile Storage Details:")
        for file in file_storage:
            encryption_status = "✅ Encrypted" if file.get("encrypted", False) else "❌ Unencrypted"
            print(f"  • {file.get('name', 'N/A')}: {encryption_status}")
    
    # Encryption Analysis
    print("\n🔐 ENCRYPTION ANALYSIS")
    print("-" * 40)
    encryption_analysis = results.get("encryption_analysis", {})
    encryption_used = encryption_analysis.get("encryption_used", False)
    encryption_methods = encryption_analysis.get("encryption_methods", [])
    
    print(f"Encryption Used: {'✅ Yes' if encryption_used else '❌ No'}")
    print(f"Encryption Methods: {len(encryption_methods)}")
    
    if encryption_methods:
        print(f"\nEncryption Methods:")
        for method in encryption_methods:
            print(f"  • {method}")
    
    # Backup Analysis
    print("\n💾 BACKUP ANALYSIS")
    print("-" * 40)
    backup_analysis = results.get("backup_analysis", {})
    backup_enabled = backup_analysis.get("backup_enabled", False)
    backup_rules = backup_analysis.get("backup_rules")
    
    print(f"Backup Enabled: {'❌ Yes' if backup_enabled else '✅ No'}")
    print(f"Backup Rules: {backup_rules or 'Default'}")
    
    # Overall Vulnerabilities
    print("\n🚨 STORAGE VULNERABILITIES")
    print("-" * 40)
    vulnerabilities = results.get("vulnerabilities", [])
    security_issues = results.get("security_issues", [])
    
    print(f"Total Vulnerabilities: {len(vulnerabilities)}")
    print(f"Security Issues: {len(security_issues)}")
    
    # Categorize by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "unknown").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    print(f"\nVulnerabilities by Severity:")
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"  {severity.upper()}: {count}")
    
    # Show critical and high vulnerabilities
    critical_vulns = [v for v in vulnerabilities if v.get("severity", "").lower() == "critical"]
    high_vulns = [v for v in vulnerabilities if v.get("severity", "").lower() == "high"]
    
    if critical_vulns:
        print(f"\n🚨 Critical Vulnerabilities:")
        for vuln in critical_vulns:
            print(f"  • {vuln.get('description', 'N/A')}")
    
    if high_vulns:
        print(f"\n⚠️  High Severity Vulnerabilities:")
        for vuln in high_vulns[:5]:  # Show first 5
            print(f"  • {vuln.get('description', 'N/A')}")
        if len(high_vulns) > 5:
            print(f"  ... and {len(high_vulns) - 5} more")
    
    # Recommendations
    print("\n💡 STORAGE SECURITY RECOMMENDATIONS")
    print("-" * 40)
    recommendations = results.get("recommendations", [])
    
    if recommendations:
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
    else:
        print("  No specific recommendations generated.")
    
    # Security Summary
    print("\n📊 STORAGE SECURITY SUMMARY")
    print("-" * 40)
    
    total_issues = len(vulnerabilities) + len(security_issues)
    critical_high_issues = len(critical_vulns) + len(high_vulns)
    
    if critical_high_issues > 0:
        print(f"🚨 CRITICAL: {critical_high_issues} high/critical security issues found")
        print("   Immediate action required!")
    elif total_issues > 0:
        print(f"⚠️  WARNING: {total_issues} security issues found")
        print("   Review and address security concerns")
    else:
        print("✅ GOOD: No major storage security issues detected")
        print("   Continue monitoring and best practices")
    
    # Storage Security Score
    max_score = 100
    score_deductions = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 1
    }
    
    total_deduction = 0
    for severity, count in severity_counts.items():
        if severity in score_deductions:
            total_deduction += count * score_deductions[severity]
    
    security_score = max(0, max_score - total_deduction)
    
    print(f"\nStorage Security Score: {security_score}/100")
    
    if security_score >= 80:
        print("Storage Security Status: ✅ EXCELLENT")
    elif security_score >= 60:
        print("Storage Security Status: ⚠️  GOOD")
    elif security_score >= 40:
        print("Storage Security Status: ⚠️  FAIR")
    elif security_score >= 20:
        print("Storage Security Status: 🚨 POOR")
    else:
        print("Storage Security Status: 🚨 CRITICAL")

def save_storage_report(results: dict, output_file: str):
    """Save detailed storage analysis report."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n📄 Detailed storage report saved to: {output_file}")
    except Exception as e:
        print(f"Error saving report: {str(e)}")

def main():
    """Main function for storage security testing."""
    print("Storage Security Testing Tool")
    print("=" * 50)
    
    # Example APK path (you would replace this with actual APK path)
    apk_path = input("Enter the path to the APK file: ").strip()
    
    if not os.path.exists(apk_path):
        print(f"Error: APK file not found: {apk_path}")
        return
    
    if not apk_path.endswith('.apk'):
        print(f"Warning: File does not have .apk extension: {apk_path}")
        response = input("Continue anyway? (y/n): ").strip().lower()
        if response != 'y':
            return
    
    # Setup debug logging
    setup_debug_logging(debug=True)
    
    try:
        # Perform comprehensive storage analysis
        results = test_storage_security(apk_path, debug=True)
        
        # Save detailed report
        apk_name = Path(apk_path).stem
        report_file = f"storage_security_analysis_{apk_name}.json"
        save_storage_report(results, report_file)
        
        print("\n✅ Storage security analysis completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error during analysis: {str(e)}")
        debug_print(f"Error details: {str(e)}", True)

if __name__ == "__main__":
    main() 