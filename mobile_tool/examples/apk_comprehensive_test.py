#!/usr/bin/env python3
"""
Comprehensive APK Security Testing Example
Demonstrates all enhanced APK-specific security checks and analysis capabilities.
"""

import os
import sys
import json
import time
from pathlib import Path

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from analyzers.static_analyzer import StaticAnalyzer
from reporting.report_generator import ReportGenerator
from utils.debug_utils import setup_debug_logging, debug_print

def test_apk_static_analysis(apk_path: str, debug: bool = True):
    """Test comprehensive APK static analysis."""
    print("="*80)
    print("COMPREHENSIVE APK STATIC ANALYSIS TEST")
    print("="*80)
    
    # Initialize static analyzer with debug enabled
    static_analyzer = StaticAnalyzer(debug=debug)
    
    print(f"Analyzing APK: {apk_path}")
    print(f"Debug mode: {'Enabled' if debug else 'Disabled'}")
    print("-" * 80)
    
    # Perform comprehensive static analysis
    start_time = time.time()
    results = static_analyzer.analyze_apk(apk_path)
    end_time = time.time()
    
    print(f"Analysis completed in {end_time - start_time:.2f} seconds")
    print("-" * 80)
    
    # Display detailed results
    display_static_analysis_results(results)
    
    return results

def display_static_analysis_results(results: dict):
    """Display comprehensive static analysis results."""
    
    # File Information
    print("\n📁 FILE INFORMATION")
    print("-" * 40)
    file_info = results.get("file_info", {})
    print(f"File Path: {file_info.get('file_path', 'N/A')}")
    print(f"File Size: {file_info.get('file_size', 0):,} bytes")
    print(f"File Type: {file_info.get('file_type', 'N/A')}")
    print(f"Total Files: {file_info.get('total_files', 0)}")
    
    # Manifest Analysis
    print("\n📋 MANIFEST ANALYSIS")
    print("-" * 40)
    manifest = results.get("manifest_analysis", {})
    print(f"Package: {manifest.get('package', 'N/A')}")
    print(f"Version Code: {manifest.get('version_code', 'N/A')}")
    print(f"Version Name: {manifest.get('version_name', 'N/A')}")
    print(f"Min SDK: {manifest.get('min_sdk', 'N/A')}")
    print(f"Target SDK: {manifest.get('target_sdk', 'N/A')}")
    
    # Deep Analysis
    print("\n🔍 DEEP MANIFEST ANALYSIS")
    print("-" * 40)
    deep_analysis = results.get("deep_analysis", {})
    app_attrs = deep_analysis.get("application_attributes", {})
    
    print("Application Attributes:")
    for attr, value in app_attrs.items():
        status = "❌" if value == "true" and attr in ["debuggable", "allowBackup", "usesCleartextTraffic"] else "✅"
        print(f"  {status} {attr}: {value}")
    
    # Security Issues from Deep Analysis
    security_issues = deep_analysis.get("security_issues", [])
    if security_issues:
        print(f"\n🚨 Security Issues Found: {len(security_issues)}")
        for i, issue in enumerate(security_issues, 1):
            print(f"  {i}. [{issue.get('severity', 'unknown').upper()}] {issue.get('description', 'N/A')}")
    
    # Exported Components
    exported_components = deep_analysis.get("exported_components", [])
    if exported_components:
        print(f"\n🚪 Exported Components: {len(exported_components)}")
        for component in exported_components:
            protection = "Protected" if component.get("permission") else "Unprotected"
            print(f"  • {component.get('type', 'unknown')}: {component.get('name', 'N/A')} ({protection})")
    
    # Permissions Analysis
    print("\n🔐 PERMISSIONS ANALYSIS")
    print("-" * 40)
    permissions = results.get("permissions", [])
    print(f"Total Permissions: {len(permissions)}")
    
    dangerous_count = 0
    signature_count = 0
    
    for permission in permissions:
        if permission.get("name") in static_analyzer.dangerous_permissions:
            dangerous_count += 1
            print(f"  ⚠️  Dangerous: {permission.get('name')}")
        elif permission.get("name") in static_analyzer.signature_permissions:
            signature_count += 1
            print(f"  🔒 Signature: {permission.get('name')}")
    
    print(f"\nDangerous Permissions: {dangerous_count}")
    print(f"Signature Permissions: {signature_count}")
    
    # Intent Filter Analysis
    print("\n🔗 INTENT FILTER ANALYSIS")
    print("-" * 40)
    intent_analysis = results.get("intent_analysis", {})
    intent_filters = intent_analysis.get("intent_filters", [])
    deeplinks = intent_analysis.get("deeplinks", [])
    
    print(f"Intent Filters: {len(intent_filters)}")
    print(f"Deep Links: {len(deeplinks)}")
    
    if deeplinks:
        print("\nDeep Links Found:")
        for deeplink in deeplinks:
            print(f"  • {deeplink.get('scheme', 'N/A')}://{deeplink.get('host', 'N/A')}")
    
    # Deep Link Analysis
    print("\n🔗 DEEP LINK ANALYSIS")
    print("-" * 40)
    deeplink_analysis = results.get("deeplink_analysis", {})
    deeplinks = deeplink_analysis.get("deeplinks", [])
    schemes = deeplink_analysis.get("schemes", [])
    hosts = deeplink_analysis.get("hosts", [])
    
    print(f"Total Deep Links: {len(deeplinks)}")
    print(f"Unique Schemes: {len(schemes)}")
    print(f"Unique Hosts: {len(hosts)}")
    
    if schemes:
        print(f"Schemes: {', '.join(schemes)}")
    
    # Security Issues from Deep Links
    deeplink_issues = deeplink_analysis.get("security_issues", [])
    if deeplink_issues:
        print(f"\n🚨 Deep Link Security Issues: {len(deeplink_issues)}")
        for issue in deeplink_issues:
            print(f"  • [{issue.get('severity', 'unknown').upper()}] {issue.get('description', 'N/A')}")
    
    # Backup Configuration
    print("\n💾 BACKUP CONFIGURATION")
    print("-" * 40)
    backup_analysis = results.get("backup_analysis", {})
    backup_enabled = backup_analysis.get("backup_enabled", False)
    backup_rules = backup_analysis.get("backup_rules")
    
    print(f"Backup Enabled: {'❌ Yes' if backup_enabled else '✅ No'}")
    print(f"Backup Rules: {backup_rules or 'Default'}")
    
    backup_issues = backup_analysis.get("security_issues", [])
    if backup_issues:
        print(f"\n🚨 Backup Security Issues: {len(backup_issues)}")
        for issue in backup_issues:
            print(f"  • [{issue.get('severity', 'unknown').upper()}] {issue.get('description', 'N/A')}")
    
    # WebView Configuration
    print("\n🌐 WEBVIEW CONFIGURATION")
    print("-" * 40)
    webview_analysis = results.get("webview_analysis", {})
    webview_usage = webview_analysis.get("webview_usage", False)
    
    print(f"WebView Usage: {'⚠️  Detected' if webview_usage else '✅ Not Detected'}")
    
    if webview_usage:
        webview_issues = webview_analysis.get("security_issues", [])
        if webview_issues:
            print(f"\n🚨 WebView Security Issues: {len(webview_issues)}")
            for issue in webview_issues:
                print(f"  • [{issue.get('severity', 'unknown').upper()}] {issue.get('description', 'N/A')}")
        
        recommendations = webview_analysis.get("recommendations", [])
        if recommendations:
            print(f"\n💡 WebView Recommendations:")
            for rec in recommendations:
                print(f"  • {rec}")
    
    # Third-Party Libraries
    print("\n📚 THIRD-PARTY LIBRARIES")
    print("-" * 40)
    third_party_analysis = results.get("third_party_analysis", {})
    libraries = third_party_analysis.get("libraries", [])
    vulnerable_libs = third_party_analysis.get("vulnerable_libraries", [])
    
    print(f"Total Libraries: {len(libraries)}")
    print(f"Vulnerable Libraries: {len(vulnerable_libs)}")
    
    if libraries:
        print("\nDetected Libraries:")
        for lib in libraries:
            print(f"  • {lib.get('name', 'N/A')} v{lib.get('version', 'unknown')}")
    
    if vulnerable_libs:
        print(f"\n🚨 Vulnerable Libraries:")
        for lib in vulnerable_libs:
            print(f"  • {lib.get('name', 'N/A')} v{lib.get('version', 'unknown')}")
    
    # Code Analysis
    print("\n💻 CODE ANALYSIS")
    print("-" * 40)
    code_analysis = results.get("code_analysis", {})
    
    hardcoded_secrets = code_analysis.get("hardcoded_secrets", [])
    insecure_crypto = code_analysis.get("insecure_crypto", [])
    sql_injection = code_analysis.get("sql_injection", [])
    path_traversal = code_analysis.get("path_traversal", [])
    command_injection = code_analysis.get("command_injection", [])
    
    print(f"Hardcoded Secrets: {len(hardcoded_secrets)}")
    print(f"Insecure Crypto: {len(insecure_crypto)}")
    print(f"SQL Injection Patterns: {len(sql_injection)}")
    print(f"Path Traversal Patterns: {len(path_traversal)}")
    print(f"Command Injection Patterns: {len(command_injection)}")
    
    if hardcoded_secrets:
        print(f"\n🚨 Hardcoded Secrets Found:")
        for secret in hardcoded_secrets[:3]:  # Show first 3
            print(f"  • {secret.get('file', 'N/A')}: {secret.get('match', 'N/A')}")
        if len(hardcoded_secrets) > 3:
            print(f"  ... and {len(hardcoded_secrets) - 3} more")
    
    # Native Libraries
    print("\n🔧 NATIVE LIBRARIES")
    print("-" * 40)
    native_analysis = results.get("native_analysis", {})
    native_libs = native_analysis.get("native_libraries", [])
    
    print(f"Native Libraries: {len(native_libs)}")
    if native_libs:
        for lib in native_libs:
            print(f"  • {lib}")
    
    # Certificates
    print("\n🔐 CERTIFICATES")
    print("-" * 40)
    certificate_analysis = results.get("certificate_analysis", {})
    certificates = certificate_analysis.get("certificates", [])
    
    print(f"Certificates: {len(certificates)}")
    if certificates:
        for cert in certificates:
            print(f"  • {cert.get('subject', 'N/A')}")
    
    # Overall Vulnerabilities
    print("\n🚨 OVERALL VULNERABILITIES")
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
    
    # Recommendations
    print("\n💡 RECOMMENDATIONS")
    print("-" * 40)
    recommendations = results.get("recommendations", [])
    
    if recommendations:
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
    else:
        print("  No specific recommendations generated.")

def save_detailed_report(results: dict, output_file: str):
    """Save detailed analysis report."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n📄 Detailed report saved to: {output_file}")
    except Exception as e:
        print(f"Error saving report: {str(e)}")

def main():
    """Main function for comprehensive APK testing."""
    print("Comprehensive APK Security Testing Tool")
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
        # Perform comprehensive static analysis
        results = test_apk_static_analysis(apk_path, debug=True)
        
        # Save detailed report
        apk_name = Path(apk_path).stem
        report_file = f"apk_comprehensive_analysis_{apk_name}.json"
        save_detailed_report(results, report_file)
        
        print("\n✅ Comprehensive APK analysis completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error during analysis: {str(e)}")
        debug_print(f"Error details: {str(e)}", True)

if __name__ == "__main__":
    main() 