#!/usr/bin/env python3
"""
Dynamic Analysis Test Script for Mobile Security Testing
Performs comprehensive dynamic analysis of APK files.
"""

import sys
import os
import argparse
import json
import logging
from pathlib import Path

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from analyzers.dynamic_analyzer import DynamicAnalyzer
from utils.debug_utils import setup_debug_logging, debug_print

def main():
    """Main function for dynamic analysis testing."""
    parser = argparse.ArgumentParser(description='Dynamic Analysis Test for APK Security')
    parser.add_argument('apk_path', help='Path to the APK file to analyze')
    parser.add_argument('--output', '-o', help='Output file for results (JSON)')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug output')
    parser.add_argument('--device', action='store_true', help='Analyze connected device')
    parser.add_argument('--package', help='Package name for device analysis')
    
    args = parser.parse_args()
    
    # Setup logging
    if args.debug:
        setup_debug_logging()
        debug_print("Debug mode enabled")
    
    # Validate APK path
    if not os.path.exists(args.apk_path):
        print(f"Error: APK file not found: {args.apk_path}")
        sys.exit(1)
    
    # Initialize dynamic analyzer
    analyzer = DynamicAnalyzer(debug=args.debug)
    
    try:
        if args.device:
            # Device analysis
            print("Starting device analysis...")
            results = analyzer.analyze_device("android", args.package)
        else:
            # APK analysis
            print(f"Starting dynamic analysis of APK: {args.apk_path}")
            results = analyzer.analyze_apk(args.apk_path)
        
        # Display results
        display_results(results)
        
        # Save results if output file specified
        if args.output:
            save_results(results, args.output)
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        if args.debug:
            logging.exception("Analysis failed")
        sys.exit(1)

def display_results(results: dict):
    """Display analysis results in a readable format."""
    print("\n" + "="*60)
    print("DYNAMIC ANALYSIS RESULTS")
    print("="*60)
    
    # Check for errors
    if "error" in results:
        print(f"❌ Analysis Error: {results['error']}")
        return
    
    # Runtime Permissions
    if "runtime_permissions" in results:
        print("\n🔐 RUNTIME PERMISSIONS")
        print("-" * 30)
        runtime_perms = results["runtime_permissions"]
        
        if "permissions_granted" in runtime_perms:
            print(f"Granted Permissions: {len(runtime_perms['permissions_granted'])}")
            for perm in runtime_perms["permissions_granted"][:5]:  # Show first 5
                print(f"  - {perm}")
            if len(runtime_perms["permissions_granted"]) > 5:
                print(f"  ... and {len(runtime_perms['permissions_granted']) - 5} more")
        
        if "security_issues" in runtime_perms:
            print(f"Security Issues: {len(runtime_perms['security_issues'])}")
            for issue in runtime_perms["security_issues"]:
                print(f"  ⚠️  {issue.get('description', 'Unknown issue')}")
    
    # Dynamic Code Loading
    if "dynamic_code_loading" in results:
        print("\n📦 DYNAMIC CODE LOADING")
        print("-" * 30)
        dynamic_loading = results["dynamic_code_loading"]
        
        if "loaded_libraries" in dynamic_loading:
            print(f"Loaded Libraries: {len(dynamic_loading['loaded_libraries'])}")
            for lib in dynamic_loading["loaded_libraries"][:5]:  # Show first 5
                print(f"  - {lib}")
            if len(dynamic_loading["loaded_libraries"]) > 5:
                print(f"  ... and {len(dynamic_loading['loaded_libraries']) - 5} more")
        
        if "security_issues" in dynamic_loading:
            print(f"Security Issues: {len(dynamic_loading['security_issues'])}")
            for issue in dynamic_loading["security_issues"]:
                print(f"  ⚠️  {issue.get('description', 'Unknown issue')}")
    
    # Root Detection
    if "root_detection" in results:
        print("\n🔍 ROOT DETECTION")
        print("-" * 30)
        root_detection = results["root_detection"]
        
        print(f"Root Status: {root_detection.get('root_status', 'Unknown')}")
        
        if "root_detection_mechanisms" in root_detection:
            print(f"Detection Mechanisms: {len(root_detection['root_detection_mechanisms'])}")
            for mechanism in root_detection["root_detection_mechanisms"]:
                print(f"  - {mechanism.get('indicator', 'Unknown')}: {mechanism.get('status', 'Unknown')}")
        
        if "security_issues" in root_detection:
            print(f"Security Issues: {len(root_detection['security_issues'])}")
            for issue in root_detection["security_issues"]:
                print(f"  ⚠️  {issue.get('description', 'Unknown issue')}")
    
    # Memory Tampering
    if "memory_tampering" in results:
        print("\n🛡️ MEMORY TAMPERING")
        print("-" * 30)
        memory_tampering = results["memory_tampering"]
        
        if "tampering_indicators" in memory_tampering:
            print(f"Tampering Indicators: {len(memory_tampering['tampering_indicators'])}")
            for indicator in memory_tampering["tampering_indicators"]:
                print(f"  - {indicator.get('indicator', 'Unknown')}: {indicator.get('status', 'Unknown')}")
        
        if "security_issues" in memory_tampering:
            print(f"Security Issues: {len(memory_tampering['security_issues'])}")
            for issue in memory_tampering["security_issues"]:
                print(f"  ⚠️  {issue.get('description', 'Unknown issue')}")
    
    # Runtime Security
    if "runtime_security" in results:
        print("\n🔒 RUNTIME SECURITY")
        print("-" * 30)
        runtime_security = results["runtime_security"]
        
        if "emulator_detection" in runtime_security:
            print(f"Emulator Detection: {len(runtime_security['emulator_detection'])}")
            for detection in runtime_security["emulator_detection"]:
                print(f"  - {detection.get('indicator', 'Unknown')}: {detection.get('status', 'Unknown')}")
        
        if "security_issues" in runtime_security:
            print(f"Security Issues: {len(runtime_security['security_issues'])}")
            for issue in runtime_security["security_issues"]:
                print(f"  ⚠️  {issue.get('description', 'Unknown issue')}")
    
    # Network Activity
    if "network_activity" in results:
        print("\n🌐 NETWORK ACTIVITY")
        print("-" * 30)
        network_activity = results["network_activity"]
        
        if "connections" in network_activity:
            print(f"Network Connections: {len(network_activity['connections'])}")
            for conn in network_activity["connections"][:5]:  # Show first 5
                print(f"  - {conn.get('protocol', 'Unknown')}: {conn.get('local_address', 'Unknown')}")
            if len(network_activity["connections"]) > 5:
                print(f"  ... and {len(network_activity['connections']) - 5} more")
    
    # File System
    if "file_system" in results:
        print("\n📁 FILE SYSTEM")
        print("-" * 30)
        file_system = results["file_system"]
        
        if "files_accessed" in file_system:
            print(f"Files Accessed: {len(file_system['files_accessed'])}")
            for file_info in file_system["files_accessed"][:5]:  # Show first 5
                print(f"  - {file_info.get('path', 'Unknown')}")
            if len(file_system["files_accessed"]) > 5:
                print(f"  ... and {len(file_system['files_accessed']) - 5} more")
    
    # Memory Analysis
    if "memory_analysis" in results:
        print("\n💾 MEMORY ANALYSIS")
        print("-" * 30)
        memory_analysis = results["memory_analysis"]
        
        if "memory_usage" in memory_analysis:
            print(f"Memory Usage: {memory_analysis['memory_usage'].get('total', 'Unknown')} MB")
        
        if "memory_leaks" in memory_analysis:
            print(f"Memory Leaks: {len(memory_analysis['memory_leaks'])}")
            for leak in memory_analysis["memory_leaks"]:
                print(f"  ⚠️  {leak.get('description', 'Unknown leak')}")
    
    # Vulnerabilities Summary
    if "vulnerabilities" in results:
        print("\n🚨 VULNERABILITIES SUMMARY")
        print("-" * 30)
        vulnerabilities = results["vulnerabilities"]
        
        severity_counts = {"high": 0, "medium": 0, "low": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "medium")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"Total Vulnerabilities: {len(vulnerabilities)}")
        print(f"  High: {severity_counts['high']}")
        print(f"  Medium: {severity_counts['medium']}")
        print(f"  Low: {severity_counts['low']}")
        
        # Show high severity vulnerabilities
        high_vulns = [v for v in vulnerabilities if v.get("severity") == "high"]
        if high_vulns:
            print("\nHigh Severity Vulnerabilities:")
            for vuln in high_vulns[:3]:  # Show first 3
                print(f"  🔴 {vuln.get('description', 'Unknown vulnerability')}")
            if len(high_vulns) > 3:
                print(f"  ... and {len(high_vulns) - 3} more high severity issues")
    
    # Recommendations
    if "recommendations" in results:
        print("\n💡 RECOMMENDATIONS")
        print("-" * 30)
        recommendations = results["recommendations"]
        
        for i, rec in enumerate(recommendations[:5], 1):  # Show first 5
            print(f"  {i}. {rec}")
        if len(recommendations) > 5:
            print(f"  ... and {len(recommendations) - 5} more recommendations")
    
    print("\n" + "="*60)

def save_results(results: dict, output_file: str):
    """Save results to JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n✅ Results saved to: {output_file}")
    except Exception as e:
        print(f"❌ Error saving results: {str(e)}")

if __name__ == "__main__":
    main() 