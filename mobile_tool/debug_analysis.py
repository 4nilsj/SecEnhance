#!/usr/bin/env python3
"""
Debug script to examine storage and code analysis results.
"""

import json
from src.mobile_security_tester import MobileSecurityTester

def debug_analysis():
    """Debug the analysis results."""
    print("🔍 Debugging Storage and Code Analysis Results")
    print("=" * 50)
    
    # Initialize tester
    tester = MobileSecurityTester(debug=True)
    
    # Run analysis
    print("Running analysis...")
    results = tester.analyze_apk('uploads/AndroGoat.apk', tests=['storage', 'code'])
    
    # Examine storage analysis
    print("\n📁 STORAGE ANALYSIS RESULTS:")
    print("-" * 30)
    storage_analysis = results.get('storage_analysis', {})
    print(f"Type: {type(storage_analysis)}")
    print(f"Keys: {list(storage_analysis.keys()) if isinstance(storage_analysis, dict) else 'Not a dict'}")
    print(f"Content: {json.dumps(storage_analysis, indent=2, default=str)}")
    
    # Check specific storage fields
    if isinstance(storage_analysis, dict):
        print(f"\nStorage Types: {storage_analysis.get('storage_types', 'Not found')}")
        print(f"Encryption: {storage_analysis.get('encryption', 'Not found')}")
        print(f"Error: {storage_analysis.get('error', 'No error')}")
        print(f"Message: {storage_analysis.get('message', 'No message')}")
    
    # Examine code analysis
    print("\n💻 CODE ANALYSIS RESULTS:")
    print("-" * 30)
    code_analysis = results.get('code_analysis', {})
    print(f"Type: {type(code_analysis)}")
    print(f"Keys: {list(code_analysis.keys()) if isinstance(code_analysis, dict) else 'Not a dict'}")
    print(f"Content: {json.dumps(code_analysis, indent=2, default=str)}")
    
    # Check specific code fields
    if isinstance(code_analysis, dict):
        print(f"\nHardcoded Secrets: {len(code_analysis.get('hardcoded_secrets', []))}")
        print(f"Injection Vulnerabilities: {len(code_analysis.get('injection_vulnerabilities', []))}")
        print(f"Authentication Issues: {len(code_analysis.get('authentication_issues', []))}")
        print(f"Cryptography Issues: {len(code_analysis.get('cryptography_issues', []))}")
        print(f"Error: {code_analysis.get('error', 'No error')}")
        print(f"Message: {code_analysis.get('message', 'No message')}")
    
    # Check vulnerabilities
    print("\n🚨 VULNERABILITIES:")
    print("-" * 30)
    vulnerabilities = results.get('vulnerabilities', [])
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    
    # Categorize by source
    storage_vulns = [v for v in vulnerabilities if 'storage' in v.get('type', '').lower()]
    code_vulns = [v for v in vulnerabilities if 'code' in v.get('type', '').lower() or 'crypto' in v.get('type', '').lower()]
    
    print(f"Storage-related vulnerabilities: {len(storage_vulns)}")
    print(f"Code-related vulnerabilities: {len(code_vulns)}")
    
    if storage_vulns:
        print("\nStorage vulnerabilities:")
        for v in storage_vulns[:3]:
            print(f"  - {v.get('type', 'Unknown')}: {v.get('description', 'No description')}")
    
    if code_vulns:
        print("\nCode vulnerabilities:")
        for v in code_vulns[:3]:
            print(f"  - {v.get('type', 'Unknown')}: {v.get('description', 'No description')}")

if __name__ == "__main__":
    debug_analysis() 