#!/usr/bin/env python3
"""
Debug script to examine network analysis results.
"""

import json
from src.mobile_security_tester import MobileSecurityTester

def debug_network_analysis():
    """Debug the network analysis results."""
    print("🔍 Debugging Network Analysis Results")
    print("=" * 50)
    
    # Initialize tester
    tester = MobileSecurityTester(debug=True)
    
    # Run analysis
    print("Running network analysis...")
    results = tester.analyze_apk('uploads/AndroGoat.apk', tests=['network'])
    
    # Examine network analysis
    print("\n🌐 NETWORK ANALYSIS RESULTS:")
    print("-" * 30)
    network_analysis = results.get('network_analysis', {})
    print(f"Type: {type(network_analysis)}")
    print(f"Keys: {list(network_analysis.keys()) if isinstance(network_analysis, dict) else 'Not a dict'}")
    print(f"Content: {json.dumps(network_analysis, indent=2, default=str)}")
    
    # Check specific network fields
    if isinstance(network_analysis, dict):
        print(f"\nAPI Endpoints: {len(network_analysis.get('api_endpoints', []))}")
        print(f"Network Config: {network_analysis.get('network_config', 'Not found')}")
        print(f"SSL/TLS Analysis: {network_analysis.get('ssl_tls_analysis', 'Not found')}")
        print(f"Certificate Pinning: {network_analysis.get('certificate_pinning', 'Not found')}")
        print(f"Error: {network_analysis.get('error', 'No error')}")
        print(f"Message: {network_analysis.get('message', 'No message')}")
        
        # Show API endpoints if any
        api_endpoints = network_analysis.get('api_endpoints', [])
        if api_endpoints:
            print("\nAPI Endpoints found:")
            for ep in api_endpoints[:5]:  # Show first 5
                print(f"  - {ep.get('endpoint', 'Unknown')} (Secure: {ep.get('secure', 'Unknown')})")
        else:
            print("\nNo API endpoints found")
    
    # Check vulnerabilities
    print("\n🚨 NETWORK VULNERABILITIES:")
    print("-" * 30)
    vulnerabilities = results.get('vulnerabilities', [])
    network_vulns = [v for v in vulnerabilities if 'network' in v.get('type', '').lower() or 'ssl' in v.get('type', '').lower() or 'http' in v.get('type', '').lower()]
    
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    print(f"Network-related vulnerabilities: {len(network_vulns)}")
    
    if network_vulns:
        print("\nNetwork vulnerabilities:")
        for v in network_vulns[:5]:
            print(f"  - {v.get('type', 'Unknown')}: {v.get('description', 'No description')}")

if __name__ == "__main__":
    debug_network_analysis() 