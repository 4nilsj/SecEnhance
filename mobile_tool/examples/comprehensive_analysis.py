#!/usr/bin/env python3
"""
Comprehensive Mobile Security Analysis Example
Demonstrates how to perform comprehensive security analysis on mobile applications.
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mobile_security_tester import MobileSecurityTester

def main():
    """Run comprehensive mobile security analysis example."""
    print("🔍 Mobile Security Testing Tool - Comprehensive Analysis")
    print("=" * 70)
    
    # Check if file is provided
    if len(sys.argv) < 2:
        print("Usage: python comprehensive_analysis.py <apk_file|ipa_file>")
        print("Example: python comprehensive_analysis.py sample_app.apk")
        print("Example: python comprehensive_analysis.py sample_app.ipa")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"❌ Error: File not found: {file_path}")
        sys.exit(1)
    
    # Determine file type
    file_ext = Path(file_path).suffix.lower()
    if file_ext not in ['.apk', '.ipa']:
        print(f"❌ Error: Unsupported file type: {file_ext}")
        print("Supported types: .apk (Android), .ipa (iOS)")
        sys.exit(1)
    
    try:
        # Initialize the security tester with custom config
        print(f"📱 Initializing security tester...")
        tester = MobileSecurityTester(debug=True)
        
        # Perform comprehensive analysis
        print(f"🔍 Performing comprehensive analysis: {file_path}")
        print("-" * 50)
        
        if file_ext == '.apk':
            # Android APK analysis
            print("📱 Analyzing Android APK...")
            results = tester.analyze_apk(file_path, tests=["static", "dynamic", "network", "storage", "code"])
        else:
            # iOS IPA analysis
            print("🍎 Analyzing iOS IPA...")
            results = tester.analyze_ipa(file_path, tests=["static", "network", "storage", "code"])
        
        # Print summary
        print("\n📊 Analysis Summary:")
        print("-" * 50)
        tester.print_summary()
        
        # Generate multiple report formats
        print("\n📄 Generating reports...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"comprehensive_analysis_{Path(file_path).stem}_{timestamp}"
        
        # Generate JSON report
        json_report = tester.generate_report(
            output_file=f"{base_name}.json",
            format="json"
        )
        print(f"📄 JSON Report: {json_report}")
        
        # Generate HTML report
        html_report = tester.generate_report(
            output_file=f"{base_name}.html",
            format="html"
        )
        print(f"📄 HTML Report: {html_report}")
        
        # Generate CSV report
        csv_report = tester.generate_report(
            output_file=f"{base_name}.csv",
            format="csv"
        )
        print(f"📄 CSV Report: {csv_report}")
        
        print(f"\n✅ Comprehensive analysis completed successfully!")
        
        # Detailed analysis results
        print("\n🔍 Detailed Analysis Results:")
        print("-" * 50)
        
        # Static Analysis Results
        static_analysis = results.get("static_analysis", {})
        if static_analysis:
            print("\n📋 Static Analysis:")
            print(f"  • File Type: {static_analysis.get('file_info', {}).get('file_type', 'Unknown')}")
            print(f"  • File Size: {static_analysis.get('file_info', {}).get('file_size', 0)} bytes")
            
            permissions = static_analysis.get("permissions", [])
            if permissions:
                print(f"  • Permissions: {len(permissions)} total")
                dangerous_perms = [p for p in permissions if p.get("severity") in ["high", "critical"]]
                if dangerous_perms:
                    print(f"  • Dangerous Permissions: {len(dangerous_perms)}")
                    for perm in dangerous_perms[:3]:
                        print(f"    - {perm.get('permission', 'Unknown')} ({perm.get('severity', 'Unknown')})")
            
            components = static_analysis.get("components", {})
            if components:
                print(f"  • Activities: {len(components.get('activities', []))}")
                print(f"  • Services: {len(components.get('services', []))}")
                print(f"  • Receivers: {len(components.get('receivers', []))}")
                print(f"  • Providers: {len(components.get('providers', []))}")
        
        # Network Analysis Results
        network_analysis = results.get("network_analysis", {})
        if network_analysis:
            print("\n🌐 Network Analysis:")
            api_endpoints = network_analysis.get("api_endpoints", [])
            print(f"  • API Endpoints: {len(api_endpoints)} found")
            
            ssl_analysis = network_analysis.get("ssl_tls_analysis", {})
            if ssl_analysis:
                print(f"  • SSL/TLS Certificate Validation: {'Enabled' if ssl_analysis.get('certificate_validation') else 'Disabled'}")
        
        # Storage Analysis Results
        storage_analysis = results.get("storage_analysis", {})
        if storage_analysis:
            print("\n💾 Storage Analysis:")
            encryption = storage_analysis.get("encryption_analysis", {})
            print(f"  • Encryption Used: {'Yes' if encryption.get('encryption_used') else 'No'}")
            
            backup = storage_analysis.get("backup_analysis", {})
            print(f"  • Backup Enabled: {'Yes' if backup.get('backup_enabled') else 'No'}")
        
        # Code Analysis Results
        code_analysis = results.get("code_analysis", {})
        if code_analysis:
            print("\n💻 Code Analysis:")
            code_quality = code_analysis.get("code_quality", {})
            print(f"  • Total Files: {code_quality.get('total_files', 0)}")
            print(f"  • Java Files: {code_quality.get('java_files', 0)}")
            print(f"  • Kotlin Files: {code_quality.get('kotlin_files', 0)}")
            
            hardcoded_secrets = code_analysis.get("hardcoded_secrets", [])
            print(f"  • Hardcoded Secrets: {len(hardcoded_secrets)} found")
        
        # Vulnerability Summary
        print("\n🚨 Vulnerability Summary:")
        print("-" * 50)
        
        summary = results.get("summary", {})
        print(f"  • Overall Risk Level: {summary.get('overall_risk', 'Unknown')}")
        print(f"  • Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"  • Critical: {summary.get('critical', 0)}")
        print(f"  • High: {summary.get('high', 0)}")
        print(f"  • Medium: {summary.get('medium', 0)}")
        print(f"  • Low: {summary.get('low', 0)}")
        
        # Top vulnerabilities by severity
        vulnerabilities = results.get("vulnerabilities", [])
        if vulnerabilities:
            print("\n🔴 Critical Vulnerabilities:")
            critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]
            for vuln in critical_vulns[:3]:
                print(f"  • {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
            
            print("\n🟠 High Severity Vulnerabilities:")
            high_vulns = [v for v in vulnerabilities if v.get("severity") == "high"]
            for vuln in high_vulns[:3]:
                print(f"  • {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
        
        # Recommendations
        recommendations = results.get("recommendations", [])
        if recommendations:
            print("\n💡 Security Recommendations:")
            print("-" * 50)
            for i, rec in enumerate(recommendations[:10], 1):
                print(f"  {i}. {rec}")
        
        # Save detailed results to JSON
        detailed_results_file = f"{base_name}_detailed.json"
        with open(detailed_results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n📄 Detailed results saved: {detailed_results_file}")
        
        # Risk assessment
        print("\n⚠️  Risk Assessment:")
        print("-" * 50)
        overall_risk = summary.get('overall_risk', 'Unknown')
        if overall_risk == 'Critical':
            print("🔴 CRITICAL RISK: Immediate action required!")
            print("   • Multiple critical vulnerabilities detected")
            print("   • Application should not be deployed")
        elif overall_risk == 'High':
            print("🟠 HIGH RISK: Urgent attention required!")
            print("   • Several high-severity vulnerabilities detected")
            print("   • Fix vulnerabilities before deployment")
        elif overall_risk == 'Medium':
            print("🟡 MEDIUM RISK: Attention required!")
            print("   • Some security issues detected")
            print("   • Review and fix important vulnerabilities")
        elif overall_risk == 'Low':
            print("🟢 LOW RISK: Generally secure!")
            print("   • Few security issues detected")
            print("   • Minor improvements recommended")
        else:
            print("🟢 SECURE: No significant vulnerabilities detected!")
            print("   • Application appears to be secure")
            print("   • Continue with security best practices")
        
    except Exception as e:
        print(f"❌ Error during comprehensive analysis: {str(e)}")
        if "--debug" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 