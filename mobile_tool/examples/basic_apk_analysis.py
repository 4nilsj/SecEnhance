#!/usr/bin/env python3
"""
Basic APK Analysis Example
Demonstrates how to perform basic security analysis on an APK file.
"""

import sys
import os
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mobile_security_tester import MobileSecurityTester

def main():
    """Run basic APK analysis example."""
    print("🔍 Mobile Security Testing Tool - Basic APK Analysis")
    print("=" * 60)
    
    # Check if APK file is provided
    if len(sys.argv) < 2:
        print("Usage: python basic_apk_analysis.py <apk_file>")
        print("Example: python basic_apk_analysis.py sample_app.apk")
        sys.exit(1)
    
    apk_file = sys.argv[1]
    
    # Check if file exists
    if not os.path.exists(apk_file):
        print(f"❌ Error: APK file not found: {apk_file}")
        sys.exit(1)
    
    try:
        # Initialize the security tester
        print(f"📱 Initializing security tester...")
        tester = MobileSecurityTester(debug=True)
        
        # Perform basic analysis
        print(f"🔍 Analyzing APK: {apk_file}")
        print("-" * 40)
        
        # Run static analysis only for basic example
        results = tester.analyze_apk(apk_file, tests=["static", "code", "storage"])
        
        # Print summary
        print("\n📊 Analysis Summary:")
        print("-" * 40)
        tester.print_summary()
        
        # Generate report
        print("\n📄 Generating report...")
        report_file = tester.generate_report(
            output_file=f"basic_analysis_{Path(apk_file).stem}.html",
            format="html"
        )
        
        print(f"✅ Analysis completed successfully!")
        print(f"📄 Report saved: {report_file}")
        
        # Print some key findings
        print("\n🔍 Key Findings:")
        print("-" * 40)
        
        summary = results.get("summary", {})
        print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"Critical: {summary.get('critical', 0)}")
        print(f"High: {summary.get('high', 0)}")
        print(f"Medium: {summary.get('medium', 0)}")
        print(f"Low: {summary.get('low', 0)}")
        
        # Show top vulnerabilities
        vulnerabilities = results.get("vulnerabilities", [])
        if vulnerabilities:
            print(f"\n🚨 Top Vulnerabilities:")
            for i, vuln in enumerate(vulnerabilities[:5], 1):
                print(f"{i}. {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Unknown')})")
                print(f"   {vuln.get('description', 'No description')}")
        
        # Show recommendations
        recommendations = results.get("recommendations", [])
        if recommendations:
            print(f"\n💡 Top Recommendations:")
            for i, rec in enumerate(recommendations[:5], 1):
                print(f"{i}. {rec}")
        
    except Exception as e:
        print(f"❌ Error during analysis: {str(e)}")
        if "--debug" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 