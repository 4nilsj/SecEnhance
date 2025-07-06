#!/usr/bin/env python3
"""
Test script for the new vulnerability fields (impact, potential_fix, false_positive_summary)
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from analyzers.vulnerability_detector import VulnerabilityDetector
from analyzers.code_analyzer import CodeAnalyzer
from report_generator import ReportGenerator

def test_new_fields():
    """Test that the new fields are properly included in vulnerability detection."""
    
    # Sample vulnerable code
    vulnerable_code = """
import os
import subprocess

def vulnerable_function(user_input):
    # SQL Injection
    query = f"SELECT * FROM users WHERE id = {user_input}"
    cursor.execute(query)
    
    # Command Injection
    os.system(f"echo {user_input}")
    
    # XSS
    html_content = f"<div>{user_input}</div>"
    
    # Hardcoded credentials
    password = "secret123"
    api_key = "sk-1234567890abcdef"
    
    return "vulnerable"
"""

    print("🔍 Testing new vulnerability fields...")
    
    # Initialize components
    detector = VulnerabilityDetector(debug=True)
    code_analyzer = CodeAnalyzer(debug=True)
    report_generator = ReportGenerator(debug=True)
    
    # Analyze code
    print("📊 Analyzing code...")
    code_analysis = code_analyzer.analyze_code(vulnerable_code, "test_file.py")
    
    # Detect vulnerabilities
    print("🚨 Detecting vulnerabilities...")
    vulnerabilities = detector.detect_vulnerabilities(vulnerable_code, "test_file.py", code_analysis)
    
    # Check if new fields are present
    print(f"\n📋 Found {len(vulnerabilities)} vulnerabilities")
    
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\n--- Vulnerability {i} ---")
        print(f"Type: {vuln.get('type', 'N/A')}")
        print(f"Description: {vuln.get('description', 'N/A')}")
        print(f"Severity: {vuln.get('severity', 'N/A')}")
        print(f"Line: {vuln.get('line_number', 'N/A')}")
        print(f"File: {vuln.get('file_name', 'N/A')}")
        
        # Check new fields
        print(f"✅ Impact: {vuln.get('impact', 'MISSING')}")
        print(f"✅ Potential Fix: {vuln.get('potential_fix', 'MISSING')}")
        print(f"✅ False Positive Summary: {vuln.get('false_positive_summary', 'MISSING')}")
        
        # Check if fields are missing
        missing_fields = []
        if not vuln.get('impact'):
            missing_fields.append('impact')
        if not vuln.get('potential_fix'):
            missing_fields.append('potential_fix')
        if not vuln.get('false_positive_summary'):
            missing_fields.append('false_positive_summary')
        
        if missing_fields:
            print(f"❌ Missing fields: {', '.join(missing_fields)}")
        else:
            print("✅ All new fields present!")
    
    # Test report generation
    print("\n📄 Testing report generation...")
    scan_results = {
        "summary": {
            "total_files": 1,
            "total_vulnerabilities": len(vulnerabilities),
            "files_with_vulnerabilities": 1,
            "severity_breakdown": {
                "high": len([v for v in vulnerabilities if v.get('severity') == 'high']),
                "medium": len([v for v in vulnerabilities if v.get('severity') == 'medium']),
                "low": len([v for v in vulnerabilities if v.get('severity') == 'low'])
            }
        },
        "vulnerabilities": vulnerabilities,
        "ai_insights": []
    }
    
    # Generate markdown report
    try:
        markdown_report = report_generator.generate_report(scan_results, "markdown", "test_report.md")
        print(f"✅ Markdown report generated: {markdown_report}")
        
        # Check if new fields are in the report
        with open("test_report.md", "r", encoding="utf-8") as f:
            report_content = f.read()
            
        if "Impact:" in report_content and "Potential Fix:" in report_content and "False Positive Summary:" in report_content:
            print("✅ New fields found in markdown report!")
        else:
            print("❌ New fields missing from markdown report")
            
    except Exception as e:
        print(f"❌ Error generating report: {e}")
    
    # Clean up
    if os.path.exists("test_report.md"):
        os.remove("test_report.md")
    
    print("\n🎉 Test completed!")

if __name__ == "__main__":
    test_new_fields() 