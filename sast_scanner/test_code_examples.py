#!/usr/bin/env python3
"""
Test script for vulnerable code examples and recommended fix code
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_code_examples():
    """Test that code examples are properly included in vulnerability detection."""
    
    # Sample vulnerable code with multiple issues
    vulnerable_code = """
import os
import subprocess
import hashlib
import random

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
    
    # Weak crypto
    hash_value = hashlib.md5(user_input.encode()).hexdigest()
    
    # Insecure random
    token = random.randint(1000, 9999)
    
    # Debug code
    print(f"User data: {user_input}")
    
    return "vulnerable"

# Eval usage
result = eval(user_input)

# Unsafe file operation
with open(user_input, 'w') as f:
    f.write("data")
"""

    print("🔍 Testing code examples in vulnerability detection...")
    
    try:
        from analyzers.vulnerability_detector import VulnerabilityDetector
        from analyzers.code_analyzer import CodeAnalyzer
        from report_generator import ReportGenerator
        
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
        
        # Check if code examples are present
        print(f"\n📋 Found {len(vulnerabilities)} vulnerabilities")
        
        code_examples_count = 0
        fix_examples_count = 0
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n--- Vulnerability {i} ---")
            print(f"Type: {vuln.get('type', 'N/A')}")
            print(f"Description: {vuln.get('description', 'N/A')}")
            print(f"Severity: {vuln.get('severity', 'N/A')}")
            
            # Check for code examples
            if vuln.get('vulnerable_code_example'):
                print(f"✅ Vulnerable Code Example: {vuln.get('vulnerable_code_example')[:50]}...")
                code_examples_count += 1
            else:
                print("❌ No vulnerable code example")
            
            if vuln.get('recommended_fix_code'):
                print(f"✅ Recommended Fix Code: {vuln.get('recommended_fix_code')[:50]}...")
                fix_examples_count += 1
            else:
                print("❌ No recommended fix code")
        
        print(f"\n📊 Summary:")
        print(f"Total vulnerabilities: {len(vulnerabilities)}")
        print(f"With vulnerable code examples: {code_examples_count}")
        print(f"With recommended fix code: {fix_examples_count}")
        
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
            
            # Check if code examples are in the report
            with open("test_report.md", "r", encoding="utf-8") as f:
                report_content = f.read()
                
            if "Vulnerable Code Example:" in report_content and "Recommended Fix:" in report_content:
                print("✅ Code examples found in markdown report!")
            else:
                print("❌ Code examples missing from markdown report")
                
        except Exception as e:
            print(f"❌ Error generating report: {e}")
        
        # Clean up
        if os.path.exists("test_report.md"):
            os.remove("test_report.md")
        
        print("\n🎉 Test completed!")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("This test requires the full SAST scanner dependencies.")

if __name__ == "__main__":
    test_code_examples() 