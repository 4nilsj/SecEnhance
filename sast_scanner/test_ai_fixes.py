#!/usr/bin/env python3
"""
Test script for AI-powered code fixing functionality
Tests actual vulnerable code extraction and AI-generated specific fixes
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_ai_code_fixing():
    """Test AI-powered code fixing functionality."""
    
    # Sample vulnerable code with multiple real-world issues
    vulnerable_code = """
import os
import subprocess
import hashlib
import random
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

def vulnerable_sql_function(user_id):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def vulnerable_command_function(command):
    # Command Injection vulnerability
    os.system(f"echo {command}")
    subprocess.call(f"ls {command}", shell=True)
    return "command executed"

def vulnerable_xss_function(user_input):
    # XSS vulnerability
    html_content = f"<div>{user_input}</div>"
    return render_template_string(f"<h1>{user_input}</h1>")

def vulnerable_crypto_function(data):
    # Weak crypto vulnerability
    hash_value = hashlib.md5(data.encode()).hexdigest()
    return hash_value

def vulnerable_random_function():
    # Insecure random vulnerability
    token = random.randint(1000, 9999)
    return str(token)

def vulnerable_credentials():
    # Hardcoded credentials
    password = "super_secret_password_123"
    api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
    database_url = "postgresql://user:password@localhost/db"
    return {"password": password, "api_key": api_key}

# Eval usage vulnerability
def dangerous_eval_function(user_input):
    result = eval(user_input)
    return result

# Unsafe file operation
def unsafe_file_operation(filename):
    with open(filename, 'w') as f:
        f.write("sensitive data")
    return "file written"

if __name__ == "__main__":
    app.run(debug=True)
"""

    print("🤖 Testing AI-powered code fixing functionality...")
    
    try:
        from analyzers.vulnerability_detector import VulnerabilityDetector
        from analyzers.code_analyzer import CodeAnalyzer
        from analyzers.ai_code_fixer import AICodeFixer
        from report_generator import ReportGenerator
        
        # Initialize components
        detector = VulnerabilityDetector(debug=True)
        code_analyzer = CodeAnalyzer(debug=True)
        ai_fixer = AICodeFixer(debug=True)
        report_generator = ReportGenerator(debug=True)
        
        # Analyze code
        print("📊 Analyzing vulnerable code...")
        code_analysis = code_analyzer.analyze_code(vulnerable_code, "vulnerable_app.py")
        
        # Detect vulnerabilities
        print("🚨 Detecting vulnerabilities...")
        vulnerabilities = detector.detect_vulnerabilities(vulnerable_code, "vulnerable_app.py", code_analysis)
        
        # Test AI code fixer directly
        print("🔧 Testing AI code fixer...")
        enhanced_vulnerabilities = ai_fixer.enhance_vulnerabilities_with_fixes(
            vulnerabilities, vulnerable_code, "vulnerable_app.py"
        )
        
        print(f"\n📋 Found {len(enhanced_vulnerabilities)} vulnerabilities with AI fixes")
        
        # Analyze results
        ai_fixes_count = 0
        actual_code_count = 0
        
        for i, vuln in enumerate(enhanced_vulnerabilities, 1):
            print(f"\n--- Vulnerability {i} ---")
            print(f"Type: {vuln.get('type', 'N/A')}")
            print(f"Description: {vuln.get('description', 'N/A')}")
            print(f"Severity: {vuln.get('severity', 'N/A')}")
            print(f"Line: {vuln.get('line_number', 'N/A')}")
            
            # Check for actual vulnerable code
            if vuln.get('actual_vulnerable_code'):
                print(f"✅ Actual Vulnerable Code (POC):")
                print(f"   {vuln.get('actual_vulnerable_code')[:100]}...")
                actual_code_count += 1
            else:
                print("❌ No actual vulnerable code extracted")
            
            # Check for AI-generated specific fix
            if vuln.get('specific_fix_code'):
                confidence = vuln.get('fix_confidence', 0.0)
                print(f"✅ AI-Generated Fix (Confidence: {confidence*100:.1f}%):")
                print(f"   {vuln.get('specific_fix_code')[:100]}...")
                print(f"   Explanation: {vuln.get('fix_explanation', 'N/A')}")
                ai_fixes_count += 1
            else:
                print("❌ No AI-generated fix")
        
        print(f"\n📊 Summary:")
        print(f"Total vulnerabilities: {len(enhanced_vulnerabilities)}")
        print(f"With actual vulnerable code: {actual_code_count}")
        print(f"With AI-generated fixes: {ai_fixes_count}")
        
        # Test report generation
        print("\n📄 Testing report generation with AI fixes...")
        scan_results = {
            "summary": {
                "total_files": 1,
                "total_vulnerabilities": len(enhanced_vulnerabilities),
                "files_with_vulnerabilities": 1,
                "severity_breakdown": {
                    "high": len([v for v in enhanced_vulnerabilities if v.get('severity') == 'high']),
                    "medium": len([v for v in enhanced_vulnerabilities if v.get('severity') == 'medium']),
                    "low": len([v for v in enhanced_vulnerabilities if v.get('severity') == 'low'])
                }
            },
            "vulnerabilities": enhanced_vulnerabilities,
            "ai_insights": []
        }
        
        # Generate markdown report
        try:
            markdown_report = report_generator.generate_report(scan_results, "markdown", "ai_fixes_report.md")
            print(f"✅ Markdown report generated: {markdown_report}")
            
            # Check if AI fixes are in the report
            with open("ai_fixes_report.md", "r", encoding="utf-8") as f:
                report_content = f.read()
                
            if "Actual Vulnerable Code (POC):" in report_content and "AI-Generated Fix" in report_content:
                print("✅ AI fixes found in markdown report!")
            else:
                print("❌ AI fixes missing from markdown report")
                
            # Generate HTML report
            html_report = report_generator.generate_report(scan_results, "html", "ai_fixes_report.html")
            print(f"✅ HTML report generated: {html_report}")
            
        except Exception as e:
            print(f"❌ Error generating report: {e}")
        
        # Clean up
        for file in ["ai_fixes_report.md", "ai_fixes_report.html"]:
            if os.path.exists(file):
                os.remove(file)
        
        print("\n🎉 AI-powered code fixing test completed!")
        
        # Show sample results
        if enhanced_vulnerabilities:
            print("\n📝 Sample AI Fix Results:")
            sample_vuln = enhanced_vulnerabilities[0]
            print(f"Vulnerability: {sample_vuln.get('type')}")
            print(f"Actual Code: {sample_vuln.get('actual_vulnerable_code', 'N/A')[:80]}...")
            print(f"AI Fix: {sample_vuln.get('specific_fix_code', 'N/A')[:80]}...")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("This test requires the full SAST scanner dependencies.")

def test_specific_vulnerability_types():
    """Test specific vulnerability types with AI fixes."""
    
    print("\n🔍 Testing specific vulnerability types...")
    
    test_cases = [
        {
            "name": "SQL Injection",
            "code": """
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
""",
            "file": "sql_test.py"
        },
        {
            "name": "XSS",
            "code": """
def display_user(user_input):
    html = f"<div>{user_input}</div>"
    return html
""",
            "file": "xss_test.py"
        },
        {
            "name": "Command Injection",
            "code": """
def run_command(command):
    os.system(f"echo {command}")
    return "done"
""",
            "file": "cmd_test.py"
        }
    ]
    
    try:
        from analyzers.vulnerability_detector import VulnerabilityDetector
        from analyzers.code_analyzer import CodeAnalyzer
        from analyzers.ai_code_fixer import AICodeFixer
        
        detector = VulnerabilityDetector(debug=True)
        code_analyzer = CodeAnalyzer(debug=True)
        ai_fixer = AICodeFixer(debug=True)
        
        for test_case in test_cases:
            print(f"\n--- Testing {test_case['name']} ---")
            
            code_analysis = code_analyzer.analyze_code(test_case['code'], test_case['file'])
            vulnerabilities = detector.detect_vulnerabilities(test_case['code'], test_case['file'], code_analysis)
            enhanced_vulns = ai_fixer.enhance_vulnerabilities_with_fixes(
                vulnerabilities, test_case['code'], test_case['file']
            )
            
            if enhanced_vulns:
                vuln = enhanced_vulns[0]
                print(f"✅ Found: {vuln.get('type')}")
                print(f"   Actual Code: {vuln.get('actual_vulnerable_code', 'N/A')[:60]}...")
                print(f"   AI Fix: {vuln.get('specific_fix_code', 'N/A')[:60]}...")
            else:
                print("❌ No vulnerabilities detected")
    
    except ImportError as e:
        print(f"❌ Import error: {e}")

if __name__ == "__main__":
    test_ai_code_fixing()
    test_specific_vulnerability_types() 