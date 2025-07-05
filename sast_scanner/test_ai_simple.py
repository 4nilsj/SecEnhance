#!/usr/bin/env python3
"""
Simple test for AI-powered code fixing functionality
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_ai_code_fixer_directly():
    """Test the AI code fixer directly."""
    
    print("🤖 Testing AI Code Fixer directly...")
    
    try:
        # Import the AI code fixer
        sys.path.insert(0, str(Path(__file__).parent / "src" / "analyzers"))
        from ai_code_fixer import AICodeFixer
        
        # Initialize AI code fixer
        ai_fixer = AICodeFixer(debug=True)
        
        # Test vulnerable code
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
        
        # Create a mock vulnerability
        mock_vulnerability = {
            "type": "sql_injection",
            "description": "SQL Injection vulnerability",
            "severity": "high",
            "line_number": 5,
            "line_content": "query = f\"SELECT * FROM users WHERE id = {user_input}\"",
            "pattern_match": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_input}\")",
            "mitigation": "Use parameterized queries",
            "cwe": "CWE-89",
            "confidence": 0.9,
            "detection_method": "pattern_matching",
            "impact": "Allows SQL injection attacks",
            "potential_fix": "Use parameterized queries",
            "false_positive_summary": "Pattern matches SQL injection risk"
        }
        
        print("📊 Testing vulnerability enhancement...")
        
        # Test the enhance_vulnerabilities_with_fixes method
        enhanced_vulns = ai_fixer.enhance_vulnerabilities_with_fixes(
            [mock_vulnerability], vulnerable_code, "test_file.py"
        )
        
        if enhanced_vulns:
            enhanced_vuln = enhanced_vulns[0]
            print("✅ Successfully enhanced vulnerability with AI fixes!")
            
            print(f"\n📝 Results:")
            print(f"Vulnerability Type: {enhanced_vuln.get('type')}")
            print(f"Severity: {enhanced_vuln.get('severity')}")
            
            # Check for actual vulnerable code
            if enhanced_vuln.get('actual_vulnerable_code'):
                print(f"✅ Actual Vulnerable Code (POC):")
                print(f"   {enhanced_vuln.get('actual_vulnerable_code')}")
            else:
                print("❌ No actual vulnerable code extracted")
            
            # Check for AI-generated specific fix
            if enhanced_vuln.get('specific_fix_code'):
                confidence = enhanced_vuln.get('fix_confidence', 0.0)
                print(f"✅ AI-Generated Fix (Confidence: {confidence*100:.1f}%):")
                print(f"   {enhanced_vuln.get('specific_fix_code')}")
                print(f"   Explanation: {enhanced_vuln.get('fix_explanation')}")
            else:
                print("❌ No AI-generated fix")
            
            # Check for fix confidence
            confidence = enhanced_vuln.get('fix_confidence', 0.0)
            print(f"Fix Confidence: {confidence*100:.1f}%")
            
        else:
            print("❌ No enhanced vulnerabilities returned")
        
        # Test multiple vulnerability types
        print("\n🔍 Testing multiple vulnerability types...")
        
        test_vulnerabilities = [
            {
                "type": "sql_injection",
                "line_number": 5,
                "pattern_match": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_input}\")"
            },
            {
                "type": "command_injection", 
                "line_number": 8,
                "pattern_match": "os.system(f\"echo {user_input}\")"
            },
            {
                "type": "hardcoded_credentials",
                "line_number": 14,
                "pattern_match": "password = \"secret123\""
            }
        ]
        
        enhanced_multi = ai_fixer.enhance_vulnerabilities_with_fixes(
            test_vulnerabilities, vulnerable_code, "test_file.py"
        )
        
        print(f"Enhanced {len(enhanced_multi)} vulnerabilities")
        
        for i, vuln in enumerate(enhanced_multi, 1):
            print(f"\n--- Vulnerability {i} ---")
            print(f"Type: {vuln.get('type')}")
            if vuln.get('specific_fix_code'):
                print(f"AI Fix: {vuln.get('specific_fix_code')[:60]}...")
            if vuln.get('actual_vulnerable_code'):
                print(f"Actual Code: {vuln.get('actual_vulnerable_code')[:60]}...")
        
        print("\n🎉 AI Code Fixer test completed successfully!")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Trying alternative import method...")
        
        try:
            # Try direct import
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "ai_code_fixer", 
                Path(__file__).parent / "src" / "analyzers" / "ai_code_fixer.py"
            )
            ai_code_fixer_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(ai_code_fixer_module)
            
            print("✅ Successfully imported AI code fixer module")
            
        except Exception as e2:
            print(f"❌ Alternative import also failed: {e2}")
    
    except Exception as e:
        print(f"❌ Error during testing: {e}")

def test_code_extraction():
    """Test code extraction functionality."""
    
    print("\n📝 Testing code extraction...")
    
    test_code = """
def vulnerable_function(user_input):
    # This is a vulnerable line
    query = f"SELECT * FROM users WHERE id = {user_input}"
    cursor.execute(query)
    
    # Another vulnerable line
    os.system(f"echo {user_input}")
    
    return "done"
"""
    
    try:
        sys.path.insert(0, str(Path(__file__).parent / "src" / "analyzers"))
        from ai_code_fixer import AICodeFixer
        
        ai_fixer = AICodeFixer(debug=True)
        
        # Test code extraction
        extracted_code = ai_fixer.extract_vulnerable_code_context(
            test_code, 3, "query = f\"SELECT * FROM users WHERE id = {user_input}\"", "python"
        )
        
        print("✅ Code extraction test:")
        print(f"Extracted code context:")
        print(extracted_code)
        
    except Exception as e:
        print(f"❌ Code extraction test failed: {e}")

if __name__ == "__main__":
    test_ai_code_fixer_directly()
    test_code_extraction() 