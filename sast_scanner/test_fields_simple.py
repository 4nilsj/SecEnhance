#!/usr/bin/env python3
"""
Simple test to verify new vulnerability fields are present in rules
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_vulnerability_rules():
    """Test that vulnerability rules contain the new fields."""
    
    # Import the vulnerability detector class
    try:
        from analyzers.vulnerability_detector import VulnerabilityDetector
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return
    
    print("🔍 Testing vulnerability rules for new fields...")
    
    # Create detector instance
    detector = VulnerabilityDetector(debug=False)
    
    # Check vulnerability rules
    print(f"\n📋 Checking {len(detector.vulnerability_rules)} vulnerability rules...")
    
    missing_fields = []
    all_fields_present = True
    
    for vuln_type, rule in detector.vulnerability_rules.items():
        print(f"\n--- {vuln_type} ---")
        
        # Check required fields
        required_fields = ['impact', 'potential_fix', 'false_positive_summary']
        rule_missing = []
        
        for field in required_fields:
            if field not in rule or not rule[field]:
                rule_missing.append(field)
                all_fields_present = False
        
        if rule_missing:
            print(f"❌ Missing fields: {', '.join(rule_missing)}")
            missing_fields.append((vuln_type, rule_missing))
        else:
            print("✅ All new fields present!")
            print(f"   Impact: {rule['impact'][:50]}...")
            print(f"   Fix: {rule['potential_fix'][:50]}...")
            print(f"   FP Summary: {rule['false_positive_summary'][:50]}...")
    
    # Summary
    print(f"\n📊 Summary:")
    print(f"Total rules: {len(detector.vulnerability_rules)}")
    print(f"Rules with all fields: {len(detector.vulnerability_rules) - len(missing_fields)}")
    print(f"Rules missing fields: {len(missing_fields)}")
    
    if missing_fields:
        print(f"\n❌ Rules with missing fields:")
        for vuln_type, fields in missing_fields:
            print(f"   {vuln_type}: {', '.join(fields)}")
    else:
        print("✅ All rules have the new fields!")
    
    return all_fields_present

def test_language_specific_rules():
    """Test language-specific rules for new fields."""
    
    try:
        from analyzers.vulnerability_detector import VulnerabilityDetector
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return
    
    print("\n🔍 Testing language-specific rules...")
    
    detector = VulnerabilityDetector(debug=False)
    
    if not hasattr(detector, 'language_specific_rules'):
        print("❌ No language-specific rules found")
        return
    
    print(f"📋 Found {len(detector.language_specific_rules)} language types")
    
    for lang, rules in detector.language_specific_rules.items():
        print(f"\n--- {lang} ---")
        print(f"Rules: {len(rules)}")
        
        missing_fields = []
        for rule_name, rule in rules.items():
            required_fields = ['impact', 'potential_fix', 'false_positive_summary']
            for field in required_fields:
                if field not in rule or not rule[field]:
                    missing_fields.append(f"{rule_name}.{field}")
        
        if missing_fields:
            print(f"❌ Missing fields: {', '.join(missing_fields)}")
        else:
            print("✅ All rules have new fields!")

if __name__ == "__main__":
    print("🚀 Starting vulnerability fields test...")
    
    # Test main vulnerability rules
    main_rules_ok = test_vulnerability_rules()
    
    # Test language-specific rules
    test_language_specific_rules()
    
    if main_rules_ok:
        print("\n🎉 All tests passed! New fields are properly implemented.")
    else:
        print("\n❌ Some tests failed. Check the missing fields above.") 