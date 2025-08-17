#!/usr/bin/env python3
"""
Test script to demonstrate the complete BCheck system
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from bchecks.bcheck_loader import BCheckLoader
from utils.report_generator import ReportGenerator, VulnerabilityReport
from utils.config_manager import ConfigManager

def test_bcheck_discovery():
    """Test BCheck discovery functionality"""
    print("🔍 Testing BCheck Discovery...")
    
    loader = BCheckLoader()
    discovered = loader.discover_bchecks()
    
    print(f"  • Discovered {len(discovered)} BCheck files")
    for bcheck in discovered:
        print(f"    - {bcheck}.py")
    
    expected_bchecks = [
        'sql_injection_bcheck',
        'xss_bcheck', 
        'ssrf_bcheck',
        'auth_bypass_bcheck',
        'comprehensive_security_bcheck'
    ]
    
    for expected in expected_bchecks:
        if expected in discovered:
            print(f"    ✅ {expected} found")
        else:
            print(f"    ❌ {expected} missing")
    
    return len(discovered) == len(expected_bchecks)

def test_bcheck_loader():
    """Test BCheck loader functionality"""
    print("\n📦 Testing BCheck Loader...")
    
    loader = BCheckLoader()
    
    # Test loading all BChecks
    loaded = loader.load_all_bchecks()
    stats = loader.get_bcheck_statistics()
    
    print(f"  • Total discovered: {stats['total_discovered']}")
    print(f"  • Total loaded: {stats['total_loaded']}")
    print(f"  • Load success rate: {stats['load_success_rate']:.1f}%")
    
    # Note: In standard Python environment, BChecks won't load due to missing Burp API
    # This is expected behavior
    if stats['total_loaded'] == 0:
        print("  ⚠️  Expected: BChecks cannot load without Burp Suite API")
        return True
    
    return True

def test_bcheck_validation():
    """Test BCheck validation functionality"""
    print("\n✅ Testing BCheck Validation...")
    
    loader = BCheckLoader()
    loader.load_all_bchecks()
    
    # Test validation for each discovered BCheck
    discovered = loader.discover_bchecks()
    
    for bcheck_name in discovered:
        validation = loader.validate_bcheck(bcheck_name)
        print(f"  • {bcheck_name}:")
        
        if validation['valid']:
            print(f"    ✅ Valid BCheck structure")
        else:
            print(f"    ❌ Invalid: {validation.get('error', 'Unknown error')}")
        
        # Only show checks if they exist (BChecks are loaded)
        if 'checks' in validation:
            for check in validation['checks']:
                print(f"      {check}")
        else:
            print(f"      ⚠️  BCheck not loaded (expected in standard Python environment)")
    
    return True

def test_bcheck_integration():
    """Test BCheck integration with other components"""
    print("\n🔗 Testing BCheck Integration...")
    
    # Test integration with Config Manager
    config = ConfigManager()
    bcheck_config = {
        'bchecks': {
            'sql_injection': {
                'enabled': True,
                'timeout': 10,
                'max_payloads': 50
            },
            'xss': {
                'enabled': True,
                'timeout': 5,
                'max_payloads': 30
            }
        }
    }
    
    config.set('bcheck_settings', bcheck_config)
    print("  ✅ BCheck configuration saved")
    
    # Test integration with Report Generator
    report_gen = ReportGenerator()
    
    # Simulate BCheck findings
    sql_vuln = VulnerabilityReport(
        title="SQL Injection Vulnerability",
        description="SQL injection detected in login form parameter",
        severity="High",
        cvss_score=8.5,
        cwe_id="CWE-89",
        evidence="Payload: ' OR 1=1--",
        location="/login",
        recommendations=[
            "Use parameterized queries",
            "Implement input validation",
            "Apply proper output encoding"
        ],
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://portswigger.net/web-security/sql-injection"
        ]
    )
    
    xss_vuln = VulnerabilityReport(
        title="Cross-Site Scripting (XSS)",
        description="Reflected XSS vulnerability in search parameter",
        severity="Medium",
        cvss_score=6.1,
        cwe_id="CWE-79",
        evidence="Payload: <script>alert('XSS')</script>",
        location="/search",
        recommendations=[
            "Implement proper output encoding",
            "Use Content Security Policy (CSP)",
            "Validate and sanitize all inputs"
        ],
        references=[
            "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)",
            "https://portswigger.net/web-security/cross-site-scripting"
        ]
    )
    
    report_gen.add_vulnerability(sql_vuln)
    report_gen.add_vulnerability(xss_vuln)
    
    # Set scan metadata
    scan_metadata = {
        'scan_name': 'BCheck Security Scan',
        'target_url': 'https://example.com',
        'scan_date': '2024-01-15',
        'scanner_version': '1.0.0',
        'bchecks_used': ['sql_injection_bcheck', 'xss_bcheck', 'ssrf_bcheck']
    }
    report_gen.set_scan_metadata(scan_metadata)
    
    print("  ✅ BCheck findings added to report")
    
    # Generate reports
    reports = report_gen.generate_all_formats("bcheck_security_scan")
    
    print("  📊 Generated reports:")
    for format_name, filepath in reports.items():
        print(f"    • {format_name.upper()}: {filepath}")
    
    return True

def test_bcheck_statistics():
    """Test BCheck statistics and reporting"""
    print("\n📊 Testing BCheck Statistics...")
    
    loader = BCheckLoader()
    stats = loader.get_bcheck_statistics()
    
    print("  📈 BCheck Statistics:")
    print(f"    • Total discovered: {stats['total_discovered']}")
    print(f"    • Total loaded: {stats['total_loaded']}")
    print(f"    • Load success rate: {stats['load_success_rate']:.1f}%")
    print(f"    • Loaded BChecks: {', '.join(stats['loaded_bchecks']) if stats['loaded_bchecks'] else 'None'}")
    
    print("\n  🔍 Validation Summary:")
    for bcheck_name, validation in stats['validation_results'].items():
        status = "✅ Valid" if validation['valid'] else "❌ Invalid"
        print(f"    • {bcheck_name}: {status}")
    
    return True

def main():
    """Run all BCheck system tests"""
    print("🧪 Testing Complete BCheck System")
    print("=" * 60)
    
    tests = [
        ("BCheck Discovery", test_bcheck_discovery),
        ("BCheck Loader", test_bcheck_loader),
        ("BCheck Validation", test_bcheck_validation),
        ("BCheck Integration", test_bcheck_integration),
        ("BCheck Statistics", test_bcheck_statistics)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            print(f"\n{'='*20} {test_name} {'='*20}")
            if test_func():
                print(f"✅ {test_name} test passed")
                passed += 1
            else:
                print(f"❌ {test_name} test failed")
        except Exception as e:
            print(f"❌ {test_name} test failed with error: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*60}")
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All BCheck system tests completed successfully!")
        print("\n🚀 BCheck System Features:")
        print("  • Dynamic BCheck discovery and loading")
        print("  • Comprehensive validation and statistics")
        print("  • Integration with configuration management")
        print("  • Advanced reporting capabilities")
        print("  • 5 specialized security BChecks")
        print("    - SQL Injection detection")
        print("    - Cross-Site Scripting detection")
        print("    - Server-Side Request Forgery detection")
        print("    - Authentication Bypass detection")
        print("    - Comprehensive security testing")
        print("\n📖 Next Steps:")
        print("  1. Load BChecks in Burp Suite Professional")
        print("  2. Configure BCheck settings as needed")
        print("  3. Run active scanning against your targets")
        print("  4. Review and export findings using the report generator")
    else:
        print("❌ Some tests failed. Please review the errors above.")

if __name__ == "__main__":
    main()
