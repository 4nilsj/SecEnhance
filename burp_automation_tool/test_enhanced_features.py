#!/usr/bin/env python3
"""
Test script to demonstrate the enhanced features of the burp automation tool
"""

import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from utils.intelligence_checker import EnhancedIntelligenceChecker
from utils.api_payload_generator import APIPayloadGenerator
from utils.config_manager import ConfigManager
from utils.report_generator import ReportGenerator, VulnerabilityReport

def test_enhanced_intelligence():
    """Test the enhanced intelligence checker"""
    print("🔍 Testing Enhanced Intelligence Checker...")
    
    checker = EnhancedIntelligenceChecker()
    
    # Test API detection patterns
    test_urls = [
        "/api/v1/users",
        "/graphql",
        "/soap/service",
        "/ws/chat"
    ]
    
    for url in test_urls:
        print(f"  Testing URL: {url}")
        # Simulate request analysis
        complexity = checker.analyze_request_complexity({"url": url})
        print(f"    Complexity score: {complexity}")
    
    # Test vulnerability likelihood
    print(f"  SQL Injection likelihood: {checker.vuln_likelihood['sql_injection']}")
    print(f"  XSS likelihood: {checker.vuln_likelihood['xss']}")
    
    print("✅ Enhanced Intelligence Checker test completed\n")

def test_advanced_payload_generation():
    """Test the advanced payload generator"""
    print("🚀 Testing Advanced Payload Generator...")
    
    generator = APIPayloadGenerator()
    
    # Test context-aware payloads
    request_context = {
        "params": {"id": "123", "search": "test", "content": "hello"}
    }
    
    sql_payloads = generator.generate_context_aware_payloads(request_context, "sql_injection")
    print(f"  Context-aware SQL injection payloads: {len(sql_payloads)} generated")
    
    xss_payloads = generator.generate_context_aware_payloads(request_context, "xss")
    print(f"  Context-aware XSS payloads: {len(xss_payloads)} generated")
    
    # Test bypass payloads
    base_payload = "1' OR '1'='1"
    bypass_payloads = generator.generate_advanced_bypass_payloads(base_payload)
    print(f"  Advanced bypass payloads: {len(bypass_payloads)} generated")
    
    print("✅ Advanced Payload Generator test completed\n")

def test_configuration_management():
    """Test the configuration manager"""
    print("⚙️ Testing Configuration Manager...")
    
    config = ConfigManager("test_config.yaml", auto_create=True)
    
    # Test setting and getting values
    config.set("test.section.value", "test_value")
    retrieved = config.get("test.section.value")
    print(f"  Set/Get test: {'✅' if retrieved == 'test_value' else '❌'}")
    
    # Test encryption
    if config.setup_encryption():
        encrypted = config.encrypt_value("secret_value")
        decrypted = config.decrypt_value(encrypted)
        print(f"  Encryption test: {'✅' if decrypted == 'secret_value' else '❌'}")
    
    # Test export
    export_path = config.export_config("json", "test_export.json")
    print(f"  Export test: {'✅' if os.path.exists(export_path) else '❌'}")
    
    # Cleanup
    if os.path.exists("test_config.yaml"):
        os.remove("test_config.yaml")
    if os.path.exists("test_export.json"):
        os.remove("test_export.json")
    
    print("✅ Configuration Manager test completed\n")

def test_enhanced_reporting():
    """Test the enhanced reporting system"""
    print("📊 Testing Enhanced Reporting System...")
    
    generator = ReportGenerator("test_reports")
    
    # Create sample vulnerabilities
    vuln1 = VulnerabilityReport(
        title="SQL Injection Vulnerability",
        description="Found SQL injection in search parameter",
        severity="high",
        cvss_score=8.5,
        cwe_id="CWE-89",
        evidence="Parameter 'search' accepts SQL injection payloads",
        location="/api/search",
        recommendations=["Use parameterized queries", "Implement input validation"]
    )
    
    vuln2 = VulnerabilityReport(
        title="XSS Vulnerability",
        description="Reflected XSS in comment field",
        severity="medium",
        cvss_score=6.1,
        cwe_id="CWE-79",
        evidence="Comment parameter reflects user input without sanitization",
        location="/api/comments",
        recommendations=["Implement output encoding", "Use CSP headers"]
    )
    
    # Add vulnerabilities to report
    generator.add_vulnerability(vuln1)
    generator.add_vulnerability(vuln2)
    
    # Set scan metadata
    generator.set_scan_metadata({
        "target_url": "https://example.com",
        "scan_type": "comprehensive",
        "scanner_version": "2.0.0"
    })
    
    # Generate reports in different formats
    html_report = generator.generate_html_report("test_report.html")
    json_report = generator.generate_json_report("test_report.json")
    csv_report = generator.generate_csv_report("test_report.csv")
    
    print(f"  HTML report: {'✅' if os.path.exists(html_report) else '❌'}")
    print(f"  JSON report: {'✅' if os.path.exists(json_report) else '❌'}")
    print(f"  CSV report: {'✅' if os.path.exists(csv_report) else '❌'}")
    
    # Get statistics
    stats = generator.get_report_statistics()
    print(f"  Total vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"  High severity: {stats['severity_counts']['high']}")
    
    # Cleanup
    import shutil
    if os.path.exists("test_reports"):
        shutil.rmtree("test_reports")
    
    print("✅ Enhanced Reporting System test completed\n")

def main():
    """Run all tests"""
    print("🧪 Testing Enhanced Burp Automation Tool Features\n")
    print("=" * 60)
    
    try:
        test_enhanced_intelligence()
        test_advanced_payload_generation()
        test_configuration_management()
        test_enhanced_reporting()
        
        print("🎉 All tests completed successfully!")
        print("The enhanced burp automation tool is ready with:")
        print("  • Enhanced Intelligence & Machine Learning")
        print("  • Advanced Payload Generation")
        print("  • Improved Configuration Management")
        print("  • Enhanced Reporting System")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
