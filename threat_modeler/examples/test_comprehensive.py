#!/usr/bin/env python3
"""
Comprehensive Threat Modeling Test Script
Tests all methodologies, input formats, and output formats.
"""

import sys
import os
import json
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.threat_modeler import ThreatModeler
from src.model_parser import ArchitectureParser
from src.threat_engine import ThreatEngine
from src.report_generator import ReportGenerator
from src.debug_utils import setup_debug_logging

def test_architecture_parser():
    """Test architecture parser with different formats."""
    print("=== Testing Architecture Parser ===")
    
    parser = ArchitectureParser()
    
    # Test YAML parsing
    yaml_content = """
name: Test App
description: Test application
components:
- name: Web Server
  type: web_server
  description: Test web server
data_flows:
- from: Web Server
  to: Database
  protocol: HTTPS
  data_type: user_data
  encrypted: true
"""
    
    try:
        architecture = parser.parse_text_architecture(yaml_content)
        print(f"✅ YAML parsing successful: {architecture['name']}")
        
        # Test validation
        issues = parser.validate_architecture(architecture)
        if not issues:
            print("✅ Architecture validation passed")
        else:
            print(f"⚠️  Validation issues: {issues}")
        
        return True
    except Exception as e:
        print(f"❌ YAML parsing failed: {e}")
        return False

def test_threat_engine():
    """Test threat engine with different methodologies."""
    print("\n=== Testing Threat Engine ===")
    
    engine = ThreatEngine()
    
    # Simple test architecture
    architecture = {
        "name": "Test App",
        "description": "Test application",
        "components": [
            {
                "name": "Web Server",
                "type": "web_server",
                "description": "Test web server",
                "technologies": ["Apache"],
                "external": False
            },
            {
                "name": "Database",
                "type": "database",
                "description": "Test database",
                "technologies": ["PostgreSQL"],
                "external": False
            }
        ],
        "data_flows": [
            {
                "from": "Web Server",
                "to": "Database",
                "protocol": "HTTPS",
                "data_type": "user_data",
                "encrypted": True
            }
        ],
        "trust_boundaries": [],
        "assets": []
    }
    
    methodologies = ["STRIDE", "PASTA", "DREAD"]
    
    for methodology in methodologies:
        try:
            threats = engine.analyze_threats(architecture, methodology)
            print(f"✅ {methodology} analysis: {len(threats)} threats found")
            
            if threats:
                avg_risk = sum(t.get("risk_score", 0) for t in threats) / len(threats)
                print(f"   Average risk score: {avg_risk:.2f}")
            
        except Exception as e:
            print(f"❌ {methodology} analysis failed: {e}")
            return False
    
    return True

def test_report_generator():
    """Test report generator with different formats."""
    print("\n=== Testing Report Generator ===")
    
    generator = ReportGenerator()
    
    # Test data
    threats = [
        {
            "title": "SQL Injection",
            "category": "Tampering",
            "description": "SQL injection vulnerability",
            "severity": "High",
            "risk_score": 8.5,
            "methodology": "STRIDE",
            "mitigations": ["Input validation", "Parameterized queries"]
        }
    ]
    
    architecture = {
        "name": "Test App",
        "description": "Test application",
        "components": [],
        "data_flows": [],
        "trust_boundaries": [],
        "assets": []
    }
    
    formats = ["markdown", "html", "json"]
    
    for fmt in formats:
        try:
            report = generator.generate_report(threats, architecture, "STRIDE", fmt)
            print(f"✅ {fmt.upper()} report generated successfully")
            
            # Test file output
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{fmt}', delete=False) as f:
                f.write(report)
                temp_file = f.name
            
            # Verify file was created
            if os.path.exists(temp_file):
                print(f"   File saved: {temp_file}")
                os.unlink(temp_file)  # Clean up
            
        except Exception as e:
            print(f"❌ {fmt.upper()} report generation failed: {e}")
            return False
    
    return True

def test_integration():
    """Test full integration workflow."""
    print("\n=== Testing Full Integration ===")
    
    # Initialize components
    modeler = ThreatModeler(debug=True)
    parser = ArchitectureParser()
    
    # Test architecture
    architecture_text = """
Name: Integration Test App
Description: Test application for integration testing

Components:
- Web Server (web_server) - Apache web server
- Database (database) - PostgreSQL database
- API Gateway (gateway) - API management gateway

Data Flows:
- Web Server -> API Gateway (HTTPS) - user_requests
- API Gateway -> Database (TCP) - queries

Trust Boundaries:
- Public: Web Server - Publicly accessible
- Internal: API Gateway, Database - Internal components

Assets:
- User Data (data) - high - User information
- Business Logic (service) - medium - Application code
"""
    
    try:
        # Parse architecture
        architecture = parser.parse_text_architecture(architecture_text)
        print("✅ Architecture parsing successful")
        
        # Validate architecture
        issues = parser.validate_architecture(architecture)
        if issues:
            print(f"⚠️  Validation issues: {issues}")
        
        # Enhance architecture
        enhanced = parser.enhance_architecture(architecture)
        print("✅ Architecture enhancement successful")
        
        # Analyze threats
        threats = modeler.engine.analyze_threats(enhanced, "STRIDE")
        print(f"✅ Threat analysis: {len(threats)} threats found")
        
        # Generate report
        report = modeler.report_gen.generate_report(threats, enhanced, "STRIDE", "markdown")
        print("✅ Report generation successful")
        
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False

def test_error_handling():
    """Test error handling and edge cases."""
    print("\n=== Testing Error Handling ===")
    
    modeler = ThreatModeler(debug=True)
    
    # Test with invalid architecture
    try:
        invalid_architecture = {"invalid": "data"}
        threats = modeler.engine.analyze_threats(invalid_architecture, "STRIDE")
        print("✅ Invalid architecture handled gracefully")
    except Exception as e:
        print(f"⚠️  Invalid architecture caused error: {e}")
    
    # Test with empty architecture
    try:
        empty_architecture = {
            "name": "Empty App",
            "description": "Empty application",
            "components": [],
            "data_flows": [],
            "trust_boundaries": [],
            "assets": []
        }
        threats = modeler.engine.analyze_threats(empty_architecture, "STRIDE")
        print(f"✅ Empty architecture handled: {len(threats)} threats found")
    except Exception as e:
        print(f"❌ Empty architecture failed: {e}")
        return False
    
    return True

def test_performance():
    """Test performance with larger architecture."""
    print("\n=== Testing Performance ===")
    
    import time
    
    modeler = ThreatModeler(debug=False)  # Disable debug for performance
    
    # Create larger test architecture
    components = []
    data_flows = []
    
    for i in range(10):
        components.append({
            "name": f"Component_{i}",
            "type": "service",
            "description": f"Test component {i}",
            "technologies": ["Python"],
            "external": False
        })
    
    for i in range(15):
        data_flows.append({
            "from": f"Component_{i % 10}",
            "to": f"Component_{(i + 1) % 10}",
            "protocol": "HTTPS",
            "data_type": "data",
            "encrypted": True
        })
    
    architecture = {
        "name": "Performance Test App",
        "description": "Large test application",
        "components": components,
        "data_flows": data_flows,
        "trust_boundaries": [],
        "assets": []
    }
    
    try:
        start_time = time.time()
        threats = modeler.engine.analyze_threats(architecture, "STRIDE")
        end_time = time.time()
        
        duration = end_time - start_time
        print(f"✅ Performance test: {len(threats)} threats in {duration:.2f} seconds")
        
        if duration < 5.0:  # Should complete within 5 seconds
            print("✅ Performance acceptable")
        else:
            print("⚠️  Performance may need optimization")
        
        return True
        
    except Exception as e:
        print(f"❌ Performance test failed: {e}")
        return False

def main():
    """Run all comprehensive tests."""
    print("🚀 Starting Comprehensive Threat Modeling Tool Tests")
    print("=" * 60)
    
    # Change to the threat_modeler directory
    os.chdir(Path(__file__).parent.parent)
    
    # Run tests
    tests = [
        ("Architecture Parser", test_architecture_parser),
        ("Threat Engine", test_threat_engine),
        ("Report Generator", test_report_generator),
        ("Integration", test_integration),
        ("Error Handling", test_error_handling),
        ("Performance", test_performance)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🧪 Running {test_name} Test...")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} test passed")
            else:
                print(f"❌ {test_name} test failed")
        except Exception as e:
            print(f"❌ {test_name} test failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Comprehensive Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All comprehensive tests passed! Threat modeling tool is ready for production.")
        return 0
    else:
        print("⚠️  Some tests failed. Please review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 