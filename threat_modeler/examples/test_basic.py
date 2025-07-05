#!/usr/bin/env python3
"""
Basic Threat Modeling Test Script
Tests the threat modeling tool with a simple web application architecture.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.threat_modeler import ThreatModeler
from src.debug_utils import setup_debug_logging

def test_basic_web_app():
    """Test threat modeling with basic web application."""
    print("=== Testing Basic Web Application Threat Modeling ===")
    
    # Setup debug logging
    setup_debug_logging(debug=True)
    
    # Initialize threat modeler
    modeler = ThreatModeler(debug=True)
    
    # Test with basic web app architecture
    architecture_file = "examples/basic_web_app.yaml"
    
    if not os.path.exists(architecture_file):
        print(f"Error: Architecture file not found: {architecture_file}")
        return False
    
    try:
        # Run threat analysis
        print(f"Analyzing architecture from: {architecture_file}")
        modeler.run_file_input(architecture_file, "STRIDE")
        
        print("✅ Basic web app threat modeling test completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Error during basic web app test: {e}")
        return False

def test_microservices():
    """Test threat modeling with microservices architecture."""
    print("\n=== Testing Microservices Threat Modeling ===")
    
    # Initialize threat modeler
    modeler = ThreatModeler(debug=True)
    
    # Test with microservices architecture
    architecture_file = "examples/microservices.json"
    
    if not os.path.exists(architecture_file):
        print(f"Error: Architecture file not found: {architecture_file}")
        return False
    
    try:
        # Run threat analysis with PASTA methodology
        print(f"Analyzing microservices architecture from: {architecture_file}")
        modeler.run_file_input(architecture_file, "PASTA")
        
        print("✅ Microservices threat modeling test completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Error during microservices test: {e}")
        return False

def test_cloud_native():
    """Test threat modeling with cloud-native architecture."""
    print("\n=== Testing Cloud-Native Threat Modeling ===")
    
    # Initialize threat modeler
    modeler = ThreatModeler(debug=True)
    
    # Test with cloud-native architecture
    architecture_file = "examples/cloud_native.yaml"
    
    if not os.path.exists(architecture_file):
        print(f"Error: Architecture file not found: {architecture_file}")
        return False
    
    try:
        # Run threat analysis with DREAD methodology
        print(f"Analyzing cloud-native architecture from: {architecture_file}")
        modeler.run_file_input(architecture_file, "DREAD")
        
        print("✅ Cloud-native threat modeling test completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Error during cloud-native test: {e}")
        return False

def main():
    """Run all threat modeling tests."""
    print("🚀 Starting Threat Modeling Tool Tests")
    print("=" * 50)
    
    # Change to the threat_modeler directory
    os.chdir(Path(__file__).parent.parent)
    
    # Run tests
    tests = [
        test_basic_web_app,
        test_microservices,
        test_cloud_native
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Threat modeling tool is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 