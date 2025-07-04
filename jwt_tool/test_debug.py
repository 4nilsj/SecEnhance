#!/usr/bin/env python3
"""
Test script to demonstrate JWT Security Testing Tool debug functionality
"""

import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from jwt_security_tester import JWTSecurityTester, setup_debug_logging, debug_print

def test_debug_functionality():
    """Test the debug functionality of the JWT Security Tester."""
    
    print("🔒 Testing JWT Security Tester Debug Functionality")
    print("=" * 60)
    
    # Test token (this is a sample JWT token for testing)
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    print(f"Test token: {test_token}")
    print()
    
    # Test without debug mode
    print("1. Testing WITHOUT debug mode:")
    print("-" * 40)
    setup_debug_logging(debug=False)
    tester_no_debug = JWTSecurityTester(debug=False)
    
    # Run a simple test
    result = tester_no_debug.analyze_token_structure(test_token)
    print(f"Result: {result.get('algorithm', 'N/A')} algorithm detected")
    print()
    
    # Test with debug mode
    print("2. Testing WITH debug mode:")
    print("-" * 40)
    setup_debug_logging(debug=True)
    tester_debug = JWTSecurityTester(debug=True)
    
    # Run the same test with debug
    result = tester_debug.analyze_token_structure(test_token)
    print(f"Result: {result.get('algorithm', 'N/A')} algorithm detected")
    print()
    
    # Test algorithm confusion with debug
    print("3. Testing algorithm confusion with debug:")
    print("-" * 40)
    result = tester_debug.test_algorithm_confusion(test_token)
    print(f"Algorithm confusion test completed")
    print()
    
    print("✅ Debug functionality test completed!")
    print("Check the console output above for debug messages.")
    print("Debug log file: jwt_debug.log")

if __name__ == "__main__":
    test_debug_functionality() 