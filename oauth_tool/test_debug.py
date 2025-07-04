#!/usr/bin/env python3
"""
Test script to demonstrate OAuth/OIDC Security Testing Tool debug functionality
"""

import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from oauth_oidc_tester import discover_metadata, setup_debug_logging, debug_print

def test_debug_functionality():
    """Test the debug functionality of the OAuth/OIDC Security Tester."""
    
    print("🔒 Testing OAuth/OIDC Security Tester Debug Functionality")
    print("=" * 60)
    
    # Test issuer (using a public OIDC provider for testing)
    test_issuer = "https://accounts.google.com"
    
    print(f"Test issuer: {test_issuer}")
    print()
    
    # Test without debug mode
    print("1. Testing WITHOUT debug mode:")
    print("-" * 40)
    setup_debug_logging(debug=False)
    
    # Run OIDC discovery without debug
    result = discover_metadata(test_issuer, debug=False)
    if "error" not in result:
        print("✅ OIDC discovery successful")
        metadata = result.get("metadata", {})
        print(f"   Authorization endpoint: {metadata.get('authorization_endpoint', 'N/A')}")
        print(f"   Token endpoint: {metadata.get('token_endpoint', 'N/A')}")
    else:
        print(f"❌ OIDC discovery failed: {result['error']}")
    print()
    
    # Test with debug mode
    print("2. Testing WITH debug mode:")
    print("-" * 40)
    setup_debug_logging(debug=True)
    
    # Run the same discovery with debug
    result = discover_metadata(test_issuer, debug=True)
    if "error" not in result:
        print("✅ OIDC discovery successful")
        metadata = result.get("metadata", {})
        print(f"   Authorization endpoint: {metadata.get('authorization_endpoint', 'N/A')}")
        print(f"   Token endpoint: {metadata.get('token_endpoint', 'N/A')}")
    else:
        print(f"❌ OIDC discovery failed: {result['error']}")
    print()
    
    # Test debug print function directly
    print("3. Testing debug_print function:")
    print("-" * 40)
    debug_print("This is a test debug message", debug=True)
    debug_print("This message should not appear", debug=False)
    print()
    
    print("✅ Debug functionality test completed!")
    print("Check the console output above for debug messages.")
    print("Debug log file: oauth_debug.log")

def test_cli_debug():
    """Test the CLI debug functionality."""
    
    print("\n🔧 Testing CLI Debug Mode:")
    print("=" * 40)
    print("To test CLI debug mode, run:")
    print()
    print("python src/oauth_oidc_tester.py \\")
    print("  --issuer https://accounts.google.com \\")
    print("  --client-id your_client_id \\")
    print("  --redirect-uri http://localhost:8080/callback \\")
    print("  --debug")
    print()
    print("This will enable detailed debug logging throughout the OAuth flow.")

if __name__ == "__main__":
    test_debug_functionality()
    test_cli_debug() 