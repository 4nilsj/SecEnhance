#!/usr/bin/env python3
"""
Test script for JWT Security Checker Plugin
Tests JWT token vulnerability detection and OAuth flow analysis.
"""

import sys
import os
import json
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from api_security_scanner.core.scanner_plugins import PluginManager
from api_security_scanner.core.request_analyzer import RequestAnalyzer


def create_test_requests():
    """Create test requests with JWT tokens and OAuth flows."""
    
    # Test JWT token (this is a test token with 'none' algorithm - vulnerable)
    test_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature"
    
    # Test requests with JWT tokens
    jwt_requests = [
        {
            "url": "https://api.example.com/protected",
            "method": "GET",
            "headers": {
                "Authorization": f"Bearer {test_jwt}",
                "Content-Type": "application/json"
            },
            "body": ""
        },
        {
            "url": "https://api.example.com/user/profile",
            "method": "POST",
            "headers": {
                "Authorization": f"Bearer {test_jwt}",
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "name": "John Doe",
                "token": test_jwt
            })
        }
    ]
    
    # Test requests with OAuth flows
    oauth_requests = [
        {
            "url": "https://api.example.com/oauth/token",
            "method": "POST",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            "body": "grant_type=password&username=user&password=pass&client_id=test"
        },
        {
            "url": "https://api.example.com/oauth/authorize",
            "method": "GET",
            "headers": {},
            "body": ""
        },
        {
            "url": "https://api.example.com/oauth/token",
            "method": "POST",
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "grant_type": "authorization_code",
                "code": "abc123",
                "redirect_uri": "https://example.com/callback",
                "client_id": "test_client"
            })
        }
    ]
    
    # Test requests without JWT/OAuth (should not trigger JWT plugin)
    normal_requests = [
        {
            "url": "https://api.example.com/public",
            "method": "GET",
            "headers": {
                "Content-Type": "application/json"
            },
            "body": ""
        },
        {
            "url": "https://api.example.com/health",
            "method": "GET",
            "headers": {},
            "body": ""
        }
    ]
    
    return {
        "jwt_requests": jwt_requests,
        "oauth_requests": oauth_requests,
        "normal_requests": normal_requests
    }


def test_request_analyzer():
    """Test the request analyzer functionality."""
    print("🔍 Testing Request Analyzer...")
    
    analyzer = RequestAnalyzer()
    test_data = create_test_requests()
    
    # Test JWT detection
    print("\n📋 Testing JWT Detection:")
    jwt_analysis = analyzer.analyze_requests(test_data["jwt_requests"])
    print(f"  Contains JWT: {jwt_analysis['contains_jwt']}")
    print(f"  JWT Tokens Found: {len(jwt_analysis['jwt_tokens'])}")
    for token in jwt_analysis['jwt_tokens']:
        print(f"    - {token['location']}: {token['token'][:50]}...")
    
    # Test OAuth detection
    print("\n🔐 Testing OAuth Detection:")
    oauth_analysis = analyzer.analyze_requests(test_data["oauth_requests"])
    print(f"  Contains OAuth: {oauth_analysis['contains_oauth']}")
    print(f"  OAuth Flows Found: {len(oauth_analysis['oauth_flows'])}")
    print(f"  OAuth Endpoints Found: {len(oauth_analysis['oauth_endpoints'])}")
    
    # Test normal requests (should not detect JWT/OAuth)
    print("\n📄 Testing Normal Requests:")
    normal_analysis = analyzer.analyze_requests(test_data["normal_requests"])
    print(f"  Contains JWT: {normal_analysis['contains_jwt']}")
    print(f"  Contains OAuth: {normal_analysis['contains_oauth']}")
    
    # Test conditional plugin recommendation
    print("\n🎯 Testing Plugin Recommendations:")
    print(f"  JWT Requests: {analyzer.should_run_jwt_plugin(test_data['jwt_requests'])}")
    print(f"  OAuth Requests: {analyzer.should_run_jwt_plugin(test_data['oauth_requests'])}")
    print(f"  Normal Requests: {analyzer.should_run_jwt_plugin(test_data['normal_requests'])}")
    
    return True


def test_jwt_plugin():
    """Test the JWT security plugin."""
    print("\n🔒 Testing JWT Security Plugin...")
    
    try:
        # Initialize plugin manager
        plugin_manager = PluginManager("api_security_scanner/plugins")
        
        # Check if JWT plugin is loaded
        if "JWTSecurityChecker" not in plugin_manager.loaded_plugins:
            print("❌ JWTSecurityChecker plugin not found!")
            return False
        
        print("✅ JWTSecurityChecker plugin loaded successfully")
        
        # Test with JWT requests
        test_data = create_test_requests()
        target_url = "https://api.example.com"
        
        print("\n🧪 Testing JWT Vulnerability Detection:")
        results = plugin_manager.execute_plugin(
            "JWTSecurityChecker",
            target_url,
            test_data["jwt_requests"]
        )
        
        if results.success:
            print(f"✅ JWT plugin executed successfully")
            print(f"  Vulnerabilities found: {len(results.vulnerabilities)}")
            
            for i, vuln in enumerate(results.vulnerabilities, 1):
                print(f"  {i}. {vuln.name} ({vuln.risk})")
                print(f"     CVSS: {vuln.cvss_score}")
                print(f"     Evidence: {vuln.evidence}")
        else:
            print(f"❌ JWT plugin failed: {results.error}")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ JWT plugin test failed: {e}")
        return False


def test_conditional_scanning():
    """Test conditional scanning based on JWT/OAuth detection."""
    print("\n🎯 Testing Conditional Scanning...")
    
    try:
        plugin_manager = PluginManager("api_security_scanner/plugins")
        test_data = create_test_requests()
        target_url = "https://api.example.com"
        
        # Test with JWT requests (should run JWT plugin)
        print("\n📋 Testing with JWT requests:")
        jwt_results = plugin_manager.execute_all_plugins(
            target_url,
            test_data["jwt_requests"]
        )
        
        jwt_plugin_ran = any(result.plugin_name == "JWTSecurityChecker" for result in jwt_results)
        print(f"  JWT plugin executed: {jwt_plugin_ran}")
        print(f"  Total plugins executed: {len(jwt_results)}")
        
        # Test with normal requests (should not run JWT plugin)
        print("\n📄 Testing with normal requests:")
        normal_results = plugin_manager.execute_all_plugins(
            target_url,
            test_data["normal_requests"]
        )
        
        jwt_plugin_ran_normal = any(result.plugin_name == "JWTSecurityChecker" for result in normal_results)
        print(f"  JWT plugin executed: {jwt_plugin_ran_normal}")
        print(f"  Total plugins executed: {len(normal_results)}")
        
        # Verify conditional behavior
        if jwt_plugin_ran and not jwt_plugin_ran_normal:
            print("✅ Conditional scanning working correctly!")
            return True
        else:
            print("❌ Conditional scanning not working as expected")
            return False
        
    except Exception as e:
        print(f"❌ Conditional scanning test failed: {e}")
        return False


def main():
    """Run all JWT plugin tests."""
    print("🚀 Starting JWT Security Plugin Tests")
    print("=" * 50)
    
    tests = [
        ("Request Analyzer", test_request_analyzer),
        ("JWT Plugin", test_jwt_plugin),
        ("Conditional Scanning", test_conditional_scanning)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n🧪 Running {test_name} Test...")
        try:
            result = test_func()
            results.append((test_name, result))
            if result:
                print(f"✅ {test_name} test passed")
            else:
                print(f"❌ {test_name} test failed")
        except Exception as e:
            print(f"❌ {test_name} test error: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\n🎯 Overall: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("🎉 All tests passed! JWT plugin is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the implementation.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
