#!/usr/bin/env python3
"""Test script for authentication functionality."""

from api_security_scanner.utils.auth_handler import AuthHandler, AuthenticationError

def test_authentication_handler():
    """Test the authentication handler functionality."""
    
    print("Testing Authentication Handler:")
    print("=" * 50)
    
    auth_handler = AuthHandler()
    
    # Test 1: Header authentication
    print("\n1. Testing Header Authentication:")
    success = auth_handler.set_authentication('header', 'X-API-Key', 'test-api-key-123')
    print(f"   Header auth setup: {'✅ Success' if success else '❌ Failed'}")
    
    # Test 2: Token authentication  
    print("\n2. Testing Token Authentication:")
    success = auth_handler.set_authentication('token', 'Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...')
    print(f"   Token auth setup: {'✅ Success' if success else '❌ Failed'}")
    
    # Test 3: Cookie authentication
    print("\n3. Testing Cookie Authentication:")
    success = auth_handler.set_authentication('cookie', 'session', 'session-id-abc123')
    print(f"   Cookie auth setup: {'✅ Success' if success else '❌ Failed'}")
    
    # Test 4: Invalid authentication type
    print("\n4. Testing Invalid Authentication Type:")
    try:
        success = auth_handler.set_authentication('invalid', 'test', 'value')
        print(f"   Invalid auth: {'✅ Success' if success else '❌ Failed'}")
    except AuthenticationError as e:
        print(f"   Invalid auth: ❌ Failed (Expected): {e}")
    
    print("\n✅ Authentication handler tests completed!")

def test_request_authentication():
    """Test how authentication is applied to requests."""
    
    print("\n" + "=" * 50)
    print("Testing Request Authentication Application:")
    print("=" * 50)
    
    auth_handler = AuthHandler()
    auth_handler.set_authentication('header', 'X-API-Key', 'test-api-key-123')
    
    # Sample requests data
    requests_data = [
        {
            'name': 'Get Users',
            'method': 'GET',
            'url': 'https://api.example.com/users',
            'headers': {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            'body': ''
        },
        {
            'name': 'Create User',
            'method': 'POST',
            'url': 'https://api.example.com/users',
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': '{"name": "John Doe", "email": "john@example.com"}'
        }
    ]
    
    print("\nOriginal requests:")
    for i, req in enumerate(requests_data, 1):
        print(f"  {i}. {req['method']} {req['url']}")
        print(f"     Headers: {req['headers']}")
    
    # Apply authentication
    authenticated_requests = auth_handler.apply_authentication(requests_data)
    
    print("\nAfter authentication applied:")
    for i, req in enumerate(authenticated_requests, 1):
        print(f"  {i}. {req['method']} {req['url']}")
        print(f"     Headers: {req['headers']}")
    
    print("\n✅ Request authentication application test completed!")

if __name__ == "__main__":
    test_authentication_handler()
    test_request_authentication()
