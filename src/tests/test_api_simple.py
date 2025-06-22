#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple test script for the insecure API
"""

import requests
import time

def test_api():
    """Test the insecure API"""
    print("🔍 Testing Insecure API...")
    
    # Wait for API to start
    time.sleep(2)
    
    try:
        # Test basic connectivity
        response = requests.get("http://localhost:5001/", timeout=5)
        if response.status_code == 200:
            print("✅ API is accessible")
        else:
            print(f"❌ API returned status code: {response.status_code}")
            return
        
        # Test SQL injection
        print("\n🔍 Testing SQL injection...")
        response = requests.get("http://localhost:5001/api/users?search=1' OR '1'='1", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ SQL injection test returned {len(data)} users")
            if len(data) > 0:
                print("   🚨 SQL injection vulnerability confirmed!")
        
        # Test XSS
        print("\n🔍 Testing XSS...")
        payload = "<script>alert('XSS')</script>"
        data = {
            "username": payload,
            "email": "test@test.com",
            "password": "test123"
        }
        response = requests.post("http://localhost:5001/api/users", json=data, timeout=5)
        if response.status_code == 200:
            result = response.json()
            if payload in result.get('message', ''):
                print("✅ XSS vulnerability confirmed!")
        
        # Test command injection
        print("\n🔍 Testing command injection...")
        response = requests.get("http://localhost:5001/api/search?q=; echo 'SUCCESS'", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'SUCCESS' in data.get('result', ''):
                print("✅ Command injection vulnerability confirmed!")
        
        # Test missing authentication
        print("\n🔍 Testing missing authentication...")
        response = requests.get("http://localhost:5001/api/admin", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'admin panel' in data.get('message', '').lower():
                print("✅ Missing authentication vulnerability confirmed!")
        
        print("\n🎉 API testing completed!")
        print("💡 You can now use http://localhost:5001 to test your security scanner")
        
    except Exception as e:
        print(f"❌ Error testing API: {e}")

if __name__ == "__main__":
    test_api() 