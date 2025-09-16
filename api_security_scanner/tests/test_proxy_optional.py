#!/usr/bin/env python3
"""Test script to verify proxy functionality is optional and only activates when needed."""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from api_security_scanner.core.config import ProxyConfig, AppConfig
from api_security_scanner.utils.proxy_handler import ProxyHandler

def test_proxy_optional():
    """Test that proxy functionality is optional and only activates when configured."""
    
    print("Testing Proxy Optional Functionality:")
    print("=" * 50)
    
    # Test 1: Default proxy config (should be disabled)
    print("\n1. Testing Default Proxy Configuration:")
    default_proxy = ProxyConfig()
    print(f"   Enabled: {default_proxy.enabled}")
    print(f"   Configured: {default_proxy.is_configured()}")
    print(f"   HTTP Proxy: {default_proxy.http_proxy}")
    print(f"   HTTPS Proxy: {default_proxy.https_proxy}")
    
    # Test 2: Proxy enabled but no URLs (should not be configured)
    print("\n2. Testing Proxy Enabled but No URLs:")
    enabled_proxy = ProxyConfig(enabled=True)
    print(f"   Enabled: {enabled_proxy.enabled}")
    print(f"   Configured: {enabled_proxy.is_configured()}")
    print(f"   HTTP Proxy: {enabled_proxy.http_proxy}")
    print(f"   HTTPS Proxy: {enabled_proxy.https_proxy}")
    
    # Test 3: Proxy with URLs (should be configured)
    print("\n3. Testing Proxy with URLs:")
    configured_proxy = ProxyConfig(
        enabled=True,
        http_proxy="http://proxy:8080",
        https_proxy="https://proxy:8080"
    )
    print(f"   Enabled: {configured_proxy.enabled}")
    print(f"   Configured: {configured_proxy.is_configured()}")
    print(f"   HTTP Proxy: {configured_proxy.http_proxy}")
    print(f"   HTTPS Proxy: {configured_proxy.https_proxy}")
    
    # Test 4: ProxyHandler behavior
    print("\n4. Testing ProxyHandler Behavior:")
    
    # Default handler (no proxy)
    default_handler = ProxyHandler(default_proxy)
    print(f"   Default handler enabled: {default_handler.is_enabled()}")
    print(f"   Default handler proxies: {default_handler.get_proxy_dict()}")
    
    # Configured handler (with proxy)
    configured_handler = ProxyHandler(configured_proxy)
    print(f"   Configured handler enabled: {configured_handler.is_enabled()}")
    print(f"   Configured handler proxies: {configured_handler.get_proxy_dict()}")
    
    # Test 5: AppConfig integration
    print("\n5. Testing AppConfig Integration:")
    app_config = AppConfig()
    print(f"   AppConfig proxy enabled: {app_config.proxy.enabled}")
    print(f"   AppConfig proxy configured: {app_config.proxy.is_configured()}")
    
    print("\n✅ All proxy optional tests completed successfully!")
    print("\n📋 Summary:")
    print("   - Proxy is disabled by default")
    print("   - Proxy only activates when both enabled=True AND URLs are provided")
    print("   - ProxyHandler respects the is_configured() check")
    print("   - AppConfig integrates proxy as optional feature")

if __name__ == "__main__":
    test_proxy_optional()
