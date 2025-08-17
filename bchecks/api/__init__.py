#!/usr/bin/env python3
"""
API Security BChecks Package
Specialized BChecks for API security testing
"""

__version__ = "1.0.0"
__author__ = "Burp Automation Tool"
__description__ = "API security BChecks for Burp Suite"

# Available BChecks
__all__ = [
    'graphql_injection_bcheck',
    'rate_limiting_bypass_bcheck'
]
