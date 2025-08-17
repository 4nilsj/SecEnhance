#!/usr/bin/env python3
"""
Web Application Security BChecks Package
Specialized BChecks for web application security testing
"""

__version__ = "1.0.0"
__author__ = "Burp Automation Tool"
__description__ = "Web application security BChecks for Burp Suite"

# Available BChecks
__all__ = [
    'sql_injection_bcheck',
    'authentication_bypass_bcheck',
    'ssrf_bcheck'
]
