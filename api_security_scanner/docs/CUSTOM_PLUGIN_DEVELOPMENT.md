# Custom Plugin Development Guide

This guide explains how to extend the API Security Scanner with custom security checks by creating your own plugins.

## Table of Contents

1. [Plugin Architecture Overview](#plugin-architecture-overview)
2. [Creating Your First Plugin](#creating-your-first-plugin)
3. [Plugin Interface Reference](#plugin-interface-reference)
4. [Advanced Plugin Development](#advanced-plugin-development)
5. [Testing Your Plugin](#testing-your-plugin)
6. [Best Practices](#best-practices)
7. [Example Plugins](#example-plugins)

## Plugin Architecture Overview

The API Security Scanner uses a modular plugin architecture where each plugin:

- Inherits from `BasePlugin` abstract class
- Implements required methods for vulnerability detection
- Returns structured results with proof-of-concept evidence
- Is automatically discovered and executed during scans

### Plugin Discovery

Plugins are automatically discovered from the `plugins/` directory. The scanner:
1. Scans the `plugins/` directory for Python files
2. Imports classes that inherit from `BasePlugin`
3. Executes all discovered plugins during custom plugin scanning phase

## Creating Your First Plugin

### Step 1: Create Plugin File

Create a new Python file in the `plugins/` directory:

```bash
touch plugins/my_custom_checker.py
```

### Step 2: Implement Plugin Class

```python
"""
Custom Security Checker Plugin

This plugin demonstrates how to create a custom security check
for the API Security Scanner.
"""

import requests
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

from src.scanner_plugins import BasePlugin, Vulnerability, ProofOfConcept, PluginResult


class MyCustomChecker(BasePlugin):
    """
    Custom security checker plugin example.
    
    This plugin checks for common security misconfigurations
    and returns detailed vulnerability information.
    """
    
    # Plugin metadata
    name = "MyCustomChecker"
    description = "Custom security checker for demonstration"
    version = "1.0.0"
    author = "Your Name"
    
    def __init__(self):
        """Initialize the plugin."""
        super().__init__()
        self.logger.info(f"Initialized {self.name} v{self.version}")
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """
        Execute custom security checks.
        
        Args:
            target_url: Base URL of the target application
            requests_data: List of parsed request data
            auth_headers: Optional authentication headers
            
        Returns:
            PluginResult containing vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            # Example: Check for exposed debug endpoints
            vulnerabilities.extend(self._check_debug_endpoints(target_url, requests_data, auth_headers))
            
            # Example: Check for information disclosure
            vulnerabilities.extend(self._check_information_disclosure(target_url, requests_data, auth_headers))
            
            return PluginResult(
                plugin_name=self.name,
                success=True,
                vulnerabilities=vulnerabilities,
                execution_time=0.0  # You can track execution time
            )
            
        except Exception as e:
            self.logger.error(f"Plugin {self.name} failed: {e}")
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=str(e)
            )
    
    def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
        """
        Generate proof-of-concept evidence for a specific vulnerability.
        
        Args:
            vulnerability_id: ID of the vulnerability
            
        Returns:
            ProofOfConcept object with request/response evidence
        """
        # This would typically retrieve stored request/response data
        # For now, return None as PoC data is stored during vulnerability creation
        return None
    
    def _check_debug_endpoints(self, target_url: str, requests_data: List[Dict[str, Any]], 
                              auth_headers: Optional[Dict[str, str]] = None) -> List[Vulnerability]:
        """Check for exposed debug endpoints."""
        vulnerabilities = []
        debug_endpoints = ['/debug', '/test', '/admin/debug', '/api/debug', '/dev/debug']
        
        for request_data in requests_data:
            url = request_data.get('url', '')
            
            for debug_endpoint in debug_endpoints:
                if debug_endpoint in url.lower():
                    # Create vulnerability with full request/response evidence
                    vuln_id = str(uuid.uuid4())
                    
                    # Make request to capture evidence
                    try:
                        response = self.make_request(
                            method=request_data.get('method', 'GET'),
                            url=url,
                            headers=auth_headers or {},
                            data=request_data.get('body')
                        )
                        
                        # Create vulnerability with proof-of-concept
                        vulnerability = self.create_vulnerability(
                            vuln_id=vuln_id,
                            name="Exposed Debug Endpoint",
                            description=f"Debug endpoint '{debug_endpoint}' is accessible and may expose sensitive information.",
                            risk="Medium",
                            cvss_score=5.3,
                            solution="Remove or secure debug endpoints in production environments.",
                            references=[
                                "https://owasp.org/www-community/attacks/Information_disclosure",
                                "https://cwe.mitre.org/data/definitions/200.html"
                            ],
                            cwe_id="CWE-200",
                            wasc_id="WASC-13",
                            url=url,
                            parameter="",
                            evidence=f"Debug endpoint accessible at {url}",
                            scan_id="",  # Will be set by the scanner
                            request=self.format_http_request(
                                request_data.get('method', 'GET'),
                                url,
                                auth_headers or {},
                                request_data.get('body')
                            ),
                            response=self.format_http_response(
                                response.status_code,
                                dict(response.headers),
                                response.text[:1000]  # Limit response size
                            )
                        )
                        
                        vulnerabilities.append(vulnerability)
                        
                    except Exception as e:
                        self.logger.warning(f"Failed to check debug endpoint {url}: {e}")
        
        return vulnerabilities
    
    def _check_information_disclosure(self, target_url: str, requests_data: List[Dict[str, Any]], 
                                    auth_headers: Optional[Dict[str, str]] = None) -> List[Vulnerability]:
        """Check for information disclosure in responses."""
        vulnerabilities = []
        
        for request_data in requests_data:
            try:
                response = self.make_request(
                    method=request_data.get('method', 'GET'),
                    url=request_data.get('url', ''),
                    headers=auth_headers or {},
                    data=request_data.get('body')
                )
                
                # Check for sensitive information in response
                sensitive_patterns = [
                    'password', 'secret', 'key', 'token', 'api_key',
                    'database', 'connection', 'config', 'admin'
                ]
                
                response_text = response.text.lower()
                found_patterns = [pattern for pattern in sensitive_patterns if pattern in response_text]
                
                if found_patterns:
                    vuln_id = str(uuid.uuid4())
                    
                    vulnerability = self.create_vulnerability(
                        vuln_id=vuln_id,
                        name="Information Disclosure",
                        description=f"Response contains potentially sensitive information: {', '.join(found_patterns)}",
                        risk="Low",
                        cvss_score=3.7,
                        solution="Review and sanitize API responses to remove sensitive information.",
                        references=[
                            "https://owasp.org/www-community/attacks/Information_disclosure",
                            "https://cwe.mitre.org/data/definitions/200.html"
                        ],
                        cwe_id="CWE-200",
                        wasc_id="WASC-13",
                        url=request_data.get('url', ''),
                        parameter="",
                        evidence=f"Sensitive patterns found: {', '.join(found_patterns)}",
                        scan_id="",  # Will be set by the scanner
                        request=self.format_http_request(
                            request_data.get('method', 'GET'),
                            request_data.get('url', ''),
                            auth_headers or {},
                            request_data.get('body')
                        ),
                        response=self.format_http_response(
                            response.status_code,
                            dict(response.headers),
                            response.text[:1000]  # Limit response size
                        )
                    )
                    
                    vulnerabilities.append(vulnerability)
                    
            except Exception as e:
                self.logger.warning(f"Failed to check information disclosure for {request_data.get('url', '')}: {e}")
        
        return vulnerabilities
```

### Step 3: Test Your Plugin

Create a test script to verify your plugin works:

```python
# test_my_plugin.py
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from plugins.my_custom_checker import MyCustomChecker

# Test data
test_requests = [
    {
        'method': 'GET',
        'url': 'https://httpbin.org/get',
        'headers': {},
        'body': None
    }
]

# Initialize and test plugin
plugin = MyCustomChecker()
result = plugin.check('https://httpbin.org', test_requests)

print(f"Plugin: {result.plugin_name}")
print(f"Success: {result.success}")
print(f"Vulnerabilities found: {len(result.vulnerabilities)}")

for vuln in result.vulnerabilities:
    print(f"- {vuln.name}: {vuln.risk} risk")
```

## Plugin Interface Reference

### BasePlugin Class

All plugins must inherit from `BasePlugin` and implement these methods:

#### Required Methods

```python
def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
          auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
    """
    Execute security checks and return results.
    
    Args:
        target_url: Base URL of the target application
        requests_data: List of parsed request data from input files
        auth_headers: Optional authentication headers
        
    Returns:
        PluginResult containing vulnerabilities found
    """
    pass

def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
    """
    Generate proof-of-concept evidence for a specific vulnerability.
    
    Args:
        vulnerability_id: ID of the vulnerability
        
    Returns:
        ProofOfConcept object with request/response evidence
    """
    pass
```

#### Helper Methods Available

```python
# Make HTTP requests
response = self.make_request(method, url, headers, data)

# Create vulnerability objects
vulnerability = self.create_vulnerability(
    vuln_id="unique-id",
    name="Vulnerability Name",
    description="Detailed description",
    risk="High|Medium|Low|Informational",
    cvss_score=7.5,
    solution="How to fix it",
    references=["https://example.com"],
    cwe_id="CWE-123",
    wasc_id="WASC-45",
    url="https://example.com/api",
    parameter="param_name",
    evidence="Evidence of the issue",
    scan_id="scan-id",
    request="Full HTTP request",
    response="Full HTTP response"
)

# Format HTTP requests/responses
request_str = self.format_http_request(method, url, headers, body)
response_str = self.format_http_response(status, headers, body)
```

### PluginResult Class

```python
class PluginResult:
    def __init__(self, plugin_name: str, success: bool, 
                 vulnerabilities: List[Vulnerability] = None, 
                 error: Optional[str] = None, execution_time: float = 0.0):
        self.plugin_name = plugin_name
        self.success = success
        self.vulnerabilities = vulnerabilities or []
        self.error = error
        self.execution_time = execution_time
        self.timestamp = datetime.now()
```

### Vulnerability Class

```python
@dataclass
class Vulnerability:
    id: str
    scan_id: str
    name: str
    description: str
    risk: str  # High, Medium, Low, Informational
    cvss_score: float
    solution: Optional[str]
    references: List[str]
    cwe_id: Optional[str]
    wasc_id: Optional[str]
    request: str  # Full HTTP request string
    response: str  # Full HTTP response string
    url: str
    parameter: Optional[str]
    evidence: Optional[str]
    source: str  # 'ZAP' or 'Custom Plugin'
    plugin_name: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    proof_of_concept: List[ProofOfConcept] = field(default_factory=list)
```

## Advanced Plugin Development

### Plugin Configuration

You can add configuration support to your plugins:

```python
class ConfigurablePlugin(BasePlugin):
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__()
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)
        self.max_retries = self.config.get('max_retries', 3)
```

### Async Operations

For plugins that need to make multiple requests:

```python
import asyncio
import aiohttp

class AsyncPlugin(BasePlugin):
    async def check_async(self, target_url: str, requests_data: List[Dict[str, Any]], 
                         auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Async version of check method."""
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for request_data in requests_data:
                task = self._check_request_async(session, request_data, auth_headers)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Vulnerability):
                    vulnerabilities.append(result)
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities
        )
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Synchronous wrapper for async check."""
        return asyncio.run(self.check_async(target_url, requests_data, auth_headers))
```

### Plugin Dependencies

If your plugin needs additional dependencies, document them:

```python
# Add to your plugin file
"""
Dependencies:
    pip install requests beautifulsoup4 lxml
"""

class WebScrapingPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        try:
            from bs4 import BeautifulSoup
            self.bs4_available = True
        except ImportError:
            self.bs4_available = False
            self.logger.warning("BeautifulSoup4 not available. Install with: pip install beautifulsoup4")
```

## Testing Your Plugin

### Unit Testing

Create comprehensive tests for your plugin:

```python
# tests/test_my_plugin.py
import unittest
from unittest.mock import Mock, patch
from plugins.my_custom_checker import MyCustomChecker

class TestMyCustomChecker(unittest.TestCase):
    def setUp(self):
        self.plugin = MyCustomChecker()
        self.test_requests = [
            {
                'method': 'GET',
                'url': 'https://example.com/debug',
                'headers': {},
                'body': None
            }
        ]
    
    @patch('plugins.my_custom_checker.requests.get')
    def test_debug_endpoint_detection(self, mock_get):
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Debug information"
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_get.return_value = mock_response
        
        # Test plugin
        result = self.plugin.check('https://example.com', self.test_requests)
        
        # Assertions
        self.assertTrue(result.success)
        self.assertEqual(len(result.vulnerabilities), 1)
        self.assertEqual(result.vulnerabilities[0].name, "Exposed Debug Endpoint")
    
    def test_plugin_metadata(self):
        self.assertEqual(self.plugin.name, "MyCustomChecker")
        self.assertEqual(self.plugin.version, "1.0.0")
```

### Integration Testing

Test your plugin with the full scanner:

```bash
# Test with a real API
python main.py scan -u "curl -X GET https://httpbin.org/get" --no-zap

# Test with your plugin only
python main.py scan -u "curl -X GET https://example.com/debug" --no-zap --no-plugins
```

## Best Practices

### 1. Error Handling

Always implement proper error handling:

```python
def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
          auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
    try:
        # Your plugin logic
        vulnerabilities = self._perform_checks(target_url, requests_data, auth_headers)
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities
        )
        
    except Exception as e:
        self.logger.error(f"Plugin {self.name} failed: {e}")
        return PluginResult(
            plugin_name=self.name,
            success=False,
            error=str(e)
        )
```

### 2. Logging

Use the built-in logger for debugging:

```python
def _check_something(self, request_data):
    self.logger.debug(f"Checking request: {request_data['url']}")
    
    try:
        # Check logic
        result = self._perform_check(request_data)
        self.logger.info(f"Check completed for {request_data['url']}: {result}")
        return result
        
    except Exception as e:
        self.logger.error(f"Check failed for {request_data['url']}: {e}")
        return False
```

### 3. Performance Considerations

- Limit response sizes to prevent memory issues
- Implement timeouts for HTTP requests
- Use connection pooling for multiple requests
- Consider async operations for I/O-bound tasks

### 4. Vulnerability Classification

Follow standard vulnerability classification:

- **High**: Critical security issues (CVSS 7.0-10.0)
- **Medium**: Important security issues (CVSS 4.0-6.9)
- **Low**: Minor security issues (CVSS 0.1-3.9)
- **Informational**: Best practices and recommendations (CVSS 0.0)

### 5. Documentation

Document your plugin thoroughly:

```python
"""
Custom Security Checker Plugin

This plugin checks for:
- Exposed debug endpoints
- Information disclosure in responses
- Missing security headers
- Insecure configurations

Author: Your Name
Version: 1.0.0
Dependencies: requests

Usage:
    The plugin is automatically loaded and executed during scans.
    No additional configuration required.

Configuration:
    timeout: Request timeout in seconds (default: 30)
    max_retries: Maximum retry attempts (default: 3)
"""
```

## Example Plugins

### 1. SQL Injection Checker

```python
class SQLInjectionChecker(BasePlugin):
    name = "SQLInjectionChecker"
    description = "Checks for SQL injection vulnerabilities"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        vulnerabilities = []
        
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --"
        ]
        
        for request_data in requests_data:
            if request_data.get('method') in ['GET', 'POST']:
                for payload in sql_payloads:
                    # Test for SQL injection
                    # ... implementation details
                    pass
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities
        )
```

### 2. Authentication Bypass Checker

```python
class AuthBypassChecker(BasePlugin):
    name = "AuthBypassChecker"
    description = "Checks for authentication bypass vulnerabilities"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        vulnerabilities = []
        
        # Check for common auth bypass techniques
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'}
        ]
        
        for request_data in requests_data:
            for bypass_header in bypass_headers:
                # Test authentication bypass
                # ... implementation details
                pass
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities
        )
```

## Conclusion

This guide provides everything you need to create custom security plugins for the API Security Scanner. Remember to:

1. Follow the plugin interface requirements
2. Implement proper error handling and logging
3. Test your plugins thoroughly
4. Document your plugins well
5. Follow security best practices

For more examples, check the existing plugins in the `plugins/` directory.
