"""
Authentication handler for managing different types of authentication.
Supports tokens, cookies, and custom headers.
"""

from typing import Dict, List, Optional, Any
from urllib.parse import urlencode

from .logger import get_logger


class AuthenticationError(Exception):
    """Custom exception for authentication errors."""
    pass


class AuthHandler:
    """Handles different types of authentication for API requests."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.auth_type = None
        self.auth_data = {}
    
    def set_authentication(self, auth_type: str, name: str, value: str) -> bool:
        """
        Set authentication parameters.
        
        Args:
            auth_type: Type of authentication ('header', 'cookie', 'token')
            name: Name of the auth parameter (header name, cookie name, etc.)
            value: Value of the auth parameter
            
        Returns:
            True if authentication was set successfully
        """
        try:
            auth_type = auth_type.lower()
            
            if auth_type not in ['header', 'cookie', 'token']:
                raise AuthenticationError(f"Unsupported authentication type: {auth_type}")
            
            if not name or not value:
                raise AuthenticationError("Authentication name and value cannot be empty")
            
            self.auth_type = auth_type
            self.auth_data = {
                'name': name,
                'value': value
            }
            
            self.logger.info(f"Authentication set: {auth_type} - {name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to set authentication: {e}")
            return False
    
    def apply_authentication(self, requests_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Apply authentication to a list of requests.
        
        Args:
            requests_data: List of request dictionaries
            
        Returns:
            List of requests with authentication applied
        """
        if not self.auth_type or not self.auth_data:
            self.logger.debug("No authentication configured, returning original requests")
            return requests_data
        
        authenticated_requests = []
        
        for request in requests_data:
            try:
                authenticated_request = self._apply_auth_to_request(request.copy())
                authenticated_requests.append(authenticated_request)
            except Exception as e:
                self.logger.error(f"Failed to apply authentication to request {request.get('name', 'Unknown')}: {e}")
                # Add original request without authentication
                authenticated_requests.append(request)
        
        self.logger.info(f"Applied {self.auth_type} authentication to {len(authenticated_requests)} requests")
        return authenticated_requests
    
    def _apply_auth_to_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Apply authentication to a single request."""
        headers = request.get('headers', {}).copy()
        
        if self.auth_type == 'header':
            # Add custom header
            headers[self.auth_data['name']] = self.auth_data['value']
            
        elif self.auth_type == 'cookie':
            # Add cookie to headers
            cookie_header = headers.get('Cookie', '')
            if cookie_header:
                cookie_header += f"; {self.auth_data['name']}={self.auth_data['value']}"
            else:
                cookie_header = f"{self.auth_data['name']}={self.auth_data['value']}"
            headers['Cookie'] = cookie_header
            
        elif self.auth_type == 'token':
            # Add Authorization header with Bearer token
            if self.auth_data['name'].lower() == 'authorization':
                headers['Authorization'] = self.auth_data['value']
            else:
                # Use custom header name for token
                headers[self.auth_data['name']] = self.auth_data['value']
        
        request['headers'] = headers
        return request
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers that can be used directly.
        
        Returns:
            Dictionary of authentication headers
        """
        if not self.auth_type or not self.auth_data:
            return {}
        
        headers = {}
        
        if self.auth_type == 'header':
            headers[self.auth_data['name']] = self.auth_data['value']
            
        elif self.auth_type == 'cookie':
            headers['Cookie'] = f"{self.auth_data['name']}={self.auth_data['value']}"
            
        elif self.auth_type == 'token':
            if self.auth_data['name'].lower() == 'authorization':
                headers['Authorization'] = self.auth_data['value']
            else:
                headers[self.auth_data['name']] = self.auth_data['value']
        
        return headers
    
    def validate_authentication(self) -> bool:
        """
        Validate that authentication is properly configured.
        
        Returns:
            True if authentication is valid
        """
        if not self.auth_type:
            self.logger.warning("No authentication type configured")
            return False
        
        if not self.auth_data or not self.auth_data.get('name') or not self.auth_data.get('value'):
            self.logger.warning("Authentication data is incomplete")
            return False
        
        # Validate specific authentication types
        if self.auth_type == 'header':
            if not self.auth_data['name'] or not self.auth_data['value']:
                self.logger.warning("Header authentication requires both name and value")
                return False
                
        elif self.auth_type == 'cookie':
            if not self.auth_data['name'] or not self.auth_data['value']:
                self.logger.warning("Cookie authentication requires both name and value")
                return False
                
        elif self.auth_type == 'token':
            if not self.auth_data['value']:
                self.logger.warning("Token authentication requires a value")
                return False
            
            # If name is not provided, default to Authorization
            if not self.auth_data['name']:
                self.auth_data['name'] = 'Authorization'
                self.logger.info("Using default Authorization header for token")
        
        self.logger.info(f"Authentication validation passed: {self.auth_type}")
        return True
    
    def get_auth_info(self) -> Dict[str, Any]:
        """
        Get information about current authentication configuration.
        
        Returns:
            Dictionary containing authentication information
        """
        return {
            'type': self.auth_type,
            'data': self.auth_data.copy() if self.auth_data else {},
            'is_configured': bool(self.auth_type and self.auth_data),
            'is_valid': self.validate_authentication()
        }
    
    def clear_authentication(self):
        """Clear current authentication configuration."""
        self.auth_type = None
        self.auth_data = {}
        self.logger.info("Authentication cleared")


class BearerTokenAuth(AuthHandler):
    """Specialized handler for Bearer token authentication."""
    
    def __init__(self, token: str):
        super().__init__()
        self.set_authentication('token', 'Authorization', f'Bearer {token}')


class APIKeyAuth(AuthHandler):
    """Specialized handler for API key authentication."""
    
    def __init__(self, api_key: str, header_name: str = 'X-API-Key'):
        super().__init__()
        self.set_authentication('header', header_name, api_key)


class BasicAuth(AuthHandler):
    """Specialized handler for Basic authentication."""
    
    def __init__(self, username: str, password: str):
        super().__init__()
        import base64
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.set_authentication('token', 'Authorization', f'Basic {credentials}')


class CookieAuth(AuthHandler):
    """Specialized handler for Cookie authentication."""
    
    def __init__(self, cookie_name: str, cookie_value: str):
        super().__init__()
        self.set_authentication('cookie', cookie_name, cookie_value)


def create_auth_handler(auth_type: str, name: str, value: str) -> AuthHandler:
    """
    Factory function to create authentication handlers.
    
    Args:
        auth_type: Type of authentication
        name: Name of the auth parameter
        value: Value of the auth parameter
        
    Returns:
        Configured AuthHandler instance
    """
    handler = AuthHandler()
    if handler.set_authentication(auth_type, name, value):
        return handler
    else:
        raise AuthenticationError(f"Failed to create authentication handler for {auth_type}")


def merge_auth_with_requests(requests_data: List[Dict[str, Any]], 
                           auth_handler: Optional[AuthHandler] = None) -> List[Dict[str, Any]]:
    """
    Merge authentication with requests data.
    
    Args:
        requests_data: List of request dictionaries
        auth_handler: Authentication handler instance
        
    Returns:
        List of requests with authentication applied
    """
    if not auth_handler:
        return requests_data
    
    return auth_handler.apply_authentication(requests_data)
