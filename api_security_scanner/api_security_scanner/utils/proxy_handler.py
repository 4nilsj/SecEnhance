"""
Proxy handler utility for API Security Scanner.
Provides proxy configuration and request handling for HTTP requests.
"""

import requests
from typing import Dict, Optional, Any
from ..core.config import ProxyConfig


class ProxyHandler:
    """Handles proxy configuration and request setup."""
    
    def __init__(self, proxy_config: ProxyConfig):
        """
        Initialize proxy handler with configuration.
        
        Args:
            proxy_config: Proxy configuration settings
        """
        self.proxy_config = proxy_config
        self._proxies = self._build_proxy_dict()
    
    def _build_proxy_dict(self) -> Optional[Dict[str, str]]:
        """
        Build proxy dictionary for requests library.
        
        Returns:
            Proxy dictionary or None if proxy is disabled or not configured
        """
        if not self.proxy_config.is_configured():
            return None
        
        proxies = {}
        
        if self.proxy_config.http_proxy:
            proxies['http'] = self.proxy_config.http_proxy
        
        if self.proxy_config.https_proxy:
            proxies['https'] = self.proxy_config.https_proxy
        
        return proxies if proxies else None
    
    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """
        Get proxy dictionary for requests.
        
        Returns:
            Proxy dictionary or None if proxy is disabled
        """
        return self._proxies
    
    def get_request_kwargs(self) -> Dict[str, Any]:
        """
        Get request kwargs with proxy and other settings.
        
        Returns:
            Dictionary of request parameters
        """
        kwargs = {
            'timeout': self.proxy_config.timeout,
            'verify': self.proxy_config.verify_ssl,
            'proxies': self._proxies
        }
        
        # Add no_proxy if specified
        if self.proxy_config.no_proxy:
            kwargs['proxies'] = kwargs.get('proxies', {})
            # Note: requests library doesn't directly support no_proxy
            # This would need to be handled at the session level or with custom logic
        
        return kwargs
    
    def create_session(self) -> requests.Session:
        """
        Create a requests session with proxy configuration.
        
        Returns:
            Configured requests session
        """
        session = requests.Session()
        
        if self._proxies:
            session.proxies.update(self._proxies)
        
        session.verify = self.proxy_config.verify_ssl
        # Note: timeout is set per request, not on session
        
        return session
    
    def is_enabled(self) -> bool:
        """
        Check if proxy is enabled and configured.
        
        Returns:
            True if proxy is enabled and configured, False otherwise
        """
        return self.proxy_config.is_configured()
    
    def get_proxy_info(self) -> Dict[str, Any]:
        """
        Get proxy configuration information.
        
        Returns:
            Dictionary with proxy configuration details
        """
        return {
            'enabled': self.proxy_config.enabled,
            'http_proxy': self.proxy_config.http_proxy,
            'https_proxy': self.proxy_config.https_proxy,
            'no_proxy': self.proxy_config.no_proxy,
            'verify_ssl': self.proxy_config.verify_ssl,
            'timeout': self.proxy_config.timeout,
            'max_retries': self.proxy_config.max_retries,
            'retry_delay': self.proxy_config.retry_delay
        }


def create_proxy_handler(proxy_config: ProxyConfig) -> ProxyHandler:
    """
    Create a proxy handler instance.
    
    Args:
        proxy_config: Proxy configuration settings
        
    Returns:
        Configured proxy handler
    """
    return ProxyHandler(proxy_config)
