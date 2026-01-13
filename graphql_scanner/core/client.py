import requests
from typing import Dict, Any, Optional

class GraphQLClient:
    def __init__(self, url: str, cookies: Optional[str] = None, headers: Optional[Dict[str, str]] = None):
        """
        Initialize the GraphQL Client.
        :param url: Target GraphQL URL
        :param cookies: Raw cookie string (e.g., "session=123; user=abc")
        :param headers: Dictionary of custom headers to include in all requests
        """
        self.url = url
        self.session = requests.Session()
        
        # Default Headers
        self.headers = {
            "User-Agent": "GraphQLScanner/1.0",
            "Content-Type": "application/json"
        }
        
        if headers:
            self.headers.update(headers)
        
        if cookies:
            self._set_cookies(cookies)

    def _set_cookies(self, cookie_string: str):
        """Parse cookie string and set in session."""
        cookie_dict = {}
        for item in cookie_string.split(';'):
            if '=' in item:
                name, value = item.strip().split('=', 1)
                cookie_dict[name] = value
        self.session.cookies.update(cookie_dict)

    def query(self, query_string: str, variables: Optional[Dict[str, Any]] = None, method: str = "POST", headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Execute a GraphQL query.
        
        Args:
            query_string: The GraphQL query.
            variables: Optional variables dictionary.
            method: HTTP method (POST or GET).
            headers: Optional headers.
            
        Returns:
            JSON response dictionary.
        """
        payload = {'query': query_string}
        if variables:
            payload['variables'] = variables

        return self.send_request(payload=payload, method=method, headers=headers)

    def batch_query(self, queries: list) -> Any:
        """
        Execute a batch of queries (array of payloads).
        """
        return self.send_request(payload=queries, method="POST")

    def send_request(self, payload: Any = None, method: str = "POST", headers: Optional[Dict[str, str]] = None, data: Any = None) -> Any:
        """
        Send a raw request to the GraphQL endpoint.
        """
        try:
            kwargs = {'timeout': 10}
            if headers:
                kwargs['headers'] = headers
            
            if method.upper() == "GET":
                 # For GET, payload usually goes to params, but here we can support both
                 # Standard GraphQL GET uses query params
                 if isinstance(payload, dict):
                     kwargs['params'] = payload
            else:
                if payload is not None:
                    kwargs['json'] = payload
                if data is not None:
                    kwargs['data'] = data

            response = self.session.request(method, self.url, **kwargs)
            # response.raise_for_status() # Don't raise, let scanner handle errors (e.g. 405 Method Not Allowed)
            try:
                return response.json()
            except:
                return response.text # Return text if not JSON (e.g. CSRF testing)
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {str(e)}")
