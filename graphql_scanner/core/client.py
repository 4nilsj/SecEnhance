import httpx
from typing import Dict, Any, Optional, List

class GraphQLClient:
    def __init__(self, url: str, cookies: Optional[str] = None, headers: Optional[Dict[str, str]] = None):
        """
        Initialize the Async GraphQL Client.
        :param url: Target GraphQL URL
        :param cookies: Raw cookie string (e.g., "session=123; user=abc")
        :param headers: Dictionary of custom headers to include in all requests
        """
        self.url = url
        self.headers = {
            "User-Agent": "GraphQLScanner/1.0",
            "Content-Type": "application/json"
        }
        
        if headers:
            self.headers.update(headers)
        
        self.cookies = {}
        if cookies:
            self._parse_cookies(cookies)
            
        self.client = httpx.AsyncClient(headers=self.headers, cookies=self.cookies, timeout=20.0, follow_redirects=True)
        self.last_query = None
        self.last_response = None

    def _parse_cookies(self, cookie_string: str):
        """Parse cookie string into a dictionary."""
        for item in cookie_string.split(';'):
            if '=' in item:
                name, value = item.strip().split('=', 1)
                self.cookies[name] = value

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        """Close the underlying async client."""
        await self.client.aclose()

    async def query(self, query_string: str, variables: Optional[Dict[str, Any]] = None, method: str = "POST", headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Execute a GraphQL query asynchronously.
        """
        payload = {'query': query_string}
        if variables:
            payload['variables'] = variables

        return await self.send_request(payload=payload, method=method, headers=headers)

    async def batch_query(self, queries: List[Dict[str, Any]]) -> Any:
        """
        Execute a batch of queries asynchronously.
        """
        return await self.send_request(payload=queries, method="POST")

    async def send_request(self, payload: Any = None, method: str = "POST", headers: Optional[Dict[str, str]] = None, data: Any = None) -> Any:
        """
        Send an async request to the GraphQL endpoint.
        """
        self.last_query = payload or data
        try:
            kwargs = {}
            if headers:
                kwargs['headers'] = headers
            
            if method.upper() == "GET":
                if isinstance(payload, dict):
                    kwargs['params'] = payload
                response = await self.client.get(self.url, **kwargs)
            else:
                if payload is not None:
                    kwargs['json'] = payload
                if data is not None:
                    kwargs['content'] = data # httpx uses 'content' for raw bytes/strings in request() or just use data=
                    if isinstance(data, str):
                        kwargs['content'] = data.encode('utf-8')
                
                response = await self.client.request(method, self.url, **kwargs)

            try:
                res_json = response.json()
                self.last_response = res_json
                return res_json
            except:
                res_text = response.text
                self.last_response = res_text
                return res_text
        except httpx.RequestError as e:
            self.last_response = f"Request error: {str(e)}"
            raise Exception(f"Request failed: {str(e)}")
