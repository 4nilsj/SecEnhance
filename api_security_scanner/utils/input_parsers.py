"""
Input parsers for different API specification formats.
Supports Postman Collections, OpenAPI/Swagger specs, and curl commands.
"""

import json
import re
import shlex
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from urllib.parse import urlparse, parse_qs, urlencode
import yaml

from utils.logger import get_logger


class InputParserError(Exception):
    """Custom exception for input parsing errors."""
    pass


class BaseInputParser:
    """Base class for input parsers."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def parse(self, input_data: Union[str, Dict, Path]) -> List[Dict[str, Any]]:
        """
        Parse input data and return list of request objects.
        
        Args:
            input_data: Input data to parse
            
        Returns:
            List of request dictionaries
        """
        raise NotImplementedError


class PostmanParser(BaseInputParser):
    """Parser for Postman Collection JSON files."""
    
    def parse(self, input_data: Union[str, Dict, Path]) -> List[Dict[str, Any]]:
        """Parse Postman Collection and extract requests."""
        try:
            if isinstance(input_data, (str, Path)):
                with open(input_data, 'r', encoding='utf-8') as f:
                    collection = json.load(f)
            else:
                collection = input_data
            
            if not isinstance(collection, dict):
                raise InputParserError("Invalid Postman collection format")
            
            # Handle both v1 and v2.1 formats
            if 'info' in collection:
                # v2.1 format
                return self._parse_v21_collection(collection)
            elif 'requests' in collection:
                # v1 format
                return self._parse_v1_collection(collection)
            else:
                raise InputParserError("Unsupported Postman collection format")
                
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            raise InputParserError(f"Failed to parse Postman collection: {e}")
    
    def _parse_v21_collection(self, collection: Dict) -> List[Dict[str, Any]]:
        """Parse Postman Collection v2.1 format."""
        requests = []
        
        def extract_requests(item: Dict, folder_path: str = ""):
            if item.get('request'):
                # This is a request item
                request_data = self._extract_request_v21(item['request'], folder_path)
                if request_data:
                    requests.append(request_data)
            elif item.get('item'):
                # This is a folder, recurse into items
                current_folder = f"{folder_path}/{item.get('name', '')}" if folder_path else item.get('name', '')
                for sub_item in item['item']:
                    extract_requests(sub_item, current_folder)
        
        # Start extraction from root items
        for item in collection.get('item', []):
            extract_requests(item)
        
        self.logger.info(f"Extracted {len(requests)} requests from Postman collection")
        return requests
    
    def _parse_v1_collection(self, collection: Dict) -> List[Dict[str, Any]]:
        """Parse Postman Collection v1 format."""
        requests = []
        
        for request in collection.get('requests', []):
            request_data = self._extract_request_v1(request)
            if request_data:
                requests.append(request_data)
        
        self.logger.info(f"Extracted {len(requests)} requests from Postman collection v1")
        return requests
    
    def _extract_request_v21(self, request: Dict, folder_path: str = "") -> Optional[Dict[str, Any]]:
        """Extract request data from v2.1 format."""
        try:
            url_info = request.get('url', {})
            
            # Handle different URL formats
            if isinstance(url_info, str):
                url = url_info
            elif isinstance(url_info, dict):
                # Build URL from components
                protocol = url_info.get('protocol', 'https')
                host = url_info.get('host', [])
                path = url_info.get('path', [])
                query = url_info.get('query', [])
                
                if isinstance(host, list):
                    host = '.'.join(host)
                if isinstance(path, list):
                    path = '/' + '/'.join(path)
                
                # Build query string
                query_params = {}
                for param in query:
                    if isinstance(param, dict) and param.get('key'):
                        query_params[param['key']] = param.get('value', '')
                
                query_string = urlencode(query_params) if query_params else ''
                url = f"{protocol}://{host}{path}"
                if query_string:
                    url += f"?{query_string}"
            else:
                return None
            
            # Extract headers
            headers = {}
            for header in request.get('header', []):
                if isinstance(header, dict) and header.get('key'):
                    headers[header['key']] = header.get('value', '')
            
            # Extract body
            body = request.get('body', {})
            body_data = None
            content_type = headers.get('Content-Type', '')
            
            if body.get('mode') == 'raw':
                body_data = body.get('raw', '')
            elif body.get('mode') == 'formdata':
                form_data = {}
                for item in body.get('formdata', []):
                    if item.get('key'):
                        form_data[item['key']] = item.get('value', '')
                body_data = urlencode(form_data)
                if not content_type:
                    content_type = 'application/x-www-form-urlencoded'
            elif body.get('mode') == 'urlencoded':
                urlencoded_data = {}
                for item in body.get('urlencoded', []):
                    if item.get('key'):
                        urlencoded_data[item['key']] = item.get('value', '')
                body_data = urlencode(urlencoded_data)
                if not content_type:
                    content_type = 'application/x-www-form-urlencoded'
            
            if body_data and content_type:
                headers['Content-Type'] = content_type
            
            return {
                'name': request.get('name', 'Unnamed Request'),
                'method': request.get('method', 'GET').upper(),
                'url': url,
                'headers': headers,
                'body': body_data,
                'folder': folder_path
            }
            
        except Exception as e:
            self.logger.error(f"Failed to extract request: {e}")
            return None
    
    def _extract_request_v1(self, request: Dict) -> Optional[Dict[str, Any]]:
        """Extract request data from v1 format."""
        try:
            url = request.get('url', '')
            if not url:
                return None
            
            # Extract headers
            headers = {}
            for header in request.get('headerData', []):
                if header.get('key'):
                    headers[header['key']] = header.get('value', '')
            
            # Extract body
            body_data = request.get('dataMode', '')
            if body_data == 'raw':
                body_data = request.get('rawModeData', '')
            elif body_data == 'urlencoded':
                form_data = {}
                for item in request.get('data', []):
                    if item.get('key'):
                        form_data[item['key']] = item.get('value', '')
                body_data = urlencode(form_data)
            
            return {
                'name': request.get('name', 'Unnamed Request'),
                'method': request.get('method', 'GET').upper(),
                'url': url,
                'headers': headers,
                'body': body_data,
                'folder': ''
            }
            
        except Exception as e:
            self.logger.error(f"Failed to extract v1 request: {e}")
            return None


class OpenAPIParser(BaseInputParser):
    """Parser for OpenAPI/Swagger specification files."""
    
    def parse(self, input_data: Union[str, Dict, Path]) -> List[Dict[str, Any]]:
        """Parse OpenAPI/Swagger spec and extract requests."""
        try:
            if isinstance(input_data, (str, Path)):
                file_path = Path(input_data)
                with open(file_path, 'r', encoding='utf-8') as f:
                    if file_path.suffix.lower() in ['.yaml', '.yml']:
                        spec = yaml.safe_load(f)
                    else:
                        spec = json.load(f)
            else:
                spec = input_data
            
            if not isinstance(spec, dict):
                raise InputParserError("Invalid OpenAPI specification format")
            
            return self._extract_requests_from_spec(spec)
            
        except (json.JSONDecodeError, yaml.YAMLError, FileNotFoundError) as e:
            raise InputParserError(f"Failed to parse OpenAPI spec: {e}")
    
    def _extract_requests_from_spec(self, spec: Dict) -> List[Dict[str, Any]]:
        """Extract requests from OpenAPI specification."""
        requests = []
        
        # Get base URL
        servers = spec.get('servers', [])
        base_url = servers[0].get('url', 'http://localhost') if servers else 'http://localhost'
        
        # Remove trailing slash from base URL
        base_url = base_url.rstrip('/')
        
        # Extract paths
        paths = spec.get('paths', {})
        
        for path, path_item in paths.items():
            # Handle path parameters
            path_with_params = self._replace_path_parameters(path)
            
            # Extract operations (GET, POST, etc.)
            for method, operation in path_item.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    request_data = self._extract_operation(
                        method.upper(), 
                        base_url + path_with_params, 
                        operation,
                        spec
                    )
                    if request_data:
                        requests.append(request_data)
        
        self.logger.info(f"Extracted {len(requests)} requests from OpenAPI specification")
        return requests
    
    def _replace_path_parameters(self, path: str) -> str:
        """Replace path parameters with example values."""
        # Replace {param} with example values
        path = re.sub(r'\{([^}]+)\}', r'{\1}', path)
        return path
    
    def _extract_operation(self, method: str, url: str, operation: Dict, spec: Dict) -> Optional[Dict[str, Any]]:
        """Extract request data from an operation."""
        try:
            # Extract headers
            headers = {}
            
            # Get security requirements
            security = operation.get('security', [])
            if security and isinstance(security, list) and len(security) > 0:
                security_req = security[0]
                for scheme_name, scopes in security_req.items():
                    # Add placeholder for security headers
                    if scheme_name.lower() in ['bearer', 'apikey']:
                        headers['Authorization'] = 'Bearer <token>'
                    elif scheme_name.lower() == 'basic':
                        headers['Authorization'] = 'Basic <credentials>'
            
            # Extract request body
            body_data = None
            request_body = operation.get('requestBody', {})
            if request_body:
                content = request_body.get('content', {})
                if 'application/json' in content:
                    headers['Content-Type'] = 'application/json'
                    # Generate example JSON body
                    schema = content['application/json'].get('schema', {})
                    body_data = self._generate_example_from_schema(schema)
                elif 'application/x-www-form-urlencoded' in content:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    schema = content['application/x-www-form-urlencoded'].get('schema', {})
                    body_data = self._generate_form_data_from_schema(schema)
            
            # Extract parameters
            parameters = operation.get('parameters', [])
            query_params = {}
            path_params = {}
            header_params = {}
            
            for param in parameters:
                param_name = param.get('name', '')
                param_in = param.get('in', '')
                example_value = param.get('example', 'test')
                
                if param_in == 'query':
                    query_params[param_name] = example_value
                elif param_in == 'path':
                    path_params[param_name] = example_value
                elif param_in == 'header':
                    header_params[param_name] = example_value
            
            # Add header parameters to headers
            headers.update(header_params)
            
            # Replace path parameters in URL
            for param_name, param_value in path_params.items():
                url = url.replace(f'{{{param_name}}}', str(param_value))
            
            # Add query parameters to URL
            if query_params:
                query_string = urlencode(query_params)
                url += f"?{query_string}"
            
            return {
                'name': operation.get('summary', f"{method} {url}"),
                'method': method,
                'url': url,
                'headers': headers,
                'body': body_data,
                'folder': 'OpenAPI'
            }
            
        except Exception as e:
            self.logger.error(f"Failed to extract operation: {e}")
            return None
    
    def _generate_example_from_schema(self, schema: Dict) -> str:
        """Generate example JSON from schema."""
        try:
            # Simple example generation
            if schema.get('type') == 'object':
                properties = schema.get('properties', {})
                example = {}
                for prop_name, prop_schema in properties.items():
                    prop_type = prop_schema.get('type', 'string')
                    if prop_type == 'string':
                        example[prop_name] = prop_schema.get('example', 'test')
                    elif prop_type == 'integer':
                        example[prop_name] = prop_schema.get('example', 1)
                    elif prop_type == 'boolean':
                        example[prop_name] = prop_schema.get('example', True)
                    else:
                        example[prop_name] = 'test'
                return json.dumps(example, indent=2)
            else:
                return '{}'
        except Exception:
            return '{}'
    
    def _generate_form_data_from_schema(self, schema: Dict) -> str:
        """Generate form data from schema."""
        try:
            if schema.get('type') == 'object':
                properties = schema.get('properties', {})
                form_data = {}
                for prop_name, prop_schema in properties.items():
                    form_data[prop_name] = prop_schema.get('example', 'test')
                return urlencode(form_data)
            else:
                return ''
        except Exception:
            return ''


class CurlParser(BaseInputParser):
    """Parser for curl command strings."""
    
    def parse(self, input_data: Union[str, Dict, Path]) -> List[Dict[str, Any]]:
        """Parse curl command and extract request data."""
        if not isinstance(input_data, str):
            raise InputParserError("Curl parser expects a string input")
        
        try:
            return [self._parse_curl_command(input_data)]
        except Exception as e:
            raise InputParserError(f"Failed to parse curl command: {e}")
    
    def _parse_curl_command(self, curl_command: str) -> Dict[str, Any]:
        """Parse a single curl command."""
        # Remove 'curl' prefix if present
        curl_command = curl_command.strip()
        if curl_command.startswith('curl '):
            curl_command = curl_command[5:]
        
        # Use shlex to properly parse the command
        try:
            args = shlex.split(curl_command)
        except ValueError:
            # Fallback to simple split if shlex fails
            args = curl_command.split()
        
        # Parse arguments
        method = 'GET'
        url = None
        headers = {}
        data = None
        params = {}
        
        i = 0
        while i < len(args):
            arg = args[i]
            
            if arg == '-X' or arg == '--request':
                if i + 1 < len(args):
                    method = args[i + 1].upper()
                    i += 2
                else:
                    i += 1
            elif arg == '-H' or arg == '--header':
                if i + 1 < len(args):
                    header = args[i + 1]
                    if ':' in header:
                        key, value = header.split(':', 1)
                        headers[key.strip()] = value.strip()
                    i += 2
                else:
                    i += 1
            elif arg == '-d' or arg == '--data':
                if i + 1 < len(args):
                    data = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg == '--data-raw':
                if i + 1 < len(args):
                    data = args[i + 1]
                    i += 2
                else:
                    i += 1
            elif arg == '-G' or arg == '--get':
                # Convert data to query parameters
                if data:
                    params.update(parse_qs(data))
                    data = None
                i += 1
            elif not arg.startswith('-') and url is None:
                # This should be the URL
                url = arg
                i += 1
            else:
                i += 1
        
        if not url:
            raise InputParserError("No URL found in curl command")
        
        # Add query parameters to URL if present
        if params:
            query_string = urlencode(params, doseq=True)
            if '?' in url:
                url += '&' + query_string
            else:
                url += '?' + query_string
        
        return {
            'name': f"Curl {method} {url}",
            'method': method,
            'url': url,
            'headers': headers,
            'body': data,
            'folder': 'Curl'
        }


class InputParserFactory:
    """Factory for creating appropriate input parsers."""
    
    @staticmethod
    def get_parser(input_type: str) -> BaseInputParser:
        """Get parser based on input type."""
        parsers = {
            'postman': PostmanParser,
            'openapi': OpenAPIParser,
            'swagger': OpenAPIParser,
            'curl': CurlParser
        }
        
        parser_class = parsers.get(input_type.lower())
        if not parser_class:
            raise InputParserError(f"Unsupported input type: {input_type}")
        
        return parser_class()
    
    @staticmethod
    def detect_input_type(input_path: str) -> str:
        """Detect input type based on file extension or content."""
        path = Path(input_path)
        
        # Check file extension
        if path.suffix.lower() == '.json':
            # Try to detect if it's Postman or OpenAPI
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = json.load(f)
                    if 'info' in content and 'item' in content:
                        return 'postman'
                    elif 'openapi' in content or 'swagger' in content:
                        return 'openapi'
            except:
                pass
        elif path.suffix.lower() in ['.yaml', '.yml']:
            return 'openapi'
        
        # Check if it's a curl command
        if input_path.strip().startswith('curl '):
            return 'curl'
        
        raise InputParserError(f"Could not detect input type for: {input_path}")


def parse_input(input_source: str, input_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Parse input from various sources.
    
    Args:
        input_source: Path to file or curl command string
        input_type: Type of input (auto-detected if None)
        
    Returns:
        List of parsed request objects
    """
    logger = get_logger(__name__)
    
    try:
        if input_type is None:
            input_type = InputParserFactory.detect_input_type(input_source)
        
        parser = InputParserFactory.get_parser(input_type)
        requests = parser.parse(input_source)
        
        logger.info(f"Successfully parsed {len(requests)} requests from {input_type} input")
        return requests
        
    except Exception as e:
        logger.error(f"Input parsing failed: {e}")
        raise
