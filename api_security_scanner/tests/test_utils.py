"""
Unit tests for utils modules.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch, mock_open
from pathlib import Path

from api_security_scanner.utils.logger import get_logger, setup_logging, LoggedTimer
from api_security_scanner.utils.auth_handler import create_auth_handler, HeaderAuthHandler, CookieAuthHandler, TokenAuthHandler
from api_security_scanner.utils.input_parsers import parse_input, InputParserError


class TestLogger:
    """Test logger functionality."""
    
    def test_get_logger(self):
        """Test getting a logger instance."""
        logger = get_logger("test_module")
        assert logger is not None
        assert logger.name == "test_module"
    
    def test_setup_logging(self, temp_log_dir):
        """Test logging setup."""
        logger_instance = setup_logging(verbose=1, log_dir=temp_log_dir)
        assert logger_instance is not None
        assert os.path.exists(temp_log_dir)
    
    def test_setup_logging_debug(self, temp_log_dir):
        """Test debug logging setup."""
        logger_instance = setup_logging(verbose=2, log_dir=temp_log_dir)
        assert logger_instance is not None
    
    def test_logged_timer(self):
        """Test LoggedTimer context manager."""
        logger = get_logger("test")
        
        with LoggedTimer(logger, "test operation"):
            pass
        
        # Timer should complete without errors
        assert True
    
    def test_logged_timer_with_exception(self):
        """Test LoggedTimer with exception."""
        logger = get_logger("test")
        
        with pytest.raises(ValueError):
            with LoggedTimer(logger, "test operation"):
                raise ValueError("Test exception")


class TestAuthHandler:
    """Test authentication handler functionality."""
    
    def test_create_auth_handler_header(self):
        """Test creating header auth handler."""
        handler = create_auth_handler("header", "X-API-Key", "test-key")
        assert isinstance(handler, HeaderAuthHandler)
        assert handler.header_name == "X-API-Key"
        assert handler.header_value == "test-key"
    
    def test_create_auth_handler_cookie(self):
        """Test creating cookie auth handler."""
        handler = create_auth_handler("cookie", "session", "session-value")
        assert isinstance(handler, CookieAuthHandler)
        assert handler.cookie_name == "session"
        assert handler.cookie_value == "session-value"
    
    def test_create_auth_handler_token(self):
        """Test creating token auth handler."""
        handler = create_auth_handler("token", "Authorization", "Bearer token123")
        assert isinstance(handler, TokenAuthHandler)
        assert handler.token_name == "Authorization"
        assert handler.token_value == "Bearer token123"
    
    def test_create_auth_handler_invalid_type(self):
        """Test creating auth handler with invalid type."""
        with pytest.raises(ValueError):
            create_auth_handler("invalid", "name", "value")
    
    def test_header_auth_handler_apply(self):
        """Test header auth handler application."""
        handler = HeaderAuthHandler("X-API-Key", "test-key")
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            }
        ]
        
        result = handler.apply_authentication(requests_data)
        
        assert len(result) == 1
        assert "X-API-Key" in result[0]["headers"]
        assert result[0]["headers"]["X-API-Key"] == "test-key"
    
    def test_cookie_auth_handler_apply(self):
        """Test cookie auth handler application."""
        handler = CookieAuthHandler("session", "session-value")
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            }
        ]
        
        result = handler.apply_authentication(requests_data)
        
        assert len(result) == 1
        assert "Cookie" in result[0]["headers"]
        assert "session=session-value" in result[0]["headers"]["Cookie"]
    
    def test_token_auth_handler_apply(self):
        """Test token auth handler application."""
        handler = TokenAuthHandler("Authorization", "Bearer token123")
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"}
            }
        ]
        
        result = handler.apply_authentication(requests_data)
        
        assert len(result) == 1
        assert "Authorization" in result[0]["headers"]
        assert result[0]["headers"]["Authorization"] == "Bearer token123"
    
    def test_auth_handler_preserves_existing_headers(self):
        """Test that auth handler preserves existing headers."""
        handler = HeaderAuthHandler("X-API-Key", "test-key")
        requests_data = [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json", "User-Agent": "Test"}
            }
        ]
        
        result = handler.apply_authentication(requests_data)
        
        assert "Content-Type" in result[0]["headers"]
        assert "User-Agent" in result[0]["headers"]
        assert "X-API-Key" in result[0]["headers"]


class TestInputParsers:
    """Test input parsing functionality."""
    
    def test_parse_postman_collection(self, sample_postman_collection, temp_dir):
        """Test parsing Postman collection."""
        # Write sample collection to file
        collection_file = os.path.join(temp_dir, "collection.json")
        with open(collection_file, 'w') as f:
            import json
            json.dump(sample_postman_collection, f)
        
        result = parse_input(collection_file)
        
        assert len(result) == 2
        assert result[0]["url"] == "https://api.example.com/users"
        assert result[0]["method"] == "GET"
        assert result[1]["url"] == "https://api.example.com/users"
        assert result[1]["method"] == "POST"
    
    def test_parse_openapi_spec(self, sample_openapi_spec, temp_dir):
        """Test parsing OpenAPI specification."""
        # Write sample spec to file
        spec_file = os.path.join(temp_dir, "api-spec.yaml")
        with open(spec_file, 'w') as f:
            import yaml
            yaml.dump(sample_openapi_spec, f)
        
        result = parse_input(spec_file)
        
        assert len(result) == 2
        assert result[0]["url"] == "https://api.example.com/users"
        assert result[0]["method"] == "GET"
        assert result[1]["url"] == "https://api.example.com/users"
        assert result[1]["method"] == "POST"
    
    def test_parse_curl_command(self, sample_curl_command):
        """Test parsing curl command."""
        result = parse_input(sample_curl_command)
        
        assert len(result) == 1
        assert result[0]["url"] == "https://api.example.com/users"
        assert result[0]["method"] == "GET"
        assert "Content-Type" in result[0]["headers"]
    
    def test_parse_input_invalid_file(self, temp_dir):
        """Test parsing invalid file."""
        invalid_file = os.path.join(temp_dir, "invalid.txt")
        with open(invalid_file, 'w') as f:
            f.write("This is not a valid API specification")
        
        with pytest.raises(InputParserError):
            parse_input(invalid_file)
    
    def test_parse_input_nonexistent_file(self, temp_dir):
        """Test parsing nonexistent file."""
        nonexistent_file = os.path.join(temp_dir, "nonexistent.json")
        
        with pytest.raises(InputParserError):
            parse_input(nonexistent_file)
    
    def test_parse_input_invalid_json(self, temp_dir):
        """Test parsing invalid JSON."""
        invalid_json_file = os.path.join(temp_dir, "invalid.json")
        with open(invalid_json_file, 'w') as f:
            f.write("{ invalid json }")
        
        with pytest.raises(InputParserError):
            parse_input(invalid_json_file)
    
    def test_parse_input_invalid_yaml(self, temp_dir):
        """Test parsing invalid YAML."""
        invalid_yaml_file = os.path.join(temp_dir, "invalid.yaml")
        with open(invalid_yaml_file, 'w') as f:
            f.write("invalid: yaml: content: [")
        
        with pytest.raises(InputParserError):
            parse_input(invalid_yaml_file)
    
    def test_parse_input_empty_collection(self, temp_dir):
        """Test parsing empty Postman collection."""
        empty_collection = {"info": {"name": "Empty"}, "item": []}
        collection_file = os.path.join(temp_dir, "empty.json")
        with open(collection_file, 'w') as f:
            import json
            json.dump(empty_collection, f)
        
        result = parse_input(collection_file)
        assert len(result) == 0
    
    def test_parse_input_malformed_curl(self):
        """Test parsing malformed curl command."""
        malformed_curl = "not a curl command"
        
        with pytest.raises(InputParserError):
            parse_input(malformed_curl)
    
    def test_parse_input_curl_with_data(self):
        """Test parsing curl command with data."""
        curl_with_data = 'curl -X POST "https://api.example.com/users" -H "Content-Type: application/json" -d \'{"name": "John"}\''
        
        result = parse_input(curl_with_data)
        
        assert len(result) == 1
        assert result[0]["method"] == "POST"
        assert "name" in result[0].get("body", "")
    
    def test_parse_input_curl_with_headers(self):
        """Test parsing curl command with multiple headers."""
        curl_with_headers = 'curl -X GET "https://api.example.com/users" -H "Content-Type: application/json" -H "Accept: application/json"'
        
        result = parse_input(curl_with_headers)
        
        assert len(result) == 1
        assert "Content-Type" in result[0]["headers"]
        assert "Accept" in result[0]["headers"]
    
    @patch('builtins.open', new_callable=mock_open)
    def test_parse_input_file_permission_error(self, mock_file):
        """Test parsing file with permission error."""
        mock_file.side_effect = PermissionError("Permission denied")
        
        with pytest.raises(InputParserError):
            parse_input("test.json")
    
    def test_parse_input_unsupported_extension(self, temp_dir):
        """Test parsing file with unsupported extension."""
        unsupported_file = os.path.join(temp_dir, "test.xml")
        with open(unsupported_file, 'w') as f:
            f.write("<xml>content</xml>")
        
        with pytest.raises(InputParserError):
            parse_input(unsupported_file)
