"""
Unit tests for HAR (HTTP Archive) file parser
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from api_security_scanner.utils.input_parsers import InputParserFactory, HarParser


class TestHARParser:
    """Test cases for HAR file parser."""
    
    @pytest.fixture
    def sample_har_data(self):
        """Create sample HAR data for testing."""
        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "Insomnia",
                    "version": "2023.5.8"
                },
                "entries": [
                    {
                        "startedDateTime": "2024-01-01T10:00:00.000Z",
                        "time": 150,
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/users",
                            "httpVersion": "HTTP/1.1",
                            "headers": [
                                {"name": "Accept", "value": "application/json"},
                                {"name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."},
                                {"name": "User-Agent", "value": "Insomnia/2023.5.8"}
                            ],
                            "queryString": [
                                {"name": "page", "value": "1"},
                                {"name": "limit", "value": "10"}
                            ],
                            "cookies": [],
                            "headersSize": 200,
                            "bodySize": 0
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "httpVersion": "HTTP/1.1",
                            "headers": [
                                {"name": "Content-Type", "value": "application/json"},
                                {"name": "Content-Length", "value": "150"}
                            ],
                            "cookies": [],
                            "content": {
                                "size": 150,
                                "mimeType": "application/json",
                                "text": '{"users": [{"id": 1, "name": "John Doe"}]}'
                            },
                            "redirectURL": "",
                            "headersSize": 100,
                            "bodySize": 150
                        },
                        "cache": {},
                        "timings": {
                            "blocked": 0,
                            "dns": 10,
                            "connect": 20,
                            "send": 5,
                            "wait": 100,
                            "receive": 15
                        }
                    },
                    {
                        "startedDateTime": "2024-01-01T10:01:00.000Z",
                        "time": 200,
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/users",
                            "httpVersion": "HTTP/1.1",
                            "headers": [
                                {"name": "Content-Type", "value": "application/json"},
                                {"name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
                            ],
                            "queryString": [],
                            "cookies": [],
                            "headersSize": 250,
                            "bodySize": 50,
                            "postData": {
                                "mimeType": "application/json",
                                "text": '{"name": "Jane Doe", "email": "jane@example.com"}'
                            }
                        },
                        "response": {
                            "status": 201,
                            "statusText": "Created",
                            "httpVersion": "HTTP/1.1",
                            "headers": [
                                {"name": "Content-Type", "value": "application/json"},
                                {"name": "Location", "value": "/users/2"}
                            ],
                            "cookies": [],
                            "content": {
                                "size": 80,
                                "mimeType": "application/json",
                                "text": '{"id": 2, "name": "Jane Doe", "email": "jane@example.com"}'
                            },
                            "redirectURL": "",
                            "headersSize": 120,
                            "bodySize": 80
                        },
                        "cache": {},
                        "timings": {
                            "blocked": 0,
                            "dns": 5,
                            "connect": 15,
                            "send": 10,
                            "wait": 150,
                            "receive": 20
                        }
                    }
                ]
            }
        }
    
    @pytest.fixture
    def sample_har_file(self, sample_har_data, tmp_path):
        """Create a sample HAR file for testing."""
        har_file = tmp_path / "sample.har"
        with open(har_file, 'w', encoding='utf-8') as f:
            json.dump(sample_har_data, f, indent=2)
        return str(har_file)
    
    def test_har_parser_initialization(self):
        """Test HAR parser initialization."""
        parser = HarParser()
        assert parser is not None
        assert hasattr(parser, 'parse')
    
    def test_parse_valid_har_file(self, sample_har_file):
        """Test parsing a valid HAR file."""
        parser = HarParser()
        result = parser.parse(sample_har_file)
        
        assert result is not None
        assert isinstance(result, list)
        assert len(result) == 2
        
        # Check first request
        first_request = result[0]
        assert first_request['method'] == 'GET'
        assert first_request['url'].startswith('https://api.example.com/users')
        assert 'page=1' in first_request['url'] or 'page' in first_request.get('params', {})
        assert 'Authorization' in first_request['headers']
        assert first_request['headers']['Authorization'] == 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
        
        # Check second request
        second_request = result[1]
        assert second_request['method'] == 'POST'
        assert second_request['url'] == 'https://api.example.com/users'
        assert second_request['body'] == '{"name": "Jane Doe", "email": "jane@example.com"}'
        assert second_request['headers']['Content-Type'] == 'application/json'
    
    def test_parse_har_with_query_parameters(self, sample_har_file):
        """Test parsing HAR file with query parameters."""
        parser = HarParser()
        result = parser.parse(sample_har_file)
        
        first_request = result[0]
        
        # Check that query parameters are properly handled
        if 'params' in first_request:
            assert first_request['params']['page'] == '1'
            assert first_request['params']['limit'] == '10'
        else:
            # Query parameters might be included in URL
            assert 'page=1' in first_request['url']
            assert 'limit=10' in first_request['url']
    
    def test_parse_har_with_headers(self, sample_har_file):
        """Test parsing HAR file with headers."""
        parser = HarParser()
        result = parser.parse(sample_har_file)
        
        first_request = result[0]
        headers = first_request['headers']
        
        assert 'Accept' in headers
        assert headers['Accept'] == 'application/json'
        assert 'Authorization' in headers
        assert 'User-Agent' in headers
    
    def test_parse_har_with_post_data(self, sample_har_file):
        """Test parsing HAR file with POST data."""
        parser = HarParser()
        result = parser.parse(sample_har_file)
        
        second_request = result[1]
        
        assert second_request['method'] == 'POST'
        assert second_request['body'] == '{"name": "Jane Doe", "email": "jane@example.com"}'
        assert second_request['headers']['Content-Type'] == 'application/json'
    
    def test_parse_nonexistent_file(self):
        """Test parsing a non-existent HAR file."""
        parser = HarParser()
        
        with pytest.raises(Exception):  # Should raise InputParserError
            parser.parse('/nonexistent/file.har')
    
    def test_parse_invalid_json_file(self, tmp_path):
        """Test parsing an invalid JSON file."""
        invalid_file = tmp_path / "invalid.har"
        invalid_file.write_text("invalid json content")
        
        parser = HarParser()
        
        with pytest.raises(Exception):  # Should raise InputParserError
            parser.parse(str(invalid_file))
    
    def test_parse_empty_har_file(self, tmp_path):
        """Test parsing an empty HAR file."""
        empty_file = tmp_path / "empty.har"
        empty_file.write_text("{}")
        
        parser = HarParser()
        
        with pytest.raises(Exception):  # Should raise InputParserError
            parser.parse(str(empty_file))
    
    def test_parse_har_with_no_entries(self, tmp_path):
        """Test parsing HAR file with no entries."""
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Test"},
                "entries": []
            }
        }
        
        har_file = tmp_path / "empty_entries.har"
        with open(har_file, 'w', encoding='utf-8') as f:
            json.dump(har_data, f)
        
        parser = HarParser()
        result = parser.parse(str(har_file))
        
        assert result is not None
        assert isinstance(result, list)
        assert len(result) == 0
    
    def test_parse_har_with_missing_request_data(self, tmp_path):
        """Test parsing HAR file with missing request data."""
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Test"},
                "entries": [
                    {
                        "startedDateTime": "2024-01-01T10:00:00.000Z",
                        "time": 150,
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/test"
                            # Missing headers, queryString, etc.
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK"
                        }
                    }
                ]
            }
        }
        
        har_file = tmp_path / "incomplete.har"
        with open(har_file, 'w', encoding='utf-8') as f:
            json.dump(har_data, f)
        
        parser = HarParser()
        result = parser.parse(str(har_file))
        
        assert result is not None
        assert len(result) == 1
        
        request = result[0]
        assert request['method'] == 'GET'
        assert request['url'] == 'https://api.example.com/test'
        assert request['headers'] == {}
        assert request['body'] == ''
    
    def test_parse_har_with_cookies(self, tmp_path):
        """Test parsing HAR file with cookies."""
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Test"},
                "entries": [
                    {
                        "startedDateTime": "2024-01-01T10:00:00.000Z",
                        "time": 150,
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/test",
                            "headers": [],
                            "queryString": [],
                            "cookies": [
                                {"name": "session_id", "value": "abc123"},
                                {"name": "user_pref", "value": "dark_mode"}
                            ]
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [],
                            "cookies": []
                        }
                    }
                ]
            }
        }
        
        har_file = tmp_path / "with_cookies.har"
        with open(har_file, 'w', encoding='utf-8') as f:
            json.dump(har_data, f)
        
        parser = HarParser()
        result = parser.parse(str(har_file))
        
        assert result is not None
        assert len(result) == 1
        
        request = result[0]
        # Check that cookies are stored in the cookies field
        assert 'cookies' in request
        assert request['cookies']['session_id'] == 'abc123'
        assert request['cookies']['user_pref'] == 'dark_mode'
    
    def test_parse_har_with_form_data(self, tmp_path):
        """Test parsing HAR file with form data."""
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Test"},
                "entries": [
                    {
                        "startedDateTime": "2024-01-01T10:00:00.000Z",
                        "time": 150,
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/form",
                            "headers": [
                                {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}
                            ],
                            "queryString": [],
                            "cookies": [],
                            "postData": {
                                "mimeType": "application/x-www-form-urlencoded",
                                "text": "name=John+Doe&email=john%40example.com"
                            }
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": []
                        }
                    }
                ]
            }
        }
        
        har_file = tmp_path / "form_data.har"
        with open(har_file, 'w', encoding='utf-8') as f:
            json.dump(har_data, f)
        
        parser = HarParser()
        result = parser.parse(str(har_file))
        
        assert result is not None
        assert len(result) == 1
        
        request = result[0]
        assert request['method'] == 'POST'
        assert request['body'] == 'name=John+Doe&email=john%40example.com'
        assert request['headers']['Content-Type'] == 'application/x-www-form-urlencoded'
    
    def test_input_parser_factory_har_support(self):
        """Test that InputParserFactory supports HAR files."""
        factory = InputParserFactory()
        
        # Test with 'har' type
        parser = factory.get_parser('har')
        assert parser is not None
        assert hasattr(parser, 'parse')
        
        # Test with 'HAR' type (case insensitive)
        parser = factory.get_parser('HAR')
        assert parser is not None
        assert hasattr(parser, 'parse')
    
    def test_har_parser_error_handling(self, tmp_path):
        """Test HAR parser error handling."""
        parser = HarParser()
        
        # Test with file that doesn't exist
        with pytest.raises(Exception):
            parser.parse('/nonexistent/path/file.har')
        
        # Test with file that's not JSON
        invalid_file = tmp_path / "not_json.har"
        invalid_file.write_text("This is not JSON content")
        
        with pytest.raises(Exception):
            parser.parse(str(invalid_file))
        
        # Test with JSON that's not a HAR file
        not_har_file = tmp_path / "not_har.json"
        with open(not_har_file, 'w', encoding='utf-8') as f:
            json.dump({"not": "a har file"}, f)
        
        with pytest.raises(Exception):
            parser.parse(str(not_har_file))
    
    def test_har_parser_with_large_file(self, tmp_path):
        """Test HAR parser with a large number of entries."""
        # Create HAR with many entries
        entries = []
        for i in range(100):
            entries.append({
                "startedDateTime": f"2024-01-01T10:{i:02d}:00.000Z",
                "time": 100 + i,
                "request": {
                    "method": "GET",
                    "url": f"https://api.example.com/endpoint{i}",
                    "headers": [{"name": "Accept", "value": "application/json"}],
                    "queryString": [],
                    "cookies": []
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "cookies": []
                }
            })
        
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Test"},
                "entries": entries
            }
        }
        
        har_file = tmp_path / "large.har"
        with open(har_file, 'w', encoding='utf-8') as f:
            json.dump(har_data, f)
        
        parser = HarParser()
        result = parser.parse(str(har_file))
        
        assert result is not None
        assert len(result) == 100
        
        # Check a few requests
        assert result[0]['url'] == 'https://api.example.com/endpoint0'
        assert result[50]['url'] == 'https://api.example.com/endpoint50'
        assert result[99]['url'] == 'https://api.example.com/endpoint99'


if __name__ == '__main__':
    pytest.main([__file__])
