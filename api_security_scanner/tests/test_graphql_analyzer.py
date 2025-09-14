"""
Test GraphQL analyzer functionality in RequestAnalyzer.
"""

import pytest
from unittest.mock import Mock, patch
from api_security_scanner.core.request_analyzer import RequestAnalyzer


class TestGraphQLAnalyzer:
    """Test GraphQL detection in RequestAnalyzer."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = RequestAnalyzer()
    
    def test_graphql_endpoint_detection(self):
        """Test GraphQL endpoint detection in URLs."""
        # Test various GraphQL endpoint patterns
        test_urls = [
            'https://api.example.com/graphql',
            'https://api.example.com/api/graphql',
            'https://api.example.com/v1/graphql',
            'https://api.example.com/query',
            'https://api.example.com/api/query',
            'https://api.example.com/gql',
            'https://api.example.com/api/gql'
        ]
        
        for url in test_urls:
            endpoints = self.analyzer._detect_graphql_endpoints(url)
            assert len(endpoints) > 0, f"Should detect GraphQL endpoint in {url}"
            assert endpoints[0]['type'] == 'graphql_endpoint'
            assert endpoints[0]['confidence'] == 'high'
    
    def test_non_graphql_endpoint_detection(self):
        """Test that non-GraphQL endpoints are not detected."""
        test_urls = [
            'https://api.example.com/users',
            'https://api.example.com/api/users',
            'https://api.example.com/posts',
            'https://api.example.com/auth/login'
        ]
        
        for url in test_urls:
            endpoints = self.analyzer._detect_graphql_endpoints(url)
            assert len(endpoints) == 0, f"Should not detect GraphQL endpoint in {url}"
    
    def test_graphql_operations_detection_json(self):
        """Test GraphQL operations detection in JSON body."""
        # Test GraphQL query in JSON format
        body = '{"query": "query { user { name email } }"}'
        headers = {'Content-Type': 'application/json'}
        
        operations = self.analyzer._detect_graphql_operations(body, headers)
        assert len(operations) > 0
        assert any(op['type'] == 'graphql_operation' for op in operations)
        assert any(op['operation_type'] == 'query' for op in operations)
    
    def test_graphql_mutation_detection(self):
        """Test GraphQL mutation detection."""
        body = '{"query": "mutation { createUser(name: \"John\") { id } }"}'
        headers = {'Content-Type': 'application/json'}
        
        operations = self.analyzer._detect_graphql_operations(body, headers)
        assert len(operations) > 0
        assert any(op['operation_type'] == 'mutation' for op in operations)
    
    def test_graphql_subscription_detection(self):
        """Test GraphQL subscription detection."""
        body = '{"query": "subscription { userUpdates { id name } }"}'
        headers = {'Content-Type': 'application/json'}
        
        operations = self.analyzer._detect_graphql_operations(body, headers)
        assert len(operations) > 0
        assert any(op['operation_type'] == 'subscription' for op in operations)
    
    def test_graphql_introspection_detection(self):
        """Test GraphQL introspection detection."""
        body = '{"query": "query { __schema { types { name } } }"}'
        headers = {'Content-Type': 'application/json'}
        
        operations = self.analyzer._detect_graphql_operations(body, headers)
        assert len(operations) > 0
        assert any(op['operation_type'] == 'introspection' for op in operations)
    
    def test_graphql_content_type_detection(self):
        """Test GraphQL content type detection."""
        body = 'query { user { name } }'
        headers = {'Content-Type': 'application/graphql'}
        
        operations = self.analyzer._detect_graphql_operations(body, headers)
        assert len(operations) > 0
        assert any(op['type'] == 'graphql_content_type' for op in operations)
    
    def test_graphql_parameters_detection(self):
        """Test GraphQL parameters detection."""
        body = '{"query": "query { user { name } }", "variables": {"id": 1}, "operationName": "GetUser"}'
        headers = {'Content-Type': 'application/json'}
        
        operations = self.analyzer._detect_graphql_operations(body, headers)
        assert len(operations) > 0
        assert any(op['type'] == 'graphql_parameters' for op in operations)
        
        # Find the parameters operation
        params_op = next(op for op in operations if op['type'] == 'graphql_parameters')
        assert 'variables' in params_op['parameters']
        assert 'operationName' in params_op['parameters']
    
    def test_raw_graphql_body_detection(self):
        """Test raw GraphQL body detection (non-JSON)."""
        body = 'query { user { name email } }'
        headers = {'Content-Type': 'text/plain'}
        
        operations = self.analyzer._detect_graphql_operations(body, headers)
        assert len(operations) > 0
        assert any(op['operation_type'] == 'query' for op in operations)
    
    def test_non_graphql_body_detection(self):
        """Test that non-GraphQL bodies are not detected."""
        test_bodies = [
            '{"name": "John", "email": "john@example.com"}',
            '{"users": [{"id": 1, "name": "John"}]}',
            'username=john&password=secret',
            '<?xml version="1.0"?><user><name>John</name></user>'
        ]
        
        headers = {'Content-Type': 'application/json'}
        
        for body in test_bodies:
            operations = self.analyzer._detect_graphql_operations(body, headers)
            # Should not detect GraphQL operations in non-GraphQL content
            assert len(operations) == 0 or not any(op['type'] == 'graphql_operation' for op in operations)
    
    def test_should_run_graphql_plugin_with_graphql_requests(self):
        """Test should_run_graphql_plugin with GraphQL requests."""
        requests = [
            {
                'url': 'https://api.example.com/graphql',
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"query": "query { user { name } }"}'
            }
        ]
        
        assert self.analyzer.should_run_graphql_plugin(requests) == True
    
    def test_should_run_graphql_plugin_without_graphql_requests(self):
        """Test should_run_graphql_plugin without GraphQL requests."""
        requests = [
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            }
        ]
        
        assert self.analyzer.should_run_graphql_plugin(requests) == False
    
    def test_graphql_analysis_summary(self):
        """Test GraphQL analysis summary generation."""
        requests = [
            {
                'url': 'https://api.example.com/graphql',
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"query": "query { user { name } }"}'
            }
        ]
        
        summary = self.analyzer.get_graphql_analysis_summary(requests)
        assert 'GraphQL endpoints detected' in summary
        assert 'GraphQL operations found' in summary
        assert 'query' in summary
    
    def test_graphql_analysis_summary_no_graphql(self):
        """Test GraphQL analysis summary when no GraphQL is found."""
        requests = [
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            }
        ]
        
        summary = self.analyzer.get_graphql_analysis_summary(requests)
        assert summary == "No GraphQL indicators found"
    
    def test_comprehensive_graphql_analysis(self):
        """Test comprehensive GraphQL analysis with multiple requests."""
        requests = [
            {
                'url': 'https://api.example.com/graphql',
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"query": "query { user { name } }"}'
            },
            {
                'url': 'https://api.example.com/graphql',
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"query": "mutation { createUser(name: \"John\") { id } }"}'
            },
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            }
        ]
        
        analysis = self.analyzer.analyze_requests(requests)
        
        assert analysis['contains_graphql'] == True
        assert len(analysis['graphql_endpoints']) > 0
        assert len(analysis['graphql_operations']) > 0
        assert 'GraphQLSecurityChecker' in analysis['recommended_plugins']
        
        # Check operation types
        operation_types = set()
        for op in analysis['graphql_operations']:
            if 'operation_type' in op:
                operation_types.add(op['operation_type'])
        
        assert 'query' in operation_types
        assert 'mutation' in operation_types
    
    def test_mixed_jwt_graphql_analysis(self):
        """Test analysis with both JWT and GraphQL content."""
        requests = [
            {
                'url': 'https://api.example.com/graphql',
                'method': 'POST',
                'headers': {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
                },
                'body': '{"query": "query { user { name } }"}'
            }
        ]
        
        analysis = self.analyzer.analyze_requests(requests)
        
        assert analysis['contains_jwt'] == True
        assert analysis['contains_graphql'] == True
        assert 'JWTSecurityChecker' in analysis['recommended_plugins']
        assert 'GraphQLSecurityChecker' in analysis['recommended_plugins']
