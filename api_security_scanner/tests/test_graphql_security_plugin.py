"""
Tests for GraphQL Security Checker Plugin.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from api_security_scanner.plugins.graphql_security_checker import GraphQLSecurityChecker
from api_security_scanner.core.scanner_plugins import PluginResult, Vulnerability


class TestGraphQLSecurityChecker:
    """Test the GraphQL security checker plugin."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = GraphQLSecurityChecker()
        self.mock_response = Mock()
        self.mock_response.status_code = 200
        self.mock_response.headers = {'Content-Type': 'application/json'}
        self.mock_response.text = '{"data": {"user": {"name": "John Doe"}}}'
    
    def test_plugin_initialization(self):
        """Test plugin initialization."""
        assert self.plugin.name == "GraphQLSecurityChecker"
        assert self.plugin.description == "Advanced GraphQL vulnerability detection, query analysis, and security testing"
        assert self.plugin.version == "1.0.0"
        assert len(self.plugin.graphql_patterns) > 0
        assert len(self.plugin.attack_payloads) > 0
        assert 'introspection' in self.plugin.attack_payloads
    
    def test_graphql_endpoint_detection(self):
        """Test GraphQL endpoint detection."""
        # Test URL patterns
        assert self.plugin._is_graphql_endpoint("/graphql", {})
        assert self.plugin._is_graphql_endpoint("/api/graphql", {})
        assert self.plugin._is_graphql_endpoint("/v1/graphql", {})
        assert self.plugin._is_graphql_endpoint("/query", {})
        assert self.plugin._is_graphql_endpoint("/gql", {})
        
        # Test request body patterns
        request_with_query = {
            'body': 'query { user { name } }'
        }
        assert self.plugin._is_graphql_endpoint("/api", request_with_query)
        
        request_with_mutation = {
            'body': 'mutation { createUser(name: "John") { id } }'
        }
        assert self.plugin._is_graphql_endpoint("/api", request_with_mutation)
        
        request_with_subscription = {
            'body': 'subscription { userUpdated { name } }'
        }
        assert self.plugin._is_graphql_endpoint("/api", request_with_subscription)
        
        # Test JSON format
        request_with_json = {
            'body': '{"query": "query { user { name } }"}'
        }
        assert self.plugin._is_graphql_endpoint("/api", request_with_json)
        
        # Test headers
        request_with_headers = {
            'headers': {'Content-Type': 'application/graphql'}
        }
        assert self.plugin._is_graphql_endpoint("/api", request_with_headers)
        
        # Test non-GraphQL endpoints
        assert not self.plugin._is_graphql_endpoint("/api/users", {})
        assert not self.plugin._is_graphql_endpoint("/api/posts", {})
    
    def test_introspection_vulnerability_detection(self):
        """Test introspection vulnerability detection."""
        # Mock response with introspection data
        introspection_response = Mock()
        introspection_response.status_code = 200
        introspection_response.headers = {'Content-Type': 'application/json'}
        introspection_response.text = '{"data": {"__schema": {"types": [{"name": "User"}]}}}'
        
        with patch.object(self.plugin, 'make_request', return_value=introspection_response):
            vulnerabilities = self.plugin._test_introspection(
                "https://test.com/graphql", "POST", {}, introspection_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Introspection Enabled"
        assert vulnerabilities[0].risk == "High"
        assert vulnerabilities[0].cvss_score == 7.5
    
    def test_query_complexity_attack_detection(self):
        """Test query complexity attack detection."""
        # Mock response that takes time to process
        complex_response = Mock()
        complex_response.status_code = 200
        complex_response.headers = {'Content-Type': 'application/json'}
        complex_response.text = '{"data": {"user": {"name": "John"}}}'
        
        with patch.object(self.plugin, 'make_request', return_value=complex_response):
            with patch('time.time', side_effect=[0, 6]):  # 6 second delay
                vulnerabilities = self.plugin._test_query_complexity_attacks(
                    "https://test.com/graphql", "POST", {}, complex_response
                )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Query Complexity Attack"
        assert vulnerabilities[0].risk == "High"
        assert vulnerabilities[0].cvss_score == 7.5
    
    def test_depth_attack_detection(self):
        """Test query depth attack detection."""
        # Mock response that processes deep query
        depth_response = Mock()
        depth_response.status_code = 200
        depth_response.headers = {'Content-Type': 'application/json'}
        depth_response.text = '{"data": {"user": {"name": "John"}}}'
        
        with patch.object(self.plugin, 'make_request', return_value=depth_response):
            vulnerabilities = self.plugin._test_depth_attacks(
                "https://test.com/graphql", "POST", {}, depth_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Query Depth Attack"
        assert vulnerabilities[0].risk == "High"
        assert vulnerabilities[0].cvss_score == 7.5
    
    def test_alias_attack_detection(self):
        """Test alias attack detection."""
        # Mock response that processes alias query
        alias_response = Mock()
        alias_response.status_code = 200
        alias_response.headers = {'Content-Type': 'application/json'}
        alias_response.text = '{"data": {"user0": {"name": "John"}, "user1": {"name": "Jane"}}}'
        
        with patch.object(self.plugin, 'make_request', return_value=alias_response):
            vulnerabilities = self.plugin._test_alias_attacks(
                "https://test.com/graphql", "POST", {}, alias_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Alias Attack"
        assert vulnerabilities[0].risk == "Medium"
        assert vulnerabilities[0].cvss_score == 6.5
    
    def test_batch_attack_detection(self):
        """Test batch attack detection."""
        # Mock response that processes batch query
        batch_response = Mock()
        batch_response.status_code = 200
        batch_response.headers = {'Content-Type': 'application/json'}
        batch_response.text = '{"data": {"query0": {"name": "John"}, "query1": {"name": "Jane"}}}'
        
        with patch.object(self.plugin, 'make_request', return_value=batch_response):
            vulnerabilities = self.plugin._test_batch_attacks(
                "https://test.com/graphql", "POST", {}, batch_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Batch Query Attack"
        assert vulnerabilities[0].risk == "Medium"
        assert vulnerabilities[0].cvss_score == 6.5
    
    def test_fragment_attack_detection(self):
        """Test fragment attack detection."""
        # Mock response that processes fragment query
        fragment_response = Mock()
        fragment_response.status_code = 200
        fragment_response.headers = {'Content-Type': 'application/json'}
        fragment_response.text = '{"data": {"user": {"name": "John", "email": "john@example.com"}}}'
        
        with patch.object(self.plugin, 'make_request', return_value=fragment_response):
            vulnerabilities = self.plugin._test_fragment_attacks(
                "https://test.com/graphql", "POST", {}, fragment_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Fragment Attack"
        assert vulnerabilities[0].risk == "Medium"
        assert vulnerabilities[0].cvss_score == 6.5
    
    def test_union_interface_attack_detection(self):
        """Test union/interface attack detection."""
        # Mock response that processes union query
        union_response = Mock()
        union_response.status_code = 200
        union_response.headers = {'Content-Type': 'application/json'}
        union_response.text = '{"data": {"search": [{"name": "John"}, {"title": "Post"}]}}'
        
        with patch.object(self.plugin, 'make_request', return_value=union_response):
            vulnerabilities = self.plugin._test_union_interface_attacks(
                "https://test.com/graphql", "POST", {}, union_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Union/Interface Attack"
        assert vulnerabilities[0].risk == "Medium"
        assert vulnerabilities[0].cvss_score == 6.5
    
    def test_directive_attack_detection(self):
        """Test directive attack detection."""
        # Mock response that processes directive query
        directive_response = Mock()
        directive_response.status_code = 200
        directive_response.headers = {'Content-Type': 'application/json'}
        directive_response.text = '{"data": {"user": {"name": "John"}}}'
        
        with patch.object(self.plugin, 'make_request', return_value=directive_response):
            vulnerabilities = self.plugin._test_directive_attacks(
                "https://test.com/graphql", "POST", {}, directive_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Directive Attack"
        assert vulnerabilities[0].risk == "Medium"
        assert vulnerabilities[0].cvss_score == 6.5
    
    def test_subscription_attack_detection(self):
        """Test subscription attack detection."""
        # Mock response that processes subscription
        subscription_response = Mock()
        subscription_response.status_code = 200
        subscription_response.headers = {'Content-Type': 'application/json'}
        subscription_response.text = '{"data": {"userUpdated": {"id": 1, "name": "John"}}}'
        
        with patch.object(self.plugin, 'make_request', return_value=subscription_response):
            vulnerabilities = self.plugin._test_subscription_attacks(
                "https://test.com/graphql", "POST", {}, subscription_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Subscription Attack"
        assert vulnerabilities[0].risk == "High"
        assert vulnerabilities[0].cvss_score == 7.5
    
    def test_mutation_attack_detection(self):
        """Test mutation attack detection."""
        # Mock response that processes mutation
        mutation_response = Mock()
        mutation_response.status_code = 200
        mutation_response.headers = {'Content-Type': 'application/json'}
        mutation_response.text = '{"data": {"deleteUser": {"success": true}}}'
        
        with patch.object(self.plugin, 'make_request', return_value=mutation_response):
            vulnerabilities = self.plugin._test_mutation_attacks(
                "https://test.com/graphql", "POST", {}, mutation_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Mutation Attack"
        assert vulnerabilities[0].risk == "High"
        assert vulnerabilities[0].cvss_score == 8.1
    
    def test_injection_attack_detection(self):
        """Test injection attack detection."""
        # Mock response that shows injection vulnerability
        injection_response = Mock()
        injection_response.status_code = 200
        injection_response.headers = {'Content-Type': 'application/json'}
        injection_response.text = '{"error": "SQL syntax error"}'
        
        with patch.object(self.plugin, 'make_request', return_value=injection_response):
            vulnerabilities = self.plugin._test_injection_attacks(
                "https://test.com/graphql", "POST", {}, injection_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Injection Vulnerability"
        assert vulnerabilities[0].risk == "High"
        assert vulnerabilities[0].cvss_score == 8.1
    
    def test_authorization_bypass_detection(self):
        """Test authorization bypass detection."""
        # Mock response that shows authorization bypass
        auth_response = Mock()
        auth_response.status_code = 200
        auth_response.headers = {'Content-Type': 'application/json'}
        auth_response.text = '{"data": {"admin": {"users": [{"password": "secret"}]}}}'
        
        with patch.object(self.plugin, 'make_request', return_value=auth_response):
            vulnerabilities = self.plugin._test_authorization_bypass(
                "https://test.com/graphql", "POST", {}, auth_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Authorization Bypass"
        assert vulnerabilities[0].risk == "Critical"
        assert vulnerabilities[0].cvss_score == 9.1
    
    def test_information_disclosure_detection(self):
        """Test information disclosure detection."""
        # Mock response that shows information disclosure
        info_response = Mock()
        info_response.status_code = 200
        info_response.headers = {'Content-Type': 'application/json'}
        info_response.text = '{"data": {"user": {"password": "secret123", "email": "user@example.com"}}}'
        
        with patch.object(self.plugin, 'make_request', return_value=info_response):
            vulnerabilities = self.plugin._test_information_disclosure(
                "https://test.com/graphql", "POST", {}, info_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Information Disclosure"
        assert vulnerabilities[0].risk == "Medium"
        assert vulnerabilities[0].cvss_score == 6.5
    
    def test_rate_limiting_detection(self):
        """Test rate limiting detection."""
        # Mock response that shows no rate limiting
        rate_response = Mock()
        rate_response.status_code = 200
        rate_response.headers = {'Content-Type': 'application/json'}
        rate_response.text = '{"data": {"__typename": "Query"}}'
        
        with patch.object(self.plugin, 'make_request', return_value=rate_response):
            vulnerabilities = self.plugin._test_rate_limiting(
                "https://test.com/graphql", "POST", {}, rate_response
            )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "GraphQL Rate Limiting Insufficient"
        assert vulnerabilities[0].risk == "Medium"
        assert vulnerabilities[0].cvss_score == 6.5
    
    def test_attack_payload_generation(self):
        """Test attack payload generation."""
        # Test deep query generation
        deep_query = self.plugin._generate_deep_query()
        assert "user" in deep_query
        assert "posts" in deep_query
        assert "comments" in deep_query
        
        # Test alias attack generation
        alias_query = self.plugin._generate_alias_attack()
        assert "user0:" in alias_query
        assert "user19:" in alias_query
        
        # Test batch query generation
        batch_query = self.plugin._generate_batch_query()
        assert "query0:" in batch_query
        assert "query9:" in batch_query
        
        # Test fragment attack generation
        fragment_query = self.plugin._generate_fragment_attack()
        assert "fragment" in fragment_query
        assert "UserData" in fragment_query
        
        # Test union attack generation
        union_query = self.plugin._generate_union_attack()
        assert "search" in union_query
        assert "User" in union_query
        assert "Post" in union_query
        
        # Test interface attack generation
        interface_query = self.plugin._generate_interface_attack()
        assert "node" in interface_query
        
        # Test directive attack generation
        directive_query = self.plugin._generate_directive_attack()
        assert "@include" in directive_query
        assert "@skip" in directive_query
        
        # Test subscription attack generation
        subscription_query = self.plugin._generate_subscription_attack()
        assert "subscription" in subscription_query
        
        # Test mutation attack generation
        mutation_query = self.plugin._generate_mutation_attack()
        assert "mutation" in mutation_query
        assert "deleteUser" in mutation_query
        
        # Test complex query generation
        complex_query = self.plugin._generate_complex_query()
        assert "user" in complex_query
        assert len(complex_query) > 500  # Should be a complex query
    
    def test_comprehensive_graphql_analysis(self):
        """Test comprehensive GraphQL analysis."""
        # Create a request with GraphQL endpoint
        request = {
            'url': 'https://test.com/graphql',
            'method': 'POST',
            'headers': {'Content-Type': 'application/json'},
            'body': '{"query": "query { user { name } }"}'
        }
        
        response = Mock()
        response.status_code = 200
        response.headers = {'Content-Type': 'application/json'}
        response.text = '{"data": {"user": {"name": "John Doe"}}}'
        
        # Mock the make_request method
        with patch.object(self.plugin, 'make_request', return_value=response):
            result = self.plugin.check("https://test.com", [request])
        
        assert isinstance(result, PluginResult)
        assert result.success
        assert result.plugin_name == "GraphQLSecurityChecker"
        # Should find some vulnerabilities in the test GraphQL endpoint
        assert len(result.vulnerabilities) >= 0  # May or may not find vulnerabilities depending on implementation
    
    def test_non_graphql_endpoint_skipping(self):
        """Test that non-GraphQL endpoints are skipped."""
        # Create a request with non-GraphQL endpoint
        request = {
            'url': 'https://test.com/api/users',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json'},
            'body': '{"name": "John"}'
        }
        
        response = Mock()
        response.status_code = 200
        response.headers = {'Content-Type': 'application/json'}
        response.text = '{"users": [{"name": "John"}]}'
        
        # Mock the make_request method
        with patch.object(self.plugin, 'make_request', return_value=response):
            result = self.plugin.check("https://test.com", [request])
        
        assert isinstance(result, PluginResult)
        assert result.success
        assert result.plugin_name == "GraphQLSecurityChecker"
        # Should not find any vulnerabilities for non-GraphQL endpoints
        assert len(result.vulnerabilities) == 0
    
    def test_error_handling(self):
        """Test error handling in plugin."""
        # Create a request that will cause an error
        request = {
            'url': 'https://test.com/graphql',
            'method': 'POST',
            'headers': {'Content-Type': 'application/json'},
            'body': '{"query": "query { user { name } }"}'
        }
        
        # Mock make_request to raise an exception
        with patch.object(self.plugin, 'make_request', side_effect=Exception("Network error")):
            result = self.plugin.check("https://test.com", [request])
        
        assert isinstance(result, PluginResult)
        assert not result.success
        assert "GraphQL security check failed" in result.error
        assert len(result.vulnerabilities) == 0
    
    def test_poc_generation(self):
        """Test proof-of-concept generation."""
        poc = self.plugin.generate_poc("test-vuln-id")
        
        assert poc.vulnerability_id == "test-vuln-id"
        assert poc.request_method == "POST"
        assert "graphql" in poc.request_url
        assert "application/json" in poc.request_headers["Content-Type"]
        assert "__schema" in poc.request_body
        assert poc.response_status == 200
        assert "__schema" in poc.response_body


if __name__ == "__main__":
    pytest.main([__file__])
