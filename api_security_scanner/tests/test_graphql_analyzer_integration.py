"""
Test GraphQL analyzer integration with PluginManager.
"""

import pytest
from unittest.mock import Mock, patch
from api_security_scanner.core.request_analyzer import RequestAnalyzer
from api_security_scanner.core.scanner_plugins import PluginManager


class TestGraphQLAnalyzerIntegration:
    """Test GraphQL analyzer integration with PluginManager."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = RequestAnalyzer()
        self.plugin_manager = PluginManager()
        self.plugin_manager.request_analyzer = self.analyzer
    
    def test_plugin_manager_graphql_detection(self):
        """Test that PluginManager correctly detects GraphQL and enables plugin."""
        # Mock the plugin manager to have GraphQL plugin loaded
        self.plugin_manager.loaded_plugins = {
            'SecurityHeadersChecker': Mock(),
            'ComprehensiveSecurityChecker': Mock(),
            'GraphQLSecurityChecker': Mock()
        }
        
        # Create GraphQL requests
        requests_data = [
            {
                'url': 'https://api.example.com/graphql',
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"query": "query { user { name } }"}'
            }
        ]
        
        # Test plugin selection
        plugins_to_run = self.plugin_manager._get_plugins_to_run(
            self.analyzer.analyze_requests(requests_data)
        )
        
        assert 'GraphQLSecurityChecker' in plugins_to_run
        assert 'SecurityHeadersChecker' in plugins_to_run
        assert 'ComprehensiveSecurityChecker' in plugins_to_run
    
    def test_plugin_manager_no_graphql_detection(self):
        """Test that PluginManager skips GraphQL plugin when no GraphQL detected."""
        # Mock the plugin manager to have GraphQL plugin loaded
        self.plugin_manager.loaded_plugins = {
            'SecurityHeadersChecker': Mock(),
            'ComprehensiveSecurityChecker': Mock(),
            'GraphQLSecurityChecker': Mock()
        }
        
        # Create non-GraphQL requests
        requests_data = [
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            }
        ]
        
        # Test plugin selection
        plugins_to_run = self.plugin_manager._get_plugins_to_run(
            self.analyzer.analyze_requests(requests_data)
        )
        
        assert 'GraphQLSecurityChecker' not in plugins_to_run
        assert 'SecurityHeadersChecker' in plugins_to_run
        assert 'ComprehensiveSecurityChecker' in plugins_to_run
    
    def test_plugin_manager_mixed_requests(self):
        """Test PluginManager with mixed GraphQL and non-GraphQL requests."""
        # Mock the plugin manager to have GraphQL plugin loaded
        self.plugin_manager.loaded_plugins = {
            'SecurityHeadersChecker': Mock(),
            'ComprehensiveSecurityChecker': Mock(),
            'GraphQLSecurityChecker': Mock()
        }
        
        # Create mixed requests
        requests_data = [
            {
                'url': 'https://api.example.com/graphql',
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"query": "query { user { name } }"}'
            },
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            }
        ]
        
        # Test plugin selection
        plugins_to_run = self.plugin_manager._get_plugins_to_run(
            self.analyzer.analyze_requests(requests_data)
        )
        
        assert 'GraphQLSecurityChecker' in plugins_to_run
        assert 'SecurityHeadersChecker' in plugins_to_run
        assert 'ComprehensiveSecurityChecker' in plugins_to_run
    
    def test_plugin_manager_graphql_plugin_not_available(self):
        """Test PluginManager when GraphQL plugin is not available."""
        # Mock the plugin manager without GraphQL plugin
        self.plugin_manager.loaded_plugins = {
            'SecurityHeadersChecker': Mock(),
            'ComprehensiveSecurityChecker': Mock()
        }
        
        # Create GraphQL requests
        requests_data = [
            {
                'url': 'https://api.example.com/graphql',
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"query": "query { user { name } }"}'
            }
        ]
        
        # Test plugin selection
        plugins_to_run = self.plugin_manager._get_plugins_to_run(
            self.analyzer.analyze_requests(requests_data)
        )
        
        assert 'GraphQLSecurityChecker' not in plugins_to_run
        assert 'SecurityHeadersChecker' in plugins_to_run
        assert 'ComprehensiveSecurityChecker' in plugins_to_run
    
    def test_plugin_manager_jwt_and_graphql_detection(self):
        """Test PluginManager with both JWT and GraphQL content."""
        # Mock the plugin manager to have both plugins loaded
        self.plugin_manager.loaded_plugins = {
            'SecurityHeadersChecker': Mock(),
            'ComprehensiveSecurityChecker': Mock(),
            'JWTSecurityChecker': Mock(),
            'GraphQLSecurityChecker': Mock()
        }
        
        # Create requests with both JWT and GraphQL
        requests_data = [
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
        
        # Test plugin selection
        plugins_to_run = self.plugin_manager._get_plugins_to_run(
            self.analyzer.analyze_requests(requests_data)
        )
        
        assert 'JWTSecurityChecker' in plugins_to_run
        assert 'GraphQLSecurityChecker' in plugins_to_run
        assert 'SecurityHeadersChecker' in plugins_to_run
        assert 'ComprehensiveSecurityChecker' in plugins_to_run
    
    def test_plugin_manager_user_selected_plugins(self):
        """Test PluginManager with user-selected plugins (should ignore conditional logic)."""
        # Mock the plugin manager to have GraphQL plugin loaded
        self.plugin_manager.loaded_plugins = {
            'SecurityHeadersChecker': Mock(),
            'ComprehensiveSecurityChecker': Mock(),
            'GraphQLSecurityChecker': Mock()
        }
        
        # Set user-selected plugins
        self.plugin_manager.selected_plugins = ['GraphQLSecurityChecker']
        
        # Create non-GraphQL requests
        requests_data = [
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            }
        ]
        
        # Test plugin selection (should run selected plugins regardless of analysis)
        plugins_to_run = self.plugin_manager._get_plugins_to_run(
            self.analyzer.analyze_requests(requests_data)
        )
        
        assert 'GraphQLSecurityChecker' in plugins_to_run
        assert len(plugins_to_run) == 1  # Only the selected plugin should run
    
    def test_analyzer_recommended_plugins_includes_graphql(self):
        """Test that analyzer recommends GraphQL plugin when GraphQL is detected."""
        requests_data = [
            {
                'url': 'https://api.example.com/graphql',
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"query": "query { user { name } }"}'
            }
        ]
        
        analysis = self.analyzer.analyze_requests(requests_data)
        
        assert 'GraphQLSecurityChecker' in analysis['recommended_plugins']
        assert 'SecurityHeadersChecker' in analysis['recommended_plugins']
        assert 'ComprehensiveSecurityChecker' in analysis['recommended_plugins']
    
    def test_analyzer_recommended_plugins_no_graphql(self):
        """Test that analyzer doesn't recommend GraphQL plugin when no GraphQL detected."""
        requests_data = [
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            }
        ]
        
        analysis = self.analyzer.analyze_requests(requests_data)
        
        assert 'GraphQLSecurityChecker' not in analysis['recommended_plugins']
        assert 'SecurityHeadersChecker' in analysis['recommended_plugins']
        assert 'ComprehensiveSecurityChecker' in analysis['recommended_plugins']
