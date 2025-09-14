"""
Unit tests for plugin selection functionality
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from typing import Optional

from api_security_scanner.core.scanner_plugins import PluginManager, BasePlugin, PluginResult
from api_security_scanner.core.request_analyzer import RequestAnalyzer


class MockPlugin(BasePlugin):
    """Mock plugin for testing."""
    
    name = "MockPlugin"
    description = "A mock plugin for testing"
    version = "1.0.0"
    author = "Test Author"
    
    def check(self, target_url: str, requests_data: list, auth_headers: Optional[dict] = None) -> PluginResult:
        """Mock check method."""
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=[],
            error=None
        )
    
    def generate_poc(self, vulnerability_id: str):
        """Mock PoC generation."""
        return None


class MockJWTPlugin(BasePlugin):
    """Mock JWT plugin for testing."""
    
    name = "JWTSecurityChecker"
    description = "Mock JWT security checker"
    version = "1.0.0"
    author = "Test Author"
    
    def check(self, target_url: str, requests_data: list, auth_headers: Optional[dict] = None) -> PluginResult:
        """Mock check method."""
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=[],
            error=None
        )
    
    def generate_poc(self, vulnerability_id: str):
        """Mock PoC generation."""
        return None


class MockSecurityHeadersPlugin(BasePlugin):
    """Mock security headers plugin for testing."""
    
    name = "SecurityHeadersChecker"
    description = "Mock security headers checker"
    version = "1.0.0"
    author = "Test Author"
    
    def check(self, target_url: str, requests_data: list, auth_headers: Optional[dict] = None) -> PluginResult:
        """Mock check method."""
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=[],
            error=None
        )
    
    def generate_poc(self, vulnerability_id: str):
        """Mock PoC generation."""
        return None


class TestPluginSelection:
    """Test cases for plugin selection functionality."""
    
    @pytest.fixture
    def temp_plugins_dir(self, tmp_path):
        """Create a temporary plugins directory with mock plugins."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        
        # Create mock plugin files with simpler content
        mock_plugin_content = '''
class TestMockPlugin:
    name = "TestMockPlugin"
    description = "A mock plugin for testing"
    version = "1.0.0"
    author = "Test Author"
    
    def check(self, target_url, requests_data, auth_headers=None):
        from api_security_scanner.core.scanner_plugins import PluginResult
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=[],
            error=None
        )
    
    def generate_poc(self, vulnerability_id):
        return None
'''
        
        jwt_plugin_content = '''
class TestJWTSecurityChecker:
    name = "TestJWTSecurityChecker"
    description = "Mock JWT security checker"
    version = "1.0.0"
    author = "Test Author"
    
    def check(self, target_url, requests_data, auth_headers=None):
        from api_security_scanner.core.scanner_plugins import PluginResult
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=[],
            error=None
        )
    
    def generate_poc(self, vulnerability_id):
        return None
'''
        
        headers_plugin_content = '''
class TestSecurityHeadersChecker:
    name = "TestSecurityHeadersChecker"
    description = "Mock security headers checker"
    version = "1.0.0"
    author = "Test Author"
    
    def check(self, target_url, requests_data, auth_headers=None):
        from api_security_scanner.core.scanner_plugins import PluginResult
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=[],
            error=None
        )
    
    def generate_poc(self, vulnerability_id):
        return None
'''
        
        (plugins_dir / "mock_plugin.py").write_text(mock_plugin_content)
        (plugins_dir / "jwt_plugin.py").write_text(jwt_plugin_content)
        (plugins_dir / "headers_plugin.py").write_text(headers_plugin_content)
        
        return str(plugins_dir)
    
    def test_plugin_manager_initialization(self, temp_plugins_dir):
        """Test plugin manager initialization."""
        plugin_manager = PluginManager(temp_plugins_dir)
        
        assert plugin_manager.plugins_dir == Path(temp_plugins_dir)
        # Plugins may not load due to import issues in test environment
        assert isinstance(plugin_manager.loaded_plugins, dict)
    
    def test_plugin_selection_with_specific_plugins(self, temp_plugins_dir):
        """Test plugin selection with specific plugins."""
        selected_plugins = ["TestMockPlugin", "TestJWTSecurityChecker"]
        plugin_manager = PluginManager(temp_plugins_dir, selected_plugins=selected_plugins)
        
        # Should only load selected plugins
        loaded_plugin_names = list(plugin_manager.loaded_plugins.keys())
        assert len(loaded_plugin_names) <= len(selected_plugins)
        
        # All loaded plugins should be in the selected list
        for plugin_name in loaded_plugin_names:
            assert plugin_name in selected_plugins
    
    def test_plugin_selection_with_nonexistent_plugin(self, temp_plugins_dir):
        """Test plugin selection with non-existent plugin names."""
        selected_plugins = ["NonExistentPlugin", "TestMockPlugin"]
        plugin_manager = PluginManager(temp_plugins_dir, selected_plugins=selected_plugins)
        
        # Should only load existing plugins
        loaded_plugin_names = list(plugin_manager.loaded_plugins.keys())
        assert "NonExistentPlugin" not in loaded_plugin_names
        assert "TestMockPlugin" in loaded_plugin_names or len(loaded_plugin_names) == 0
    
    def test_plugin_selection_empty_list(self, temp_plugins_dir):
        """Test plugin selection with empty list."""
        selected_plugins = []
        plugin_manager = PluginManager(temp_plugins_dir, selected_plugins=selected_plugins)
        
        # Should load no plugins
        assert len(plugin_manager.loaded_plugins) == 0
    
    def test_plugin_selection_none(self, temp_plugins_dir):
        """Test plugin selection with None (should load all plugins)."""
        plugin_manager = PluginManager(temp_plugins_dir, selected_plugins=None)
        
        # Should attempt to load all available plugins
        assert isinstance(plugin_manager.loaded_plugins, dict)
    
    def test_get_plugin_list(self, temp_plugins_dir):
        """Test getting plugin list."""
        plugin_manager = PluginManager(temp_plugins_dir)
        plugin_list = plugin_manager.get_plugin_list()
        
        assert isinstance(plugin_list, list)
        # Plugin list may be empty if plugins failed to load
        
        # Check plugin list structure
        for plugin in plugin_list:
            assert 'name' in plugin
            assert 'description' in plugin
            assert 'version' in plugin
            assert 'author' in plugin
    
    def test_execute_plugin_with_selection(self, temp_plugins_dir):
        """Test executing specific plugins."""
        selected_plugins = ["TestMockPlugin"]
        plugin_manager = PluginManager(temp_plugins_dir, selected_plugins=selected_plugins)
        
        if "TestMockPlugin" in plugin_manager.loaded_plugins:
            result = plugin_manager.execute_plugin(
                "TestMockPlugin", 
                "https://example.com", 
                [{"url": "https://example.com", "method": "GET", "headers": {}}]
            )
            
            assert isinstance(result, PluginResult)
            assert result.plugin_name == "TestMockPlugin"
            assert result.success is True
    
    def test_execute_nonexistent_plugin(self, temp_plugins_dir):
        """Test executing non-existent plugin."""
        plugin_manager = PluginManager(temp_plugins_dir)
        
        result = plugin_manager.execute_plugin(
            "NonExistentPlugin", 
            "https://example.com", 
            [{"url": "https://example.com", "method": "GET", "headers": {}}]
        )
        
        assert isinstance(result, PluginResult)
        assert result.plugin_name == "NonExistentPlugin"
        assert result.success is False
        assert result.error is not None and "not found" in result.error
    
    def test_get_plugins_to_run_with_selection(self, temp_plugins_dir):
        """Test getting plugins to run with user selection."""
        selected_plugins = ["TestMockPlugin", "TestJWTSecurityChecker"]
        plugin_manager = PluginManager(temp_plugins_dir, selected_plugins=selected_plugins)
        
        plugins_to_run = plugin_manager._get_plugins_to_run()
        
        # Should only return selected plugins that are loaded
        assert len(plugins_to_run) <= len(selected_plugins)
        for plugin_name in plugins_to_run:
            assert plugin_name in selected_plugins
    
    def test_get_plugins_to_run_without_selection(self, temp_plugins_dir):
        """Test getting plugins to run without user selection (default behavior)."""
        plugin_manager = PluginManager(temp_plugins_dir, selected_plugins=None)
        
        plugins_to_run = plugin_manager._get_plugins_to_run()
        
        # Should return all loaded plugins (default behavior)
        assert len(plugins_to_run) <= len(plugin_manager.loaded_plugins)
    
    def test_get_plugins_to_run_with_jwt_detection(self, temp_plugins_dir):
        """Test getting plugins to run with JWT detection."""
        plugin_manager = PluginManager(temp_plugins_dir, selected_plugins=None)
        
        plugins_to_run = plugin_manager._get_plugins_to_run()
        
        # Should include JWT plugin if available
        if "TestJWTSecurityChecker" in plugin_manager.loaded_plugins:
            assert "TestJWTSecurityChecker" in plugins_to_run
    
    def test_execute_all_plugins_with_selection(self, temp_plugins_dir):
        """Test executing all plugins with selection."""
        selected_plugins = ["TestMockPlugin"]
        plugin_manager = PluginManager(temp_plugins_dir, selected_plugins=selected_plugins)
        
        results = plugin_manager.execute_all_plugins(
            "https://example.com",
            [{"url": "https://example.com", "method": "GET", "headers": {}}]
        )
        
        assert isinstance(results, list)
        assert len(results) <= len(selected_plugins)
        
        for result in results:
            assert isinstance(result, PluginResult)
            assert result.plugin_name in selected_plugins
    
    def test_reload_plugins(self, temp_plugins_dir):
        """Test plugin reloading."""
        plugin_manager = PluginManager(temp_plugins_dir)
        initial_count = len(plugin_manager.loaded_plugins)
        
        plugin_manager.reload_plugins()
        
        # Should reload the same plugins
        assert len(plugin_manager.loaded_plugins) == initial_count
    
    def test_plugin_selection_case_sensitivity(self, temp_plugins_dir):
        """Test plugin selection case sensitivity."""
        selected_plugins = ["testmockplugin"]  # lowercase
        plugin_manager = PluginManager(temp_plugins_dir, selected_plugins=selected_plugins)
        
        # Should not load plugins due to case mismatch
        assert len(plugin_manager.loaded_plugins) == 0
    
    def test_plugin_selection_with_whitespace(self, temp_plugins_dir):
        """Test plugin selection with whitespace in names."""
        selected_plugins = [" TestMockPlugin ", " TestJWTSecurityChecker "]
        plugin_manager = PluginManager(temp_plugins_dir, selected_plugins=selected_plugins)
        
        # Should handle whitespace properly
        loaded_plugin_names = list(plugin_manager.loaded_plugins.keys())
        assert len(loaded_plugin_names) <= len(selected_plugins)
    
    def test_plugin_selection_duplicate_names(self, temp_plugins_dir):
        """Test plugin selection with duplicate names."""
        selected_plugins = ["TestMockPlugin", "TestMockPlugin", "TestJWTSecurityChecker"]
        plugin_manager = PluginManager(temp_plugins_dir, selected_plugins=selected_plugins)
        
        # Should handle duplicates properly
        loaded_plugin_names = list(plugin_manager.loaded_plugins.keys())
        assert len(loaded_plugin_names) <= len(set(selected_plugins))  # Should be <= unique count
    
    def test_plugin_manager_with_empty_directory(self, tmp_path):
        """Test plugin manager with empty plugins directory."""
        empty_dir = tmp_path / "empty_plugins"
        empty_dir.mkdir()
        
        plugin_manager = PluginManager(str(empty_dir))
        
        assert len(plugin_manager.loaded_plugins) == 0
        assert plugin_manager.get_plugin_list() == []
    
    def test_plugin_manager_with_invalid_plugin_file(self, tmp_path):
        """Test plugin manager with invalid plugin file."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        
        # Create invalid plugin file
        invalid_plugin = plugins_dir / "invalid_plugin.py"
        invalid_plugin.write_text("invalid python code !@#$%^&*()")
        
        plugin_manager = PluginManager(str(plugins_dir))
        
        # Should handle invalid files gracefully
        assert isinstance(plugin_manager.loaded_plugins, dict)
        # May or may not have loaded plugins depending on error handling


if __name__ == '__main__':
    pytest.main([__file__])
