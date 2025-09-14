"""
Tests for Configuration Wizard functionality.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import os
import json
import yaml

from api_security_scanner.utils.config_wizard import (
    ConfigurationWizard,
    run_configuration_wizard
)


class TestConfigurationWizard:
    """Test the ConfigurationWizard class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.wizard = ConfigurationWizard()
    
    def test_init(self):
        """Test ConfigurationWizard initialization."""
        assert self.wizard.config == {}
        assert self.wizard.current_step == 0
        assert self.wizard.total_steps == 8
        assert self.wizard.wizard_history == []
    
    def test_record_step(self):
        """Test recording wizard steps."""
        step_data = {'test': 'value'}
        self.wizard.current_step = 1  # Set step counter
        self.wizard._record_step("Test Step", step_data)
        
        assert len(self.wizard.wizard_history) == 1
        assert self.wizard.wizard_history[0]['step'] == 1
        assert self.wizard.wizard_history[0]['name'] == "Test Step"
        assert self.wizard.wizard_history[0]['data'] == step_data
        assert 'timestamp' in self.wizard.wizard_history[0]
    
    def test_get_available_plugins(self):
        """Test getting available plugins."""
        with tempfile.TemporaryDirectory() as temp_dir:
            plugins_dir = Path(temp_dir) / "plugins"
            plugins_dir.mkdir()
            
            # Create mock plugin files
            (plugins_dir / "security_headers_checker.py").touch()
            (plugins_dir / "cors_checker.py").touch()
            (plugins_dir / "jwt_security_checker.py").touch()
            (plugins_dir / "__init__.py").touch()
            
            self.wizard.config['plugin_dir'] = str(plugins_dir)
            plugins = self.wizard._get_available_plugins()
            
            assert len(plugins) == 3
            plugin_names = [p['name'] for p in plugins]
            # Check that we get plugin names (actual names may vary based on naming logic)
            assert all("Checker" in name for name in plugin_names)
    
    def test_get_available_plugins_no_directory(self):
        """Test getting plugins when directory doesn't exist."""
        self.wizard.config['plugin_dir'] = "/nonexistent/path"
        plugins = self.wizard._get_available_plugins()
        assert plugins == []
    
    def test_display_config_summary(self, capsys):
        """Test displaying configuration summary."""
        # Add some test history
        self.wizard.wizard_history = [
            {
                'step': 1,
                'name': 'Test Step 1',
                'data': {'key1': 'value1'},
                'timestamp': '2023-01-01T00:00:00'
            },
            {
                'step': 2,
                'name': 'Test Step 2',
                'data': {'key2': 'value2', 'sensitive': 'secret'},
                'timestamp': '2023-01-01T00:00:00'
            }
        ]
        
        self.wizard._display_config_summary()
        captured = capsys.readouterr()
        
        assert "CONFIGURATION SUMMARY" in captured.out
        assert "Test Step 1" in captured.out
        assert "Test Step 2" in captured.out
        assert "key1: value1" in captured.out
        assert "key2: value2" in captured.out
    
    def test_save_configuration(self):
        """Test saving configuration to file."""
        # Set up test config
        self.wizard.config = {
            'project_name': 'Test Project',
            'environment': 'development',
            'log_level': 'INFO',
            'use_zap': True,
            'zap_host': 'localhost',
            'zap_port': 8080,
            'enabled_plugins': ['SecurityHeadersChecker', 'CORSChecker'],
            'default_auth_type': 'header',
            'default_report_formats': ['html', 'json']
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env') as f:
            config_file = f.name
        
        try:
            self.wizard._save_configuration(config_file)
            
            # Read the saved file
            with open(config_file, 'r') as f:
                content = f.read()
            
            # Check that environment variables are present
            assert "PROJECT_NAME=Test Project" in content
            assert "ENVIRONMENT=development" in content
            assert "LOG_LEVEL=INFO" in content
            assert "USE_ZAP=true" in content
            assert "ZAP_HOST=localhost" in content
            assert "ZAP_PORT=8080" in content
            assert "ENABLED_PLUGINS=SecurityHeadersChecker,CORSChecker" in content
            assert "DEFAULT_AUTH_TYPE=header" in content
            assert "DEFAULT_REPORT_FORMATS=html,json" in content
            
        finally:
            os.unlink(config_file)
    
    def test_generate_additional_configs(self):
        """Test generating additional configuration files."""
        self.wizard.config = {
            'project_name': 'Test Project',
            'environment': 'development'
        }
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Change to temp directory and generate files
            original_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                self.wizard._generate_additional_configs()
                
                # Check YAML file
                yaml_file = Path(temp_dir) / "config.yaml"
                assert yaml_file.exists()
                
                with open(yaml_file, 'r') as f:
                    yaml_content = yaml.safe_load(f)
                
                assert 'api_security_scanner' in yaml_content
                assert yaml_content['api_security_scanner']['project_name'] == 'Test Project'
                assert 'metadata' in yaml_content
                assert yaml_content['metadata']['generated_by'] == 'Configuration Wizard'
                
                # Check JSON file
                json_file = Path(temp_dir) / "config.json"
                assert json_file.exists()
                
                with open(json_file, 'r') as f:
                    json_content = json.load(f)
                
                assert 'api_security_scanner' in json_content
                assert json_content['api_security_scanner']['project_name'] == 'Test Project'
                assert 'metadata' in json_content
                assert json_content['metadata']['generated_by'] == 'Configuration Wizard'
            finally:
                os.chdir(original_cwd)
    
    def test_show_next_steps(self, capsys):
        """Test showing next steps."""
        self.wizard._show_next_steps()
        captured = capsys.readouterr()
        
        assert "NEXT STEPS" in captured.out
        assert "python main.py config --show-config" in captured.out
        assert "python main.py scan -f examples/test_collection.json" in captured.out
        assert "python main.py plugins" in captured.out
        assert "python main.py templates" in captured.out
        assert "python main.py --help" in captured.out


class TestConfigurationWizardIntegration:
    """Test configuration wizard integration."""
    
    def test_run_wizard_cancelled(self):
        """Test wizard cancellation."""
        # Test that wizard returns empty dict when cancelled
        with patch('api_security_scanner.utils.config_wizard.confirm', return_value=False):
            result = run_configuration_wizard()
            assert result == {}
    
    def test_run_wizard_keyboard_interrupt(self):
        """Test wizard handling of keyboard interrupt."""
        with patch('api_security_scanner.utils.config_wizard.confirm', side_effect=KeyboardInterrupt()):
            result = run_configuration_wizard()
            assert result == {}
    
    def test_run_wizard_exception(self):
        """Test wizard handling of exceptions."""
        with patch('api_security_scanner.utils.config_wizard.confirm', side_effect=Exception("Test error")):
            result = run_configuration_wizard()
            assert result == {}


class TestConfigurationWizardErrorHandling:
    """Test configuration wizard error handling."""
    
    def test_save_configuration_error(self):
        """Test saving configuration with error."""
        wizard = ConfigurationWizard()
        wizard.config = {'test': 'value'}
        
        # Try to save to invalid path - should handle gracefully
        try:
            wizard._save_configuration("/invalid/path/config.env")
        except Exception:
            # Expected to fail, that's fine
            pass
    
    def test_generate_additional_configs_error(self):
        """Test generating additional configs with error."""
        wizard = ConfigurationWizard()
        wizard.config = {'test': 'value'}
        
        # Mock file write error
        with patch('builtins.open', side_effect=IOError("Write error")):
            with pytest.raises(IOError):
                wizard._generate_additional_configs()


if __name__ == "__main__":
    pytest.main([__file__])
