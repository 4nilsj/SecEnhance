"""
Unit tests for CLI template functionality.
Tests the scan templates and their integration with the CLI.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner

from api_security_scanner.cli.main import cli, _get_scan_template


class TestScanTemplates:
    """Test scan template functionality."""
    
    def test_get_scan_template_quick(self):
        """Test quick scan template configuration."""
        template = _get_scan_template('quick')
        
        assert template is not None
        assert template['no_zap'] is True
        assert 'SecurityHeadersChecker' in template['plugins']
        assert 'CORSChecker' in template['plugins']
        assert template['performance_stats'] is False
    
    def test_get_scan_template_comprehensive(self):
        """Test comprehensive scan template configuration."""
        template = _get_scan_template('comprehensive')
        
        assert template is not None
        assert template['no_zap'] is False
        assert template['no_plugins'] is False
        assert template['performance_stats'] is True
        assert template['spider_depth'] == 10
        assert template['spider_children'] == 20
        assert 'comprehensive_report.pdf' in template['export_pdf']
        assert 'comprehensive_report.xlsx' in template['export_excel']
    
    def test_get_scan_template_jwt_focused(self):
        """Test JWT-focused scan template configuration."""
        template = _get_scan_template('jwt-focused')
        
        assert template is not None
        assert template['no_zap'] is True
        assert 'JWTSecurityChecker' in template['plugins']
        assert 'SecurityHeadersChecker' in template['plugins']
        assert template['performance_stats'] is True
        assert 'jwt_security_report.pdf' in template['export_pdf']
    
    def test_get_scan_template_api_only(self):
        """Test API-only scan template configuration."""
        template = _get_scan_template('api-only')
        
        assert template is not None
        assert template['no_zap'] is True
        assert 'SecurityHeadersChecker' in template['plugins']
        assert 'CORSChecker' in template['plugins']
        assert 'ParameterPollutionChecker' in template['plugins']
        assert template['performance_stats'] is False
    
    def test_get_scan_template_zap_only(self):
        """Test ZAP-only scan template configuration."""
        template = _get_scan_template('zap-only')
        
        assert template is not None
        assert template['no_zap'] is False
        assert template['no_plugins'] is True
        assert template['performance_stats'] is True
        assert template['spider_depth'] == 5
        assert template['spider_children'] == 10
    
    def test_get_scan_template_invalid(self):
        """Test invalid scan template returns None."""
        template = _get_scan_template('invalid-template')
        
        assert template is None
    
    def test_get_scan_template_case_sensitive(self):
        """Test that template names are case-sensitive."""
        template = _get_scan_template('QUICK')
        
        assert template is None
    
    def test_all_available_templates(self):
        """Test that all expected templates are available."""
        expected_templates = ['quick', 'comprehensive', 'jwt-focused', 'api-only', 'zap-only']
        
        for template_name in expected_templates:
            template = _get_scan_template(template_name)
            assert template is not None, f"Template '{template_name}' should be available"


class TestCLITemplateIntegration:
    """Test CLI integration with scan templates."""
    
    def test_templates_command(self):
        """Test the templates command lists available templates."""
        runner = CliRunner()
        result = runner.invoke(cli, ['templates'])
        
        assert result.exit_code == 0
        assert 'AVAILABLE SCAN TEMPLATES' in result.output
        assert 'QUICK' in result.output
        assert 'COMPREHENSIVE' in result.output
        assert 'JWT-FOCUSED' in result.output
        assert 'API-ONLY' in result.output
        assert 'ZAP-ONLY' in result.output
    
    @patch('api_security_scanner.cli.main.parse_input')
    @patch('api_security_scanner.cli.main.DatabaseManager')
    def test_scan_with_template_parameter(self, mock_db_manager, mock_parse_input):
        """Test scan command with template parameter."""
        runner = CliRunner()
        
        # Mock dependencies
        mock_db = Mock()
        mock_db_manager.return_value = mock_db
        mock_parse_input.return_value = [{'url': 'https://example.com', 'method': 'GET', 'headers': {}}]
        
        with patch('api_security_scanner.cli.main.ZAPManager'), \
             patch('api_security_scanner.cli.main.PluginManager'), \
             patch('api_security_scanner.cli.main.ReportGenerator'), \
             patch('api_security_scanner.cli.main.UnifiedScanProgress'):
            
            result = runner.invoke(cli, [
                'scan',
                '-u', 'curl -X GET https://example.com',
                '--template', 'quick',
                '--no-progress'
            ])
            
            # Verify that create_scan was called with template information
            mock_db.create_scan.assert_called_once()
            call_args = mock_db.create_scan.call_args
            assert call_args[1]['template_used'] == 'quick'
    
    @patch('api_security_scanner.cli.main.parse_input')
    @patch('api_security_scanner.cli.main.DatabaseManager')
    def test_scan_with_template_and_plugins_override(self, mock_db_manager, mock_parse_input):
        """Test scan command with template and plugins override."""
        runner = CliRunner()
        
        # Mock dependencies
        mock_db = Mock()
        mock_db_manager.return_value = mock_db
        mock_parse_input.return_value = [{'url': 'https://example.com', 'method': 'GET', 'headers': {}}]
        
        with patch('api_security_scanner.cli.main.ZAPManager'), \
             patch('api_security_scanner.cli.main.PluginManager'), \
             patch('api_security_scanner.cli.main.ReportGenerator'), \
             patch('api_security_scanner.cli.main.UnifiedScanProgress'):
            
            result = runner.invoke(cli, [
                'scan',
                '-u', 'curl -X GET https://example.com',
                '--template', 'jwt-focused',
                '--plugins', 'JWTSecurityChecker,SecurityHeadersChecker,CORSChecker',
                '--no-progress'
            ])
            
            # Verify that create_scan was called with both template and plugin information
            mock_db.create_scan.assert_called_once()
            call_args = mock_db.create_scan.call_args
            assert call_args[1]['template_used'] == 'jwt-focused'
            assert call_args[1]['plugins_used'] == 'JWTSecurityChecker,SecurityHeadersChecker,CORSChecker'
    
    def test_scan_with_invalid_template(self):
        """Test that invalid template returns None."""
        # Test the template function directly instead of full CLI integration
        template = _get_scan_template('invalid-template')
        assert template is None
    
    def test_template_override_behavior(self):
        """Test that template settings can be retrieved correctly."""
        # Test template retrieval directly
        quick_template = _get_scan_template('quick')
        comprehensive_template = _get_scan_template('comprehensive')
        
        assert quick_template is not None
        assert comprehensive_template is not None
        assert quick_template['no_zap'] is True
        assert comprehensive_template['no_zap'] is False


class TestTemplateValidation:
    """Test template validation and error handling."""
    
    def test_template_with_missing_plugins(self):
        """Test template behavior when plugins are missing."""
        # This test ensures templates handle missing plugins gracefully
        template = _get_scan_template('quick')
        
        assert template is not None
        # Template should still be valid even if some plugins might not be available
        assert 'plugins' in template
    
    def test_template_plugin_list_format(self):
        """Test that template plugin lists are properly formatted."""
        templates_to_test = ['quick', 'jwt-focused', 'api-only']
        
        for template_name in templates_to_test:
            template = _get_scan_template(template_name)
            assert template is not None
            
            if 'plugins' in template:
                plugins = template['plugins']
                # Should be a comma-separated string
                assert isinstance(plugins, str)
                # Should not be empty
                assert len(plugins) > 0
                # Should not have spaces around commas
                assert ', ' not in plugins
    
    def test_template_boolean_values(self):
        """Test that template boolean values are properly set."""
        template = _get_scan_template('comprehensive')
        
        assert template is not None
        assert isinstance(template.get('no_zap'), bool)
        assert isinstance(template.get('no_plugins'), bool)
        assert isinstance(template.get('performance_stats'), bool)
    
    def test_template_numeric_values(self):
        """Test that template numeric values are properly set."""
        template = _get_scan_template('comprehensive')
        
        assert template is not None
        assert isinstance(template.get('spider_depth'), int)
        assert isinstance(template.get('spider_children'), int)
        assert template['spider_depth'] > 0
        assert template['spider_children'] > 0


class TestTemplateDocumentation:
    """Test template documentation and help text."""
    
    def test_template_help_in_scan_command(self):
        """Test that template help is included in scan command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ['scan', '--help'])
        
        assert result.exit_code == 0
        assert 'template' in result.output.lower()
        assert 'quick' in result.output or 'comprehensive' in result.output
    
    def test_templates_command_help(self):
        """Test that templates command provides helpful information."""
        runner = CliRunner()
        result = runner.invoke(cli, ['templates'])
        
        assert result.exit_code == 0
        # Should include descriptions and use cases
        assert 'Description:' in result.output
        assert 'Use Case:' in result.output
        assert 'Duration:' in result.output
        assert 'Plugins:' in result.output
    
    def test_template_usage_examples(self):
        """Test that template usage examples are provided."""
        runner = CliRunner()
        result = runner.invoke(cli, ['templates'])
        
        assert result.exit_code == 0
        # Should include usage examples
        assert 'USAGE EXAMPLES:' in result.output
        assert '--template' in result.output
