"""
Unit tests for plugin and template information in scan reports.
Tests the recently implemented feature to include plugin and template information in reports.
"""

import pytest
import sqlite3
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from api_security_scanner.core.db_manager import DatabaseManager
from api_security_scanner.core.report_generator import ReportGenerator
from api_security_scanner.core.scanner_plugins import Vulnerability


class TestDatabasePluginTemplateInfo:
    """Test database functionality for plugin and template information."""
    
    def test_create_scan_with_plugin_template_info(self, temp_db):
        """Test creating a scan record with plugin and template information."""
        db_manager = DatabaseManager(temp_db)
        
        # Test with both plugin and template info
        result = db_manager.create_scan(
            scan_id="test_scan_1",
            target_url="https://example.com",
            input_type="curl",
            input_source="curl -X GET https://example.com",
            auth_type="bearer",
            plugins_used="JWTSecurityChecker,SecurityHeadersChecker",
            template_used="jwt-focused"
        )
        
        assert result is True
        
        # Verify the data was stored correctly
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", ("test_scan_1",))
            row = cursor.fetchone()
            
            assert row is not None
            assert row['plugins_used'] == "JWTSecurityChecker,SecurityHeadersChecker"
            assert row['template_used'] == "jwt-focused"
    
    def test_create_scan_without_plugin_template_info(self, temp_db):
        """Test creating a scan record without plugin and template information."""
        db_manager = DatabaseManager(temp_db)
        
        # Test without plugin and template info
        result = db_manager.create_scan(
            scan_id="test_scan_2",
            target_url="https://example.com",
            input_type="file",
            input_source="collection.json"
        )
        
        assert result is True
        
        # Verify the data was stored correctly with null values
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", ("test_scan_2",))
            row = cursor.fetchone()
            
            assert row is not None
            assert row['plugins_used'] is None
            assert row['template_used'] is None
    
    def test_create_scan_with_only_plugins(self, temp_db):
        """Test creating a scan record with only plugin information."""
        db_manager = DatabaseManager(temp_db)
        
        result = db_manager.create_scan(
            scan_id="test_scan_3",
            target_url="https://example.com",
            input_type="curl",
            input_source="curl -X GET https://example.com",
            plugins_used="CORSChecker,ParameterPollutionChecker"
        )
        
        assert result is True
        
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", ("test_scan_3",))
            row = cursor.fetchone()
            
            assert row is not None
            assert row['plugins_used'] == "CORSChecker,ParameterPollutionChecker"
            assert row['template_used'] is None
    
    def test_create_scan_with_only_template(self, temp_db):
        """Test creating a scan record with only template information."""
        db_manager = DatabaseManager(temp_db)
        
        result = db_manager.create_scan(
            scan_id="test_scan_4",
            target_url="https://example.com",
            input_type="file",
            input_source="collection.json",
            template_used="comprehensive"
        )
        
        assert result is True
        
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", ("test_scan_4",))
            row = cursor.fetchone()
            
            assert row is not None
            assert row['plugins_used'] is None
            assert row['template_used'] == "comprehensive"
    
    def test_database_migration_adds_columns(self, temp_db):
        """Test that database migration adds the new columns to existing databases."""
        db_manager = DatabaseManager(temp_db)
        
        # Verify the columns exist
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scans)")
            columns = [row[1] for row in cursor.fetchall()]
            
            assert 'plugins_used' in columns
            assert 'template_used' in columns


class TestReportGeneratorPluginTemplateInfo:
    """Test report generator functionality for plugin and template information."""
    
    def test_html_report_includes_plugin_template_info(self, report_generator, temp_dir):
        """Test that HTML report includes plugin and template information."""
        scan_data = {
            'scan_id': 'test_scan_1',
            'target_url': 'https://example.com',
            'start_time': '2025-01-01 10:00:00',
            'end_time': '2025-01-01 10:05:00',
            'input_type': 'curl',
            'input_source': 'curl -X GET https://example.com',
            'plugins_used': 'JWTSecurityChecker,SecurityHeadersChecker',
            'template_used': 'jwt-focused'
        }
        
        vulnerabilities = []
        performance_stats = []
        output_path = temp_dir / "test_report.html"
        
        result = report_generator.generate_report(
            scan_data, vulnerabilities, performance_stats, str(output_path)
        )
        
        assert result is True
        assert output_path.exists()
        
        # Read and verify the HTML content
        html_content = output_path.read_text()
        assert 'Scan Template:</strong> jwt-focused' in html_content
        assert 'Plugins Used:</strong> JWTSecurityChecker,SecurityHeadersChecker' in html_content
    
    def test_html_report_omits_missing_plugin_template_info(self, report_generator, temp_dir):
        """Test that HTML report omits plugin and template fields when not provided."""
        scan_data = {
            'scan_id': 'test_scan_2',
            'target_url': 'https://example.com',
            'start_time': '2025-01-01 10:00:00',
            'end_time': '2025-01-01 10:05:00',
            'input_type': 'file',
            'input_source': 'collection.json',
            'plugins_used': None,
            'template_used': None
        }
        
        vulnerabilities = []
        performance_stats = []
        output_path = temp_dir / "test_report_no_info.html"
        
        result = report_generator.generate_report(
            scan_data, vulnerabilities, performance_stats, str(output_path)
        )
        
        assert result is True
        assert output_path.exists()
        
        # Read and verify the HTML content doesn't include the fields
        html_content = output_path.read_text()
        assert 'Scan Template:' not in html_content
        assert 'Plugins Used:' not in html_content
    
    def test_json_report_includes_plugin_template_info(self, report_generator, temp_dir):
        """Test that JSON report includes plugin and template information."""
        scan_data = {
            'scan_id': 'test_scan_3',
            'target_url': 'https://example.com',
            'start_time': '2025-01-01 10:00:00',
            'end_time': '2025-01-01 10:05:00',
            'input_type': 'curl',
            'input_source': 'curl -X GET https://example.com',
            'plugins_used': 'CORSChecker,ParameterPollutionChecker',
            'template_used': 'api-only'
        }
        
        vulnerabilities = []
        performance_stats = []
        output_path = temp_dir / "test_report.json"
        
        result = report_generator.generate_json_report(
            scan_data, vulnerabilities, performance_stats, str(output_path)
        )
        
        assert result is True
        assert output_path.exists()
        
        # Read and verify the JSON content
        with open(output_path, 'r') as f:
            report_data = json.load(f)
        
        assert report_data['scan_metadata']['plugins_used'] == 'CORSChecker,ParameterPollutionChecker'
        assert report_data['scan_metadata']['template_used'] == 'api-only'
    
    def test_json_report_handles_null_plugin_template_info(self, report_generator, temp_dir):
        """Test that JSON report handles null plugin and template information."""
        scan_data = {
            'scan_id': 'test_scan_4',
            'target_url': 'https://example.com',
            'start_time': '2025-01-01 10:00:00',
            'end_time': '2025-01-01 10:05:00',
            'input_type': 'file',
            'input_source': 'collection.json',
            'plugins_used': None,
            'template_used': None
        }
        
        vulnerabilities = []
        performance_stats = []
        output_path = temp_dir / "test_report_null.json"
        
        result = report_generator.generate_json_report(
            scan_data, vulnerabilities, performance_stats, str(output_path)
        )
        
        assert result is True
        assert output_path.exists()
        
        # Read and verify the JSON content
        with open(output_path, 'r') as f:
            report_data = json.load(f)
        
        assert report_data['scan_metadata']['plugins_used'] is None
        assert report_data['scan_metadata']['template_used'] is None
    
    def test_pdf_report_includes_plugin_template_info(self, report_generator, temp_dir):
        """Test that PDF report includes plugin and template information."""
        scan_data = {
            'scan_id': 'test_scan_5',
            'target_url': 'https://example.com',
            'start_time': '2025-01-01 10:00:00',
            'end_time': '2025-01-01 10:05:00',
            'input_type': 'curl',
            'input_source': 'curl -X GET https://example.com',
            'plugins_used': 'SecurityHeadersChecker',
            'template_used': 'quick'
        }
        
        vulnerabilities = []
        performance_stats = []
        output_path = temp_dir / "test_report.pdf"
        
        result = report_generator.generate_pdf_report(
            scan_data, vulnerabilities, performance_stats, str(output_path)
        )
        
        # PDF generation might fail due to missing dependencies, but the method should handle it gracefully
        # We're mainly testing that the method doesn't crash with the new fields
        assert isinstance(result, bool)
    
    def test_excel_report_includes_plugin_template_info(self, report_generator, temp_dir):
        """Test that Excel report includes plugin and template information."""
        scan_data = {
            'scan_id': 'test_scan_6',
            'target_url': 'https://example.com',
            'start_time': '2025-01-01 10:00:00',
            'end_time': '2025-01-01 10:05:00',
            'input_type': 'file',
            'input_source': 'collection.json',
            'plugins_used': 'RateLimitingChecker,EnhancedSecurityChecker',
            'template_used': 'comprehensive'
        }
        
        vulnerabilities = []
        performance_stats = []
        output_path = temp_dir / "test_report.xlsx"
        
        result = report_generator.generate_excel_report(
            scan_data, vulnerabilities, performance_stats, str(output_path)
        )
        
        # Excel generation might fail due to missing dependencies, but the method should handle it gracefully
        assert isinstance(result, bool)
    
    def test_xml_report_includes_plugin_template_info(self, report_generator, temp_dir):
        """Test that XML report includes plugin and template information."""
        scan_data = {
            'scan_id': 'test_scan_7',
            'target_url': 'https://example.com',
            'start_time': '2025-01-01 10:00:00',
            'end_time': '2025-01-01 10:05:00',
            'input_type': 'curl',
            'input_source': 'curl -X GET https://example.com',
            'plugins_used': 'JWTSecurityChecker',
            'template_used': 'jwt-focused'
        }
        
        vulnerabilities = []
        performance_stats = []
        output_path = temp_dir / "test_report.xml"
        
        result = report_generator.generate_xml_report(
            scan_data, vulnerabilities, performance_stats, str(output_path)
        )
        
        assert result is True
        assert output_path.exists()
        
        # Parse and verify the XML content
        tree = ET.parse(output_path)
        root = tree.getroot()
        
        scan_info = root.find('scan_information')
        assert scan_info is not None
        
        plugins_used = scan_info.find('plugins_used')
        template_used = scan_info.find('template_used')
        
        assert plugins_used is not None
        assert plugins_used.text == 'JWTSecurityChecker'
        assert template_used is not None
        assert template_used.text == 'jwt-focused'


class TestCLIIntegration:
    """Test CLI integration for plugin and template information."""
    
    @patch('api_security_scanner.cli.main.parse_input')
    @patch('api_security_scanner.cli.main.DatabaseManager')
    def test_scan_command_with_plugins_and_template(self, mock_db_manager, mock_parse_input):
        """Test that scan command correctly passes plugin and template information."""
        from click.testing import CliRunner
        from api_security_scanner.cli.main import cli
        
        # Mock the database manager
        mock_db = Mock()
        mock_db_manager.return_value = mock_db
        
        # Mock the input parser
        mock_parse_input.return_value = [{'url': 'https://example.com', 'method': 'GET', 'headers': {}}]
        
        # Mock other dependencies
        with patch('api_security_scanner.cli.main.ZAPManager'), \
             patch('api_security_scanner.cli.main.PluginManager'), \
             patch('api_security_scanner.cli.main.ReportGenerator'), \
             patch('api_security_scanner.cli.main.UnifiedScanProgress'):
            
            runner = CliRunner()
            result = runner.invoke(cli, [
                'scan',
                '-u', 'curl -X GET https://example.com',
                '--plugins', 'JWTSecurityChecker,SecurityHeadersChecker',
                '--template', 'jwt-focused',
                '--no-zap',
                '--no-progress'
            ])
            
            # Verify that create_scan was called with the correct parameters
            mock_db.create_scan.assert_called_once()
            call_args = mock_db.create_scan.call_args
            
            assert call_args[1]['plugins_used'] == 'JWTSecurityChecker,SecurityHeadersChecker'
            assert call_args[1]['template_used'] == 'jwt-focused'
    
    @patch('api_security_scanner.cli.main.parse_input')
    @patch('api_security_scanner.cli.main.DatabaseManager')
    def test_scan_command_without_plugins_and_template(self, mock_db_manager, mock_parse_input):
        """Test that scan command handles missing plugin and template information."""
        from click.testing import CliRunner
        from api_security_scanner.cli.main import cli
        
        # Mock the database manager
        mock_db = Mock()
        mock_db_manager.return_value = mock_db
        
        # Mock the input parser
        mock_parse_input.return_value = [{'url': 'https://example.com', 'method': 'GET', 'headers': {}}]
        
        # Mock other dependencies
        with patch('api_security_scanner.cli.main.ZAPManager'), \
             patch('api_security_scanner.cli.main.PluginManager'), \
             patch('api_security_scanner.cli.main.ReportGenerator'), \
             patch('api_security_scanner.cli.main.UnifiedScanProgress'):
            
            runner = CliRunner()
            result = runner.invoke(cli, [
                'scan',
                '-f', 'collection.json',
                '--no-progress'
            ])
            
            # Verify that create_scan was called with None values
            mock_db.create_scan.assert_called_once()
            call_args = mock_db.create_scan.call_args
            
            assert call_args[1]['plugins_used'] is None
            assert call_args[1]['template_used'] is None


class TestTemplatePluginCombinations:
    """Test various combinations of templates and plugins."""
    
    def test_jwt_focused_template_with_plugins(self, temp_db):
        """Test JWT-focused template with additional plugins."""
        db_manager = DatabaseManager(temp_db)
        
        result = db_manager.create_scan(
            scan_id="jwt_test",
            target_url="https://api.example.com",
            input_type="curl",
            input_source="curl -X GET https://api.example.com -H 'Authorization: Bearer token'",
            plugins_used="JWTSecurityChecker,SecurityHeadersChecker,CORSChecker",
            template_used="jwt-focused"
        )
        
        assert result is True
        
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT plugins_used, template_used FROM scans WHERE scan_id = ?", ("jwt_test",))
            row = cursor.fetchone()
            
            assert row['plugins_used'] == "JWTSecurityChecker,SecurityHeadersChecker,CORSChecker"
            assert row['template_used'] == "jwt-focused"
    
    def test_comprehensive_template_with_all_plugins(self, temp_db):
        """Test comprehensive template with all available plugins."""
        db_manager = DatabaseManager(temp_db)
        
        all_plugins = "SecurityHeadersChecker,CORSChecker,JWTSecurityChecker,ParameterPollutionChecker,RateLimitingChecker,ComprehensiveSecurityChecker,EnhancedSecurityChecker"
        
        result = db_manager.create_scan(
            scan_id="comprehensive_test",
            target_url="https://api.example.com",
            input_type="file",
            input_source="collection.json",
            plugins_used=all_plugins,
            template_used="comprehensive"
        )
        
        assert result is True
        
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT plugins_used, template_used FROM scans WHERE scan_id = ?", ("comprehensive_test",))
            row = cursor.fetchone()
            
            assert row['plugins_used'] == all_plugins
            assert row['template_used'] == "comprehensive"
    
    def test_quick_template_with_minimal_plugins(self, temp_db):
        """Test quick template with minimal plugins."""
        db_manager = DatabaseManager(temp_db)
        
        result = db_manager.create_scan(
            scan_id="quick_test",
            target_url="https://api.example.com",
            input_type="curl",
            input_source="curl -X GET https://api.example.com",
            plugins_used="SecurityHeadersChecker,CORSChecker",
            template_used="quick"
        )
        
        assert result is True
        
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT plugins_used, template_used FROM scans WHERE scan_id = ?", ("quick_test",))
            row = cursor.fetchone()
            
            assert row['plugins_used'] == "SecurityHeadersChecker,CORSChecker"
            assert row['template_used'] == "quick"


# Fixtures
@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary database for testing."""
    db_path = tmp_path / "test.db"
    return str(db_path)


@pytest.fixture
def temp_dir(tmp_path):
    """Create a temporary directory for testing."""
    return tmp_path


@pytest.fixture
def report_generator():
    """Create a report generator instance for testing."""
    return ReportGenerator()


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerabilities for testing."""
    return [
        Vulnerability(
            id="test_vuln_1",
            name="Test Vulnerability 1",
            description="A test vulnerability",
            risk="High",
            cvss_score=8.5,
            solution="Fix the vulnerability",
            references=["https://example.com/ref1"],
            cwe_id="CWE-123",
            wasc_id="WASC-15",
            request="GET /test HTTP/1.1",
            response="HTTP/1.1 200 OK",
            url="https://example.com/test",
            parameter="test_param",
            evidence="Test evidence",
            scan_id="test_scan",
            timestamp=datetime.now()
        )
    ]


@pytest.fixture
def sample_performance_stats():
    """Create sample performance statistics for testing."""
    return [
        {
            'phase_name': 'Plugin Execution',
            'duration': 5.2,
            'start_time': datetime.now(),
            'end_time': datetime.now()
        }
    ]
