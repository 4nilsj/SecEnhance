"""
Unit tests for src modules.
"""

import pytest
import tempfile
import os
import sqlite3
from unittest.mock import Mock, patch, MagicMock, mock_open
from datetime import datetime
import json

from api_security_scanner.core.db_manager import DatabaseManager
from api_security_scanner.core.zap_manager import ZAPManager, ZAPManagerError
from api_security_scanner.core.scanner_plugins import PluginManager, BasePlugin, Vulnerability, PluginResult
from api_security_scanner.core.report_generator import ReportGenerator


class TestDatabaseManager:
    """Test database manager functionality."""
    
    def test_database_manager_init(self, temp_db_path):
        """Test database manager initialization."""
        db_manager = DatabaseManager(temp_db_path)
        assert db_manager.db_path == temp_db_path
        assert os.path.exists(temp_db_path)
    
    def test_create_scan(self, temp_db_path):
        """Test creating a scan record."""
        db_manager = DatabaseManager(temp_db_path)
        
        scan_id = "test-scan-123"
        result = db_manager.create_scan(
            scan_id=scan_id,
            target_url="https://api.example.com",
            input_type="file",
            input_source="test.json",
            auth_type="header"
        )
        
        assert result is True
        
        # Verify scan was created
        scan = db_manager.get_scan(scan_id)
        assert scan is not None
        assert scan["scan_id"] == scan_id
        assert scan["target_url"] == "https://api.example.com"
    
    def test_save_zap_alerts(self, temp_db_path, sample_zap_alerts):
        """Test saving ZAP alerts."""
        db_manager = DatabaseManager(temp_db_path)
        
        # Create a scan first
        scan_id = "test-scan-123"
        db_manager.create_scan(scan_id, "https://api.example.com", "file", "test.json")
        
        result = db_manager.save_zap_alerts(scan_id, sample_zap_alerts)
        assert result is True
        
        # Verify alerts were saved
        alerts = db_manager.get_zap_alerts(scan_id)
        assert len(alerts) == 2
    
    def test_save_custom_alerts(self, temp_db_path, sample_vulnerability):
        """Test saving custom alerts."""
        db_manager = DatabaseManager(temp_db_path)
        
        # Create a scan first
        scan_id = "test-scan-123"
        db_manager.create_scan(scan_id, "https://api.example.com", "file", "test.json")
        
        vulnerabilities = [sample_vulnerability]
        result = db_manager.save_custom_alerts(scan_id, vulnerabilities)
        assert result is True
        
        # Verify alerts were saved
        alerts = db_manager.get_custom_alerts(scan_id)
        assert len(alerts) == 1
    
    def test_list_scans(self, temp_db_path):
        """Test listing scans."""
        db_manager = DatabaseManager(temp_db_path)
        
        # Create multiple scans
        for i in range(3):
            scan_id = f"test-scan-{i}"
            db_manager.create_scan(scan_id, f"https://api{i}.example.com", "file", f"test{i}.json")
        
        scans = db_manager.list_scans(limit=10)
        assert len(scans) == 3
    
    def test_get_scan_stats(self, temp_db_path, sample_zap_alerts):
        """Test getting scan statistics."""
        db_manager = DatabaseManager(temp_db_path)
        
        # Create scan and add alerts
        scan_id = "test-scan-123"
        db_manager.create_scan(scan_id, "https://api.example.com", "file", "test.json")
        db_manager.save_zap_alerts(scan_id, sample_zap_alerts)
        
        stats = db_manager.get_scan_stats(scan_id)
        assert stats is not None
        assert "zap_alerts_count" in stats
        assert stats["zap_alerts_count"] == 2
    
    def test_cleanup_old_scans(self, temp_db_path):
        """Test cleaning up old scans."""
        db_manager = DatabaseManager(temp_db_path)
        
        # Create a scan
        scan_id = "test-scan-123"
        db_manager.create_scan(scan_id, "https://api.example.com", "file", "test.json")
        
        # Cleanup scans older than 0 days (should remove all)
        result = db_manager.cleanup_old_scans(days=0)
        assert result is True
        
        # Verify scan was removed
        scan = db_manager.get_scan(scan_id)
        assert scan is None
    
    def test_database_error_handling(self, temp_db_path):
        """Test database error handling."""
        db_manager = DatabaseManager(temp_db_path)
        
        # Test with invalid scan_id
        scan = db_manager.get_scan("nonexistent")
        assert scan is None
        
        # Test with invalid scan_id for alerts
        alerts = db_manager.get_zap_alerts("nonexistent")
        assert alerts == []
    
    def test_database_connection_error(self):
        """Test database connection error handling."""
        # Use invalid path to trigger connection error
        invalid_path = "/invalid/path/database.db"
        
        with pytest.raises(Exception):
            DatabaseManager(invalid_path)


class TestZAPManager:
    """Test ZAP manager functionality."""
    
    def test_zap_manager_init(self):
        """Test ZAP manager initialization."""
        zap_manager = ZAPManager()
        assert zap_manager.zap_port == 8080
        assert zap_manager.zap_host == "localhost"
        assert zap_manager.zap_api_url == "http://localhost:8080"
    
    def test_zap_manager_init_with_params(self):
        """Test ZAP manager initialization with parameters."""
        zap_manager = ZAPManager(zap_path="/custom/zap", zap_port=8081, zap_host="custom-host")
        assert zap_manager.zap_path == "/custom/zap"
        assert zap_manager.zap_port == 8081
        assert zap_manager.zap_host == "custom-host"
    
    def test_is_zap_running_true(self, mock_requests):
        """Test ZAP running check when ZAP is running."""
        mock_requests["get"].return_value.status_code = 200
        mock_requests["get"].return_value.json.return_value = {"version": "2.12.0"}
        
        zap_manager = ZAPManager()
        result = zap_manager.is_zap_running()
        
        assert result is True
    
    def test_is_zap_running_false(self, mock_requests):
        """Test ZAP running check when ZAP is not running."""
        mock_requests["get"].side_effect = Exception("Connection refused")
        
        zap_manager = ZAPManager()
        result = zap_manager.is_zap_running()
        
        assert result is False
    
    def test_start_zap_success(self, mock_requests, mock_subprocess):
        """Test successful ZAP startup."""
        mock_requests["get"].return_value.status_code = 200
        mock_requests["get"].return_value.json.return_value = {"version": "2.12.0"}
        
        zap_manager = ZAPManager()
        result = zap_manager.start_zap()
        
        assert result is True
        assert zap_manager.is_running is True
    
    def test_start_zap_already_running(self, mock_requests):
        """Test ZAP startup when already running."""
        mock_requests["get"].return_value.status_code = 200
        
        zap_manager = ZAPManager()
        zap_manager.is_running = True
        
        result = zap_manager.start_zap()
        
        assert result is True
    
    def test_start_zap_failure(self, mock_requests, mock_subprocess):
        """Test ZAP startup failure."""
        mock_requests["get"].side_effect = Exception("Connection refused")
        
        zap_manager = ZAPManager()
        result = zap_manager.start_zap()
        
        assert result is False
    
    def test_stop_zap_success(self, mock_subprocess):
        """Test successful ZAP shutdown."""
        mock_process = Mock()
        mock_process.wait.return_value = 0
        mock_subprocess.return_value = mock_process
        
        zap_manager = ZAPManager()
        zap_manager.zap_process = mock_process
        zap_manager.is_running = True
        
        result = zap_manager.stop_zap()
        
        assert result is True
        assert zap_manager.is_running is False
    
    def test_spider_target_success(self, mock_requests):
        """Test successful spider operation."""
        mock_requests["get"].return_value.status_code = 200
        mock_requests["get"].return_value.json.return_value = {"scan": "spider-123"}
        
        zap_manager = ZAPManager()
        zap_manager.is_running = True
        
        success, scan_id = zap_manager.spider_target("https://api.example.com")
        
        assert success is True
        assert scan_id == "spider-123"
    
    def test_active_scan_target_success(self, mock_requests):
        """Test successful active scan operation."""
        mock_requests["get"].return_value.status_code = 200
        mock_requests["get"].return_value.json.return_value = {"scan": "scan-123"}
        
        zap_manager = ZAPManager()
        zap_manager.is_running = True
        
        success, scan_id = zap_manager.active_scan_target("https://api.example.com")
        
        assert success is True
        assert scan_id == "scan-123"
    
    def test_get_alerts_success(self, mock_requests, sample_zap_alerts):
        """Test successful alert retrieval."""
        mock_requests["get"].return_value.status_code = 200
        mock_requests["get"].return_value.json.return_value = {"alerts": sample_zap_alerts}
        
        zap_manager = ZAPManager()
        zap_manager.is_running = True
        
        alerts = zap_manager.get_alerts()
        
        assert len(alerts) == 2
        assert alerts[0]["id"] == "10011"
    
    def test_get_alerts_with_filters(self, mock_requests, sample_zap_alerts):
        """Test alert retrieval with filters."""
        mock_requests["get"].return_value.status_code = 200
        mock_requests["get"].return_value.json.return_value = {"alerts": sample_zap_alerts}
        
        zap_manager = ZAPManager()
        zap_manager.is_running = True
        
        alerts = zap_manager.get_alerts(base_url="https://api.example.com", risk_level="Low")
        
        assert len(alerts) == 1
        assert alerts[0]["risk"] == "Low"
    
    def test_zap_manager_error(self):
        """Test ZAP manager error handling."""
        with pytest.raises(ZAPManagerError):
            raise ZAPManagerError("Test error")
    
    def test_context_manager(self, mock_requests, mock_subprocess):
        """Test ZAP manager as context manager."""
        mock_requests["get"].return_value.status_code = 200
        mock_requests["get"].return_value.json.return_value = {"version": "2.12.0"}
        
        with ZAPManager() as zap_manager:
            assert zap_manager.is_running is True
        
        # Should be stopped after context exit
        assert zap_manager.is_running is False


class TestPluginManager:
    """Test plugin manager functionality."""
    
    def test_plugin_manager_init(self):
        """Test plugin manager initialization."""
        plugin_manager = PluginManager()
        assert plugin_manager.loaded_plugins == []
    
    def test_base_plugin_creation(self):
        """Test base plugin creation."""
        class TestPlugin(BasePlugin):
            name = "TestPlugin"
            description = "Test plugin"
            version = "1.0.0"
            author = "Test Author"
            
            def check(self, target_url, requests_data, auth_headers=None):
                return PluginResult(
                    plugin_name=self.name,
                    success=True,
                    vulnerabilities=[]
                )
            
            def generate_poc(self, vulnerability_id):
                return None
        
        plugin = TestPlugin()
        assert plugin.name == "TestPlugin"
        assert plugin.description == "Test plugin"
        assert plugin.version == "1.0.0"
        assert plugin.author == "Test Author"
    
    def test_vulnerability_creation(self, sample_vulnerability):
        """Test vulnerability creation."""
        vuln = Vulnerability(**sample_vulnerability)
        
        assert vuln.vuln_id == "test-001"
        assert vuln.name == "Test Vulnerability"
        assert vuln.risk == "High"
        assert vuln.cvss_score == 8.5
    
    def test_plugin_result_creation(self):
        """Test plugin result creation."""
        result = PluginResult(
            plugin_name="TestPlugin",
            success=True,
            vulnerabilities=[]
        )
        
        assert result.plugin_name == "TestPlugin"
        assert result.success is True
        assert result.vulnerabilities == []
    
    def test_plugin_manager_run_plugins(self):
        """Test running plugins."""
        plugin_manager = PluginManager()
        
        # Mock plugin
        mock_plugin = Mock()
        mock_plugin.name = "TestPlugin"
        mock_plugin.check.return_value = PluginResult(
            plugin_name="TestPlugin",
            success=True,
            vulnerabilities=[]
        )
        
        plugin_manager.loaded_plugins = [mock_plugin]
        
        requests_data = [{"url": "https://api.example.com/users", "method": "GET"}]
        results = plugin_manager.run_plugins("https://api.example.com", requests_data)
        
        assert len(results) == 1
        assert results[0].plugin_name == "TestPlugin"
        assert results[0].success is True
    
    def test_plugin_manager_with_exception(self):
        """Test plugin manager with plugin exception."""
        plugin_manager = PluginManager()
        
        # Mock plugin that raises exception
        mock_plugin = Mock()
        mock_plugin.name = "TestPlugin"
        mock_plugin.check.side_effect = Exception("Plugin error")
        
        plugin_manager.loaded_plugins = [mock_plugin]
        
        requests_data = [{"url": "https://api.example.com/users", "method": "GET"}]
        results = plugin_manager.run_plugins("https://api.example.com", requests_data)
        
        # Should handle exception gracefully
        assert len(results) == 0


class TestReportGenerator:
    """Test report generator functionality."""
    
    def test_report_generator_init(self, temp_reports_dir):
        """Test report generator initialization."""
        report_generator = ReportGenerator(temp_reports_dir)
        assert report_generator.reports_dir == temp_reports_dir
    
    def test_generate_html_report(self, temp_reports_dir, sample_scan_data, sample_zap_alerts):
        """Test HTML report generation."""
        report_generator = ReportGenerator(temp_reports_dir)
        
        # Mock template rendering
        with patch('jinja2.Environment.get_template') as mock_template:
            mock_template.return_value.render.return_value = "<html>Test Report</html>"
            
            result = report_generator.generate_html_report(
                scan_data=sample_scan_data,
                zap_alerts=sample_zap_alerts,
                custom_alerts=[],
                output_file="test-report.html"
            )
            
            assert result is True
            assert os.path.exists(os.path.join(temp_reports_dir, "test-report.html"))
    
    def test_generate_json_report(self, temp_reports_dir, sample_scan_data, sample_zap_alerts):
        """Test JSON report generation."""
        report_generator = ReportGenerator(temp_reports_dir)
        
        result = report_generator.generate_json_report(
            scan_data=sample_scan_data,
            zap_alerts=sample_zap_alerts,
            custom_alerts=[],
            output_file="test-report.json"
        )
        
        assert result is True
        assert os.path.exists(os.path.join(temp_reports_dir, "test-report.json"))
        
        # Verify JSON content
        with open(os.path.join(temp_reports_dir, "test-report.json"), 'r') as f:
            report_data = json.load(f)
        
        assert "scan_data" in report_data
        assert "zap_alerts" in report_data
        assert "custom_alerts" in report_data
    
    def test_generate_report_invalid_data(self, temp_reports_dir):
        """Test report generation with invalid data."""
        report_generator = ReportGenerator(temp_reports_dir)
        
        # Test with None data
        result = report_generator.generate_html_report(
            scan_data=None,
            zap_alerts=None,
            custom_alerts=None,
            output_file="test-report.html"
        )
        
        assert result is False
    
    def test_generate_report_invalid_directory(self):
        """Test report generation with invalid directory."""
        invalid_dir = "/invalid/directory"
        report_generator = ReportGenerator(invalid_dir)
        
        result = report_generator.generate_html_report(
            scan_data={},
            zap_alerts=[],
            custom_alerts=[],
            output_file="test-report.html"
        )
        
        assert result is False
    
    def test_get_template_path(self, temp_reports_dir):
        """Test getting template path."""
        report_generator = ReportGenerator(temp_reports_dir)
        
        # Should return default template path
        template_path = report_generator._get_template_path()
        assert template_path is not None
    
    def test_format_scan_data(self, sample_scan_data):
        """Test formatting scan data."""
        report_generator = ReportGenerator("/tmp")
        
        formatted_data = report_generator._format_scan_data(sample_scan_data)
        
        assert "formatted_start_time" in formatted_data
        assert "formatted_end_time" in formatted_data
        assert "duration" in formatted_data
    
    def test_calculate_risk_statistics(self, sample_zap_alerts):
        """Test calculating risk statistics."""
        report_generator = ReportGenerator("/tmp")
        
        stats = report_generator._calculate_risk_statistics(sample_zap_alerts)
        
        assert "high" in stats
        assert "medium" in stats
        assert "low" in stats
        assert "informational" in stats
        assert stats["low"] == 1
        assert stats["informational"] == 1
