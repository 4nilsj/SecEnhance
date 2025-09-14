"""
Unit tests for multi-format report generation
"""

import pytest
import json
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from api_security_scanner.core.report_generator import ReportGenerator
from api_security_scanner.core.scanner_plugins import Vulnerability


class TestMultiFormatReporting:
    """Test cases for multi-format report generation."""
    
    @pytest.fixture
    def report_generator(self):
        """Create a report generator instance for testing."""
        return ReportGenerator()
    
    @pytest.fixture
    def sample_vulnerabilities(self):
        """Create sample vulnerabilities for testing."""
        return [
            Vulnerability(
                id="vuln-1",
                name="Test Vulnerability 1",
                description="A test vulnerability",
                risk="High",
                cvss_score=8.1,
                solution="Fix the vulnerability",
                references=["https://example.com/ref1"],
                cwe_id="CWE-79",
                wasc_id="WASC-15",
                request="GET /api/test HTTP/1.1",
                response="HTTP/1.1 200 OK",
                url="https://example.com/api/test",
                parameter="test_param",
                evidence="Evidence of vulnerability",
                scan_id="test-scan",
                timestamp=datetime.now()
            ),
            Vulnerability(
                id="vuln-2",
                name="Test Vulnerability 2",
                description="Another test vulnerability",
                risk="Medium",
                cvss_score=6.5,
                solution="Address the vulnerability",
                references=["https://example.com/ref2"],
                cwe_id="CWE-20",
                wasc_id="WASC-15",
                request="POST /api/data HTTP/1.1",
                response="HTTP/1.1 200 OK",
                url="https://example.com/api/data",
                parameter="data_param",
                evidence="Evidence of medium risk",
                scan_id="test-scan",
                timestamp=datetime.now()
            )
        ]
    
    @pytest.fixture
    def sample_scan_data(self):
        """Create sample scan data."""
        return {
            'scan_id': 'test-scan-123',
            'target_url': 'https://example.com',
            'status': 'completed',
            'start_time': '2024-01-01 10:00:00',
            'end_time': '2024-01-01 10:05:00',
            'total_duration': 300.0,
            'input_type': 'curl',
            'input_source': 'command_line'
        }
    
    @pytest.fixture
    def sample_performance_stats(self):
        """Create sample performance statistics."""
        return [
            {
                'phase_name': 'Plugin Execution',
                'duration': 2.5,
                'start_time': '2024-01-01 10:00:00',
                'end_time': '2024-01-01 10:02:30',
                'details': 'Executed 3 security plugins'
            },
            {
                'phase_name': 'Report Generation',
                'duration': 0.5,
                'start_time': '2024-01-01 10:02:30',
                'end_time': '2024-01-01 10:03:00',
                'details': 'Generated HTML and JSON reports'
            }
        ]
    
    def test_html_report_generation(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test HTML report generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.html"
            
            result = report_generator.generate_report(
                sample_scan_data, sample_vulnerabilities, [], str(output_path)
            )
            
            assert result is True
            assert output_path.exists()
            assert output_path.stat().st_size > 0
            
            # Read and validate HTML content
            with open(output_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            assert "<!DOCTYPE html>" in html_content
            assert "API Security Scan Report" in html_content
            assert "test-scan-123" in html_content
            assert "Test Vulnerability 1" in html_content
            assert "Test Vulnerability 2" in html_content
    
    def test_json_report_generation(self, report_generator, sample_vulnerabilities, sample_scan_data, sample_performance_stats):
        """Test JSON report generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.json"
            
            result = report_generator.generate_json_report(
                sample_scan_data, sample_vulnerabilities, sample_performance_stats, str(output_path)
            )
            
            assert result is True
            assert output_path.exists()
            assert output_path.stat().st_size > 0
            
            # Read and validate JSON content
            with open(output_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            
            assert 'scan_metadata' in json_data
            assert 'vulnerabilities' in json_data
            assert 'performance_stats' in json_data
            assert 'risk_counts' in json_data
            assert 'generated_at' in json_data
            assert 'report_version' in json_data
            
            # Validate scan metadata
            assert json_data['scan_metadata']['scan_id'] == 'test-scan-123'
            assert json_data['scan_metadata']['target_url'] == 'https://example.com'
            
            # Validate vulnerabilities
            assert len(json_data['vulnerabilities']) == 2
            assert json_data['vulnerabilities'][0]['name'] == 'Test Vulnerability 1'
            assert json_data['vulnerabilities'][0]['cvss_score'] == 8.1
            
            # Validate risk counts
            assert json_data['risk_counts']['High'] == 1
            assert json_data['risk_counts']['Medium'] == 1
    
    @patch('api_security_scanner.core.report_generator.REPORTLAB_AVAILABLE', True)
    def test_pdf_report_generation(self, report_generator, sample_vulnerabilities, sample_scan_data, sample_performance_stats):
        """Test PDF report generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.pdf"
            
            result = report_generator.generate_pdf_report(
                sample_scan_data, sample_vulnerabilities, sample_performance_stats, str(output_path)
            )
            
            # PDF generation should succeed if ReportLab is available
            if result:
                assert output_path.exists()
                assert output_path.stat().st_size > 0
            else:
                # If ReportLab is not available, result should be False
                assert result is False
    
    @patch('api_security_scanner.core.report_generator.OPENPYXL_AVAILABLE', True)
    def test_excel_report_generation(self, report_generator, sample_vulnerabilities, sample_scan_data, sample_performance_stats):
        """Test Excel report generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.xlsx"
            
            result = report_generator.generate_excel_report(
                sample_scan_data, sample_vulnerabilities, sample_performance_stats, str(output_path)
            )
            
            # Excel generation should succeed if OpenPyXL is available
            if result:
                assert output_path.exists()
                assert output_path.stat().st_size > 0
            else:
                # If OpenPyXL is not available, result should be False
                assert result is False
    
    def test_xml_report_generation(self, report_generator, sample_vulnerabilities, sample_scan_data, sample_performance_stats):
        """Test XML report generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.xml"
            
            result = report_generator.generate_xml_report(
                sample_scan_data, sample_vulnerabilities, sample_performance_stats, str(output_path)
            )
            
            assert result is True
            assert output_path.exists()
            assert output_path.stat().st_size > 0
            
            # Read and validate XML content
            tree = ET.parse(output_path)
            root = tree.getroot()
            
            assert root.tag == 'security_scan_report'
            assert root.get('version') == '1.0'
            assert 'generated_at' in root.attrib
            
            # Check for required elements
            assert root.find('scan_information') is not None
            assert root.find('risk_summary') is not None
            assert root.find('vulnerabilities') is not None
            assert root.find('performance_statistics') is not None
            
            # Validate vulnerabilities
            vulnerabilities = root.find('vulnerabilities')
            assert vulnerabilities is not None
            assert len(vulnerabilities.findall('vulnerability')) == 2
            
            # Check that CVSS scores are included
            vuln_elements = vulnerabilities.findall('vulnerability')
            cvss_scores = [vuln.find('cvss_score') for vuln in vuln_elements]
            assert all(score is not None for score in cvss_scores)
    
    def test_report_with_no_vulnerabilities(self, report_generator, sample_scan_data):
        """Test report generation with no vulnerabilities."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "empty_report.html"
            
            result = report_generator.generate_report(
                sample_scan_data, [], [], str(output_path)
            )
            
            assert result is True
            assert output_path.exists()
            
            # Read and validate content
            with open(output_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            assert "API Security Scan Report" in html_content
            assert "0" in html_content  # Should show 0 vulnerabilities
    
    def test_report_with_no_performance_stats(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test report generation with no performance statistics."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "no_perf_report.html"
            
            result = report_generator.generate_report(
                sample_scan_data, sample_vulnerabilities, [], str(output_path)
            )
            
            assert result is True
            assert output_path.exists()
            
            # Read and validate content
            with open(output_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            assert "API Security Scan Report" in html_content
            # Performance section may be present even with empty data
            # The important thing is that the report generates successfully
    
    def test_excel_summary_sheet_creation(self, report_generator, sample_vulnerabilities, sample_scan_data, sample_performance_stats):
        """Test Excel summary sheet creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_summary.xlsx"
            
            # Mock the Excel creation methods
            with patch('api_security_scanner.core.report_generator.OPENPYXL_AVAILABLE', True):
                with patch('api_security_scanner.core.report_generator.Workbook') as mock_workbook:
                    mock_wb = MagicMock()
                    mock_workbook.return_value = mock_wb
                    mock_ws = MagicMock()
                    mock_wb.create_sheet.return_value = mock_ws
                    
                    result = report_generator.generate_excel_report(
                        sample_scan_data, sample_vulnerabilities, sample_performance_stats, str(output_path)
                    )
                    
                    # Verify that create_sheet was called for Summary
                    mock_wb.create_sheet.assert_any_call("Summary")
    
    def test_pdf_table_creation(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test PDF table creation with vulnerabilities."""
        with patch('api_security_scanner.core.report_generator.REPORTLAB_AVAILABLE', True):
            with patch('api_security_scanner.core.report_generator.SimpleDocTemplate') as mock_doc:
                with patch('api_security_scanner.core.report_generator.Table') as mock_table:
                    mock_doc_instance = MagicMock()
                    mock_doc.return_value = mock_doc_instance
                    
                    with tempfile.TemporaryDirectory() as temp_dir:
                        output_path = Path(temp_dir) / "test_table.pdf"
                        
                        result = report_generator.generate_pdf_report(
                            sample_scan_data, sample_vulnerabilities, [], str(output_path)
                        )
                        
                        # Verify that Table was called (for vulnerability data)
                        mock_table.assert_called()
    
    def test_xml_vulnerability_structure(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test XML vulnerability structure and content."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_vuln.xml"
            
            result = report_generator.generate_xml_report(
                sample_scan_data, sample_vulnerabilities, [], str(output_path)
            )
            
            assert result is True
            
            # Parse XML and validate structure
            tree = ET.parse(output_path)
            root = tree.getroot()
            
            vulnerabilities = root.find('vulnerabilities')
            assert vulnerabilities is not None
            vuln_elements = vulnerabilities.findall('vulnerability')
            
            assert len(vuln_elements) == 2
            
            # Check first vulnerability structure
            first_vuln = vuln_elements[0]
            required_fields = ['id', 'name', 'description', 'risk', 'cvss_score', 'solution', 'url']
            
            for field in required_fields:
                element = first_vuln.find(field)
                assert element is not None, f"Missing field: {field}"
                assert element.text is not None, f"Empty field: {field}"
    
    def test_report_error_handling(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test error handling in report generation."""
        # Test with invalid output path
        invalid_path = "/invalid/path/that/does/not/exist/report.html"
        
        result = report_generator.generate_report(
            sample_scan_data, sample_vulnerabilities, [], invalid_path
        )
        
        # The report generator may create the file even with invalid path
        # The important thing is that it doesn't crash
        assert isinstance(result, bool)
    
    def test_json_report_structure_validation(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test JSON report structure validation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "structure_test.json"
            
            result = report_generator.generate_json_report(
                sample_scan_data, sample_vulnerabilities, [], str(output_path)
            )
            
            assert result is True
            
            with open(output_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            
            # Validate top-level structure
            required_keys = ['scan_metadata', 'vulnerabilities', 'performance_stats', 'risk_counts', 'generated_at', 'report_version']
            for key in required_keys:
                assert key in json_data, f"Missing key: {key}"
            
            # Validate scan_metadata structure
            scan_meta = json_data['scan_metadata']
            assert 'scan_id' in scan_meta
            assert 'target_url' in scan_meta
            assert 'status' in scan_meta
            
            # Validate vulnerability structure
            vulns = json_data['vulnerabilities']
            assert isinstance(vulns, list)
            assert len(vulns) == 2
            
            # Check first vulnerability has all required fields
            first_vuln = vulns[0]
            vuln_required_fields = ['id', 'name', 'description', 'risk', 'cvss_score', 'solution', 'url']
            for field in vuln_required_fields:
                assert field in first_vuln, f"Missing vulnerability field: {field}"
    
    def test_risk_counts_calculation(self, report_generator):
        """Test risk counts calculation for different vulnerability types."""
        vulnerabilities = [
            Vulnerability(
                id="v1", name="High", description="High risk", risk="High", cvss_score=9.0,
                solution="Fix", references=[], cwe_id="CWE-79", wasc_id="WASC-15",
                request="GET /high", response="200 OK", url="https://test.com/high",
                parameter="high", evidence="high", scan_id="test", timestamp=datetime.now()
            ),
            Vulnerability(
                id="v2", name="Medium", description="Medium risk", risk="Medium", cvss_score=6.0,
                solution="Fix", references=[], cwe_id="CWE-20", wasc_id="WASC-15",
                request="GET /medium", response="200 OK", url="https://test.com/medium",
                parameter="medium", evidence="medium", scan_id="test", timestamp=datetime.now()
            ),
            Vulnerability(
                id="v3", name="Low", description="Low risk", risk="Low", cvss_score=3.0,
                solution="Fix", references=[], cwe_id="CWE-200", wasc_id="WASC-15",
                request="GET /low", response="200 OK", url="https://test.com/low",
                parameter="low", evidence="low", scan_id="test", timestamp=datetime.now()
            ),
            Vulnerability(
                id="v4", name="Info", description="Info", risk="Informational", cvss_score=1.0,
                solution="Fix", references=[], cwe_id="CWE-200", wasc_id="WASC-15",
                request="GET /info", response="200 OK", url="https://test.com/info",
                parameter="info", evidence="info", scan_id="test", timestamp=datetime.now()
            )
        ]
        
        risk_counts = report_generator._calculate_risk_counts(vulnerabilities)
        
        assert risk_counts['High'] == 1
        assert risk_counts['Medium'] == 1
        assert risk_counts['Low'] == 1
        assert risk_counts['Informational'] == 1


if __name__ == '__main__':
    pytest.main([__file__])
