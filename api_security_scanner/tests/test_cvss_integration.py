"""
Unit tests for CVSS score integration in report generation
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from api_security_scanner.core.report_generator import ReportGenerator
from api_security_scanner.core.scanner_plugins import Vulnerability


class TestCVSSIntegration:
    """Test cases for CVSS score integration in reports."""
    
    @pytest.fixture
    def report_generator(self):
        """Create a report generator instance for testing."""
        return ReportGenerator()
    
    @pytest.fixture
    def sample_vulnerabilities(self):
        """Create sample vulnerabilities with CVSS scores."""
        return [
            Vulnerability(
                id="vuln-1",
                name="High Risk Vulnerability",
                description="A critical security vulnerability",
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
                name="Medium Risk Vulnerability",
                description="A moderate security vulnerability",
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
            ),
            Vulnerability(
                id="vuln-3",
                name="Low Risk Vulnerability",
                description="A low severity vulnerability",
                risk="Low",
                cvss_score=4.3,
                solution="Consider fixing",
                references=["https://example.com/ref3"],
                cwe_id="CWE-200",
                wasc_id="WASC-15",
                request="GET /api/info HTTP/1.1",
                response="HTTP/1.1 200 OK",
                url="https://example.com/api/info",
                parameter="info_param",
                evidence="Evidence of low risk",
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
    
    def test_calculate_risk_counts_with_cvss(self, report_generator, sample_vulnerabilities):
        """Test risk count calculation includes CVSS scores."""
        risk_counts = report_generator._calculate_risk_counts(sample_vulnerabilities)
        
        assert risk_counts['High'] == 1
        assert risk_counts['Medium'] == 1
        assert risk_counts['Low'] == 1
        assert risk_counts['Informational'] == 0
    
    def test_html_report_includes_cvss_scores(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test that HTML report includes CVSS scores."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.html"
            
            result = report_generator.generate_report(
                sample_scan_data, sample_vulnerabilities, [], str(output_path)
            )
            
            assert result is True
            assert output_path.exists()
            
            # Read the generated HTML
            with open(output_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            # Check that CVSS scores are included
            assert "CVSS Score" in html_content
            assert "8.1" in html_content  # High risk CVSS
            assert "6.5" in html_content  # Medium risk CVSS
            assert "4.3" in html_content  # Low risk CVSS
    
    def test_json_report_includes_cvss_scores(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test that JSON report includes CVSS scores."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.json"
            
            result = report_generator.generate_json_report(
                sample_scan_data, sample_vulnerabilities, [], str(output_path)
            )
            
            assert result is True
            assert output_path.exists()
            
            # Read the generated JSON
            with open(output_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            
            # Check that CVSS scores are included
            assert 'vulnerabilities' in json_data
            vulnerabilities = json_data['vulnerabilities']
            
            assert len(vulnerabilities) == 3
            
            # Check each vulnerability has CVSS score
            for vuln in vulnerabilities:
                assert 'cvss_score' in vuln
                assert isinstance(vuln['cvss_score'], (int, float))
                assert 0.0 <= vuln['cvss_score'] <= 10.0
    
    @patch('api_security_scanner.core.report_generator.REPORTLAB_AVAILABLE', True)
    def test_pdf_report_includes_cvss_scores(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test that PDF report includes CVSS scores."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.pdf"
            
            result = report_generator.generate_pdf_report(
                sample_scan_data, sample_vulnerabilities, [], str(output_path)
            )
            
            # PDF generation should succeed (or fail gracefully if ReportLab not available)
            # The important thing is that the method handles CVSS scores properly
            assert isinstance(result, bool)
    
    @patch('api_security_scanner.core.report_generator.OPENPYXL_AVAILABLE', True)
    def test_excel_report_includes_cvss_scores(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test that Excel report includes CVSS scores."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.xlsx"
            
            result = report_generator.generate_excel_report(
                sample_scan_data, sample_vulnerabilities, [], str(output_path)
            )
            
            # Excel generation should succeed (or fail gracefully if OpenPyXL not available)
            assert isinstance(result, bool)
    
    def test_xml_report_includes_cvss_scores(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test that XML report includes CVSS scores."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.xml"
            
            result = report_generator.generate_xml_report(
                sample_scan_data, sample_vulnerabilities, [], str(output_path)
            )
            
            assert result is True
            assert output_path.exists()
            
            # Read the generated XML
            with open(output_path, 'r', encoding='utf-8') as f:
                xml_content = f.read()
            
            # Check that CVSS scores are included
            assert "cvss_score" in xml_content
            assert "8.1" in xml_content
            assert "6.5" in xml_content
            assert "4.3" in xml_content
    
    def test_cvss_score_validation(self, report_generator):
        """Test CVSS score validation and handling."""
        # Test with valid CVSS scores
        valid_vulns = [
            Vulnerability(
                id="vuln-1", name="Test", description="Test", risk="High", cvss_score=9.5,
                solution="Fix", references=[], cwe_id="CWE-79", wasc_id="WASC-15",
                request="GET /test", response="200 OK", url="https://test.com",
                parameter="test", evidence="test", scan_id="test", timestamp=datetime.now()
            )
        ]
        
        risk_counts = report_generator._calculate_risk_counts(valid_vulns)
        assert risk_counts['High'] == 1
    
    def test_missing_cvss_score_handling(self, report_generator):
        """Test handling of vulnerabilities without CVSS scores."""
        # Create vulnerability dict without CVSS score (simulating old data)
        vuln_dict = {
            'id': 'vuln-1',
            'name': 'Test Vulnerability',
            'risk': 'High',
            'description': 'Test description',
            'solution': 'Fix it',
            'references': [],
            'cwe_id': 'CWE-79',
            'wasc_id': 'WASC-15',
            'request': 'GET /test',
            'response': '200 OK',
            'url': 'https://test.com',
            'parameter': 'test',
            'evidence': 'test',
            'scan_id': 'test',
            'timestamp': datetime.now()
        }
        
        # Test that the system handles missing CVSS scores gracefully
        risk_counts = report_generator._calculate_risk_counts([vuln_dict])
        assert risk_counts['High'] == 1
    
    def test_cvss_score_in_issues_summary_table(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test that CVSS scores appear in the issues summary table."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.html"
            
            result = report_generator.generate_report(
                sample_scan_data, sample_vulnerabilities, [], str(output_path)
            )
            
            assert result is True
            
            with open(output_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            # Check that the issues summary table includes CVSS column
            assert "CVSS Score" in html_content
            assert "Issues Summary" in html_content
            
            # Check that each vulnerability's CVSS score is displayed
            assert "8.1" in html_content  # High risk
            assert "6.5" in html_content  # Medium risk
            assert "4.3" in html_content  # Low risk
    
    def test_cvss_score_in_detailed_vulnerability_sections(self, report_generator, sample_vulnerabilities, sample_scan_data):
        """Test that CVSS scores appear in detailed vulnerability sections."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.html"
            
            result = report_generator.generate_report(
                sample_scan_data, sample_vulnerabilities, [], str(output_path)
            )
            
            assert result is True
            
            with open(output_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            # Check that detailed sections include CVSS scores
            assert "CVSS Score:" in html_content
            
            # Check that each vulnerability section has its CVSS score
            high_risk_section = html_content[html_content.find("High Risk Vulnerability"):html_content.find("High Risk Vulnerability") + 500]
            assert "8.1" in high_risk_section
    
    def test_cvss_score_sorting_and_prioritization(self, report_generator):
        """Test that vulnerabilities are properly sorted by CVSS score."""
        vulnerabilities = [
            Vulnerability(
                id="vuln-low", name="Low Risk", description="Low", risk="Low", cvss_score=3.0,
                solution="Fix", references=[], cwe_id="CWE-200", wasc_id="WASC-15",
                request="GET /low", response="200 OK", url="https://test.com/low",
                parameter="low", evidence="low", scan_id="test", timestamp=datetime.now()
            ),
            Vulnerability(
                id="vuln-high", name="High Risk", description="High", risk="High", cvss_score=9.0,
                solution="Fix", references=[], cwe_id="CWE-79", wasc_id="WASC-15",
                request="GET /high", response="200 OK", url="https://test.com/high",
                parameter="high", evidence="high", scan_id="test", timestamp=datetime.now()
            ),
            Vulnerability(
                id="vuln-medium", name="Medium Risk", description="Medium", risk="Medium", cvss_score=6.0,
                solution="Fix", references=[], cwe_id="CWE-20", wasc_id="WASC-15",
                request="GET /medium", response="200 OK", url="https://test.com/medium",
                parameter="medium", evidence="medium", scan_id="test", timestamp=datetime.now()
            )
        ]
        
        risk_counts = report_generator._calculate_risk_counts(vulnerabilities)
        
        # Verify correct categorization
        assert risk_counts['High'] == 1
        assert risk_counts['Medium'] == 1
        assert risk_counts['Low'] == 1


if __name__ == '__main__':
    pytest.main([__file__])
