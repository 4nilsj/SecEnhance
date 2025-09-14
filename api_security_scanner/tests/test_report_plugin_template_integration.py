"""
Unit tests for report generation with plugin and template information integration.
Tests the complete flow from scan creation to report generation with plugin/template data.
"""

import pytest
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from api_security_scanner.core.db_manager import DatabaseManager
from api_security_scanner.core.report_generator import ReportGenerator
from api_security_scanner.core.scanner_plugins import Vulnerability


class TestReportPluginTemplateIntegration:
    """Test complete integration of plugin and template information in reports."""
    
    def test_complete_scan_to_report_flow_with_template_and_plugins(self, tmp_path):
        """Test complete flow from scan creation to report generation with template and plugins."""
        db_path = tmp_path / "integration_test.db"
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        
        # Initialize database manager
        db_manager = DatabaseManager(str(db_path))
        
        # Create a scan with plugin and template information
        scan_id = "integration_test_scan"
        db_manager.create_scan(
            scan_id=scan_id,
            target_url="https://api.example.com",
            input_type="curl",
            input_source="curl -X GET https://api.example.com -H 'Authorization: Bearer token'",
            auth_type="bearer",
            plugins_used="JWTSecurityChecker,SecurityHeadersChecker,CORSChecker",
            template_used="jwt-focused"
        )
        
        # Create sample vulnerabilities
        vulnerabilities = [
            Vulnerability(
                id="jwt_vuln_1",
                name="JWT Algorithm Confusion",
                description="JWT token uses weak algorithm",
                risk="High",
                cvss_score=8.5,
                solution="Use strong algorithm like RS256",
                references=["https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/"],
                cwe_id="CWE-327",
                wasc_id="WASC-15",
                request="GET /api/protected HTTP/1.1\nAuthorization: Bearer eyJ...",
                response="HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"data\": \"sensitive\"}",
                url="https://api.example.com/api/protected",
                parameter="Authorization header",
                evidence="JWT token uses 'none' algorithm",
                scan_id=scan_id,
                timestamp=datetime.now()
            ),
            Vulnerability(
                id="header_vuln_1",
                name="Missing Security Headers",
                description="API is missing important security headers",
                risk="Medium",
                cvss_score=6.1,
                solution="Implement security headers",
                references=["https://owasp.org/www-community/controls/HTTP_Strict_Transport_Security"],
                cwe_id="CWE-319",
                wasc_id="WASC-15",
                request="GET /api/protected HTTP/1.1",
                response="HTTP/1.1 200 OK\n\n{\"data\": \"response\"}",
                url="https://api.example.com/api/protected",
                parameter="Response headers",
                evidence="Missing Strict-Transport-Security header",
                scan_id=scan_id,
                timestamp=datetime.now()
            )
        ]
        
        # Create performance stats
        performance_stats = [
            {
                'phase_name': 'JWT Security Analysis',
                'duration': 2.5,
                'start_time': datetime.now(),
                'end_time': datetime.now()
            },
            {
                'phase_name': 'Security Headers Check',
                'duration': 1.2,
                'start_time': datetime.now(),
                'end_time': datetime.now()
            }
        ]
        
        # Generate reports
        report_generator = ReportGenerator()
        
        # Test HTML report
        html_path = reports_dir / "integration_test.html"
        html_success = report_generator.generate_report(
            {
                'scan_id': scan_id,
                'target_url': 'https://api.example.com',
                'start_time': '2025-01-01 10:00:00',
                'end_time': '2025-01-01 10:05:00',
                'input_type': 'curl',
                'input_source': 'curl -X GET https://api.example.com -H \'Authorization: Bearer token\'',
                'auth_type': 'bearer',
                'plugins_used': 'JWTSecurityChecker,SecurityHeadersChecker,CORSChecker',
                'template_used': 'jwt-focused'
            },
            vulnerabilities,
            performance_stats,
            str(html_path)
        )
        
        assert html_success is True
        assert html_path.exists()
        
        # Verify HTML content includes plugin and template info
        html_content = html_path.read_text(encoding='utf-8')
        assert 'Scan Template:</strong> jwt-focused' in html_content
        assert 'Plugins Used:</strong> JWTSecurityChecker,SecurityHeadersChecker,CORSChecker' in html_content
        assert 'JWT Algorithm Confusion' in html_content
        assert 'Missing Security Headers' in html_content
        
        # Test JSON report
        json_path = reports_dir / "integration_test.json"
        json_success = report_generator.generate_json_report(
            {
                'scan_id': scan_id,
                'target_url': 'https://api.example.com',
                'start_time': '2025-01-01 10:00:00',
                'end_time': '2025-01-01 10:05:00',
                'input_type': 'curl',
                'input_source': 'curl -X GET https://api.example.com -H \'Authorization: Bearer token\'',
                'auth_type': 'bearer',
                'plugins_used': 'JWTSecurityChecker,SecurityHeadersChecker,CORSChecker',
                'template_used': 'jwt-focused'
            },
            vulnerabilities,
            performance_stats,
            str(json_path)
        )
        
        assert json_success is True
        assert json_path.exists()
        
        # Verify JSON content
        with open(json_path, 'r') as f:
            json_data = json.load(f)
        
        assert json_data['scan_metadata']['plugins_used'] == 'JWTSecurityChecker,SecurityHeadersChecker,CORSChecker'
        assert json_data['scan_metadata']['template_used'] == 'jwt-focused'
        assert len(json_data['vulnerabilities']) == 2
        assert json_data['vulnerabilities'][0]['name'] == 'JWT Algorithm Confusion'
        assert json_data['vulnerabilities'][1]['name'] == 'Missing Security Headers'
    
    def test_report_with_mixed_vulnerability_sources(self, tmp_path):
        """Test report generation with vulnerabilities from different sources (ZAP and custom plugins)."""
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        
        # Create mixed vulnerabilities (ZAP alerts and custom plugin alerts)
        zap_alerts = [
            {
                'id': 'zap_alert_1',
                'name': 'Cross-Site Scripting (Reflected)',
                'description': 'The application is vulnerable to reflected XSS',
                'risk': 'High',
                'cvss_score': 7.5,
                'solution': 'Implement proper input validation and output encoding',
                'references': ['https://owasp.org/www-community/attacks/xss/'],
                'cwe_id': 'CWE-79',
                'wasc_id': 'WASC-8',
                'request': 'GET /search?q=<script>alert(1)</script> HTTP/1.1',
                'response': 'HTTP/1.1 200 OK\n\n<html><body>Search results for <script>alert(1)</script></body></html>',
                'url': 'https://example.com/search',
                'parameter': 'q',
                'evidence': 'Reflected XSS in search parameter',
                'scan_id': 'mixed_test_scan',
                'timestamp': datetime.now().isoformat()
            }
        ]
        
        custom_alerts = [
            Vulnerability(
                id="custom_alert_1",
                name="Insecure JWT Implementation",
                description="JWT tokens are not properly validated",
                risk="Critical",
                cvss_score=9.0,
                solution="Implement proper JWT validation",
                references=["https://tools.ietf.org/html/rfc7519"],
                cwe_id="CWE-347",
                wasc_id="WASC-15",
                request="GET /api/user HTTP/1.1\nAuthorization: Bearer invalid_token",
                response="HTTP/1.1 200 OK\n\n{\"user\": \"admin\"}",
                url="https://api.example.com/api/user",
                parameter="Authorization header",
                evidence="JWT token accepted without proper validation",
                scan_id="mixed_test_scan",
                timestamp=datetime.now()
            )
        ]
        
        # Combine all vulnerabilities
        all_vulnerabilities = zap_alerts + custom_alerts
        
        # Generate report
        report_generator = ReportGenerator()
        html_path = reports_dir / "mixed_sources_test.html"
        
        html_success = report_generator.generate_report(
            {
                'scan_id': 'mixed_test_scan',
                'target_url': 'https://example.com',
                'start_time': '2025-01-01 10:00:00',
                'end_time': '2025-01-01 10:10:00',
                'input_type': 'file',
                'input_source': 'collection.json',
                'plugins_used': 'JWTSecurityChecker,SecurityHeadersChecker',
                'template_used': 'comprehensive'
            },
            all_vulnerabilities,
            [],
            str(html_path)
        )
        
        assert html_success is True
        assert html_path.exists()
        
        # Verify content includes both types of vulnerabilities
        html_content = html_path.read_text(encoding='utf-8')
        assert 'Cross-Site Scripting (Reflected)' in html_content
        assert 'Insecure JWT Implementation' in html_content
        assert 'Plugins Used:</strong> JWTSecurityChecker,SecurityHeadersChecker' in html_content
        assert 'Scan Template:</strong> comprehensive' in html_content
    
    def test_report_with_no_plugin_template_info(self, tmp_path):
        """Test report generation without plugin and template information."""
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        
        vulnerabilities = [
            Vulnerability(
                id="basic_vuln_1",
                name="Basic Security Issue",
                description="A basic security issue found",
                risk="Low",
                cvss_score=3.5,
                solution="Fix the basic issue",
                references=["https://example.com/ref"],
                cwe_id="CWE-200",
                wasc_id="WASC-15",
                request="GET /test HTTP/1.1",
                response="HTTP/1.1 200 OK\n\n{\"data\": \"test\"}",
                url="https://example.com/test",
                parameter="test_param",
                evidence="Basic evidence",
                scan_id="basic_test_scan",
                timestamp=datetime.now()
            )
        ]
        
        report_generator = ReportGenerator()
        html_path = reports_dir / "no_plugin_template_test.html"
        
        html_success = report_generator.generate_report(
            {
                'scan_id': 'basic_test_scan',
                'target_url': 'https://example.com',
                'start_time': '2025-01-01 10:00:00',
                'end_time': '2025-01-01 10:02:00',
                'input_type': 'curl',
                'input_source': 'curl -X GET https://example.com',
                'plugins_used': None,
                'template_used': None
            },
            vulnerabilities,
            [],
            str(html_path)
        )
        
        assert html_success is True
        assert html_path.exists()
        
        # Verify content doesn't include plugin/template fields
        html_content = html_path.read_text(encoding='utf-8')
        assert 'Scan Template:' not in html_content
        assert 'Plugins Used:' not in html_content
        assert 'Basic Security Issue' in html_content
    
    def test_xml_report_plugin_template_structure(self, tmp_path):
        """Test XML report structure with plugin and template information."""
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        
        vulnerabilities = [
            Vulnerability(
                id="xml_test_vuln",
                name="XML Test Vulnerability",
                description="Test vulnerability for XML report",
                risk="Medium",
                cvss_score=5.5,
                solution="Fix the XML test vulnerability",
                references=["https://example.com/xml-ref"],
                cwe_id="CWE-300",
                wasc_id="WASC-15",
                request="GET /xml-test HTTP/1.1",
                response="HTTP/1.1 200 OK\n\n{\"xml\": \"test\"}",
                url="https://example.com/xml-test",
                parameter="xml_param",
                evidence="XML test evidence",
                scan_id="xml_test_scan",
                timestamp=datetime.now()
            )
        ]
        
        report_generator = ReportGenerator()
        xml_path = reports_dir / "xml_plugin_template_test.xml"
        
        xml_success = report_generator.generate_xml_report(
            {
                'scan_id': 'xml_test_scan',
                'target_url': 'https://example.com',
                'start_time': '2025-01-01 10:00:00',
                'end_time': '2025-01-01 10:03:00',
                'input_type': 'file',
                'input_source': 'api_spec.yaml',
                'plugins_used': 'ParameterPollutionChecker,RateLimitingChecker',
                'template_used': 'api-only'
            },
            vulnerabilities,
            [],
            str(xml_path)
        )
        
        assert xml_success is True
        assert xml_path.exists()
        
        # Parse and verify XML structure
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        # Check scan information
        scan_info = root.find('scan_information')
        assert scan_info is not None
        
        plugins_used = scan_info.find('plugins_used')
        template_used = scan_info.find('template_used')
        
        assert plugins_used is not None
        assert plugins_used.text == 'ParameterPollutionChecker,RateLimitingChecker'
        assert template_used is not None
        assert template_used.text == 'api-only'
        
        # Check vulnerabilities
        vulnerabilities_elem = root.find('vulnerabilities')
        assert vulnerabilities_elem is not None
        
        vuln_elements = vulnerabilities_elem.findall('vulnerability')
        assert len(vuln_elements) == 1
        
        first_vuln = vuln_elements[0]
        assert first_vuln.find('name').text == 'XML Test Vulnerability'
        assert first_vuln.find('risk').text == 'Medium'
        assert first_vuln.find('cvss_score').text == '5.5'
    
    def test_report_with_large_plugin_list(self, tmp_path):
        """Test report generation with a large list of plugins."""
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        
        # Create a long list of plugins
        all_plugins = [
            'SecurityHeadersChecker',
            'CORSChecker', 
            'JWTSecurityChecker',
            'ParameterPollutionChecker',
            'RateLimitingChecker',
            'ComprehensiveSecurityChecker',
            'EnhancedSecurityChecker',
            'CustomPlugin1',
            'CustomPlugin2',
            'CustomPlugin3'
        ]
        plugins_string = ','.join(all_plugins)
        
        report_generator = ReportGenerator()
        html_path = reports_dir / "large_plugin_list_test.html"
        
        html_success = report_generator.generate_report(
            {
                'scan_id': 'large_plugins_scan',
                'target_url': 'https://example.com',
                'start_time': '2025-01-01 10:00:00',
                'end_time': '2025-01-01 10:15:00',
                'input_type': 'file',
                'input_source': 'large_collection.json',
                'plugins_used': plugins_string,
                'template_used': 'comprehensive'
            },
            [],
            [],
            str(html_path)
        )
        
        assert html_success is True
        assert html_path.exists()
        
        # Verify the long plugin list is properly displayed
        html_content = html_path.read_text(encoding='utf-8')
        assert 'Plugins Used:</strong> SecurityHeadersChecker,CORSChecker,JWTSecurityChecker' in html_content
        assert 'CustomPlugin1,CustomPlugin2,CustomPlugin3' in html_content
        assert 'Scan Template:</strong> comprehensive' in html_content
    
    def test_report_with_special_characters_in_plugin_names(self, tmp_path):
        """Test report generation with special characters in plugin names."""
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        
        # Plugin names with special characters
        special_plugins = [
            'Security-Headers-Checker',
            'CORS_Checker',
            'JWT.Security.Checker',
            'Parameter&Pollution&Checker'
        ]
        plugins_string = ','.join(special_plugins)
        
        report_generator = ReportGenerator()
        html_path = reports_dir / "special_chars_test.html"
        
        html_success = report_generator.generate_report(
            {
                'scan_id': 'special_chars_scan',
                'target_url': 'https://example.com',
                'start_time': '2025-01-01 10:00:00',
                'end_time': '2025-01-01 10:05:00',
                'input_type': 'curl',
                'input_source': 'curl -X GET https://example.com',
                'plugins_used': plugins_string,
                'template_used': 'quick'
            },
            [],
            [],
            str(html_path)
        )
        
        assert html_success is True
        assert html_path.exists()
        
        # Verify special characters are properly handled
        html_content = html_path.read_text(encoding='utf-8')
        assert 'Security-Headers-Checker' in html_content
        assert 'CORS_Checker' in html_content
        assert 'JWT.Security.Checker' in html_content
        # HTML escaping converts & to &amp;
        assert 'Parameter&amp;Pollution&amp;Checker' in html_content
