#!/usr/bin/env python3
"""
Enhanced Report Generator
Provides comprehensive vulnerability reporting with multiple formats and advanced features
"""

import os
import json
import yaml
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import logging
import hashlib
import base64
from jinja2 import Template
import webbrowser
import tempfile

class VulnerabilityReport:
    """Represents a single vulnerability finding"""
    
    def __init__(self, 
                 title: str,
                 description: str,
                 severity: str,
                 cvss_score: Optional[float] = None,
                 cwe_id: Optional[str] = None,
                 cve_id: Optional[str] = None,
                 evidence: Optional[str] = None,
                 location: Optional[str] = None,
                 request_data: Optional[Dict[str, Any]] = None,
                 response_data: Optional[Dict[str, Any]] = None,
                 recommendations: Optional[List[str]] = None,
                 references: Optional[List[str]] = None):
        
        self.title = title
        self.description = description
        self.severity = severity
        self.cvss_score = cvss_score
        self.cwe_id = cwe_id
        self.cve_id = cve_id
        self.evidence = evidence
        self.location = location
        self.request_data = request_data or {}
        self.response_data = response_data or {}
        self.recommendations = recommendations or []
        self.references = references or []
        self.timestamp = datetime.now()
        self.id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique ID for the vulnerability"""
        content = f"{self.title}{self.location}{self.timestamp.isoformat()}"
        return hashlib.md5(content.encode()).hexdigest()[:8]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cwe_id': self.cwe_id,
            'cve_id': self.cve_id,
            'evidence': self.evidence,
            'location': self.location,
            'request_data': self.request_data,
            'response_data': self.response_data,
            'recommendations': self.recommendations,
            'references': self.references,
            'timestamp': self.timestamp.isoformat()
        }
    
    def get_severity_color(self) -> str:
        """Get color code for severity level"""
        severity_colors = {
            'critical': '#FF0000',
            'high': '#FF6600',
            'medium': '#FFCC00',
            'low': '#00CC00',
            'info': '#0066CC'
        }
        return severity_colors.get(self.severity.lower(), '#666666')

class ReportGenerator:
    """Enhanced report generator with multiple output formats"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        self.vulnerabilities: List[VulnerabilityReport] = []
        self.scan_metadata: Dict[str, Any] = {}
        self.logger = logging.getLogger(__name__)
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # HTML template for reports
        self.html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }
        .summary-item { text-align: center; padding: 15px; background: white; border-radius: 5px; border-left: 4px solid #007bff; }
        .summary-number { font-size: 2em; font-weight: bold; color: #007bff; }
        .vulnerability { margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; overflow: hidden; }
        .vuln-header { padding: 15px; background: #f8f9fa; border-bottom: 1px solid #ddd; }
        .vuln-title { font-size: 1.2em; font-weight: bold; margin-bottom: 5px; }
        .severity-badge { display: inline-block; padding: 4px 8px; border-radius: 3px; color: white; font-size: 0.8em; font-weight: bold; }
        .vuln-body { padding: 15px; }
        .vuln-section { margin-bottom: 15px; }
        .vuln-section h4 { margin-bottom: 10px; color: #333; }
        .evidence { background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; white-space: pre-wrap; }
        .recommendations { background: #e7f3ff; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff; }
        .recommendations ul { margin: 0; padding-left: 20px; }
        .chart-container { text-align: center; margin: 30px 0; }
        .severity-critical { background-color: #dc3545; }
        .severity-high { background-color: #fd7e14; }
        .severity-medium { background-color: #ffc107; }
        .severity-low { background-color: #28a745; }
        .severity-info { background-color: #17a2b8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Scan Report</h1>
            <p>Generated on {{ scan_metadata.timestamp }}</p>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-number">{{ scan_metadata.total_vulnerabilities }}</div>
                    <div>Total Findings</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">{{ scan_metadata.critical_count }}</div>
                    <div>Critical</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">{{ scan_metadata.high_count }}</div>
                    <div>High</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">{{ scan_metadata.medium_count }}</div>
                    <div>Medium</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">{{ scan_metadata.low_count }}</div>
                    <div>Low</div>
                </div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>Vulnerability Details</h2>
            {% for vuln in vulnerabilities %}
            <div class="vulnerability">
                <div class="vuln-header">
                    <div class="vuln-title">{{ vuln.title }}</div>
                    <span class="severity-badge severity-{{ vuln.severity.lower() }}">{{ vuln.severity.upper() }}</span>
                    {% if vuln.cvss_score %}
                    <span style="margin-left: 10px; color: #666;">CVSS: {{ vuln.cvss_score }}</span>
                    {% endif %}
                    {% if vuln.cwe_id %}
                    <span style="margin-left: 10px; color: #666;">CWE: {{ vuln.cwe_id }}</span>
                    {% endif %}
                </div>
                <div class="vuln-body">
                    <div class="vuln-section">
                        <h4>Description</h4>
                        <p>{{ vuln.description }}</p>
                    </div>
                    
                    {% if vuln.location %}
                    <div class="vuln-section">
                        <h4>Location</h4>
                        <p>{{ vuln.location }}</p>
                    </div>
                    {% endif %}
                    
                    {% if vuln.evidence %}
                    <div class="vuln-section">
                        <h4>Evidence</h4>
                        <div class="evidence">{{ vuln.evidence }}</div>
                    </div>
                    {% endif %}
                    
                    {% if vuln.recommendations %}
                    <div class="vuln-section">
                        <h4>Recommendations</h4>
                        <div class="recommendations">
                            <ul>
                            {% for rec in vuln.recommendations %}
                                <li>{{ rec }}</li>
                            {% endfor %}
                            </ul>
                        </div>
                    </div>
                    {% endif %}
                    
                    {% if vuln.references %}
                    <div class="vuln-section">
                        <h4>References</h4>
                        <ul>
                        {% for ref in vuln.references %}
                            <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                        {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
</body>
</html>
        """
    
    def add_vulnerability(self, vulnerability: VulnerabilityReport):
        """Add a vulnerability to the report"""
        self.vulnerabilities.append(vulnerability)
        self.logger.info(f"Added vulnerability: {vulnerability.title} ({vulnerability.severity})")
    
    def set_scan_metadata(self, metadata: Dict[str, Any]):
        """Set scan metadata information"""
        self.scan_metadata.update(metadata)
        self.scan_metadata['timestamp'] = datetime.now().isoformat()
    
    def generate_html_report(self, filename: Optional[str] = None) -> str:
        """Generate HTML report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.html"
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            # Prepare data for template
            template_data = {
                'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
                'scan_metadata': self._prepare_metadata()
            }
            
            # Render template
            template = Template(self.html_template)
            html_content = template.render(**template_data)
            
            # Write to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report generated: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")
            return ""
    
    def generate_json_report(self, filename: Optional[str] = None) -> str:
        """Generate JSON report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            report_data = {
                'metadata': self._prepare_metadata(),
                'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
                'summary': self._generate_summary()
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            
            self.logger.info(f"JSON report generated: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {e}")
            return ""
    
    def generate_csv_report(self, filename: Optional[str] = None) -> str:
        """Generate CSV report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.csv"
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'id', 'title', 'severity', 'cvss_score', 'cwe_id', 'cve_id',
                    'location', 'description', 'evidence', 'recommendations', 'timestamp'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for vuln in self.vulnerabilities:
                    vuln_dict = vuln.to_dict()
                    row = {field: vuln_dict.get(field, '') for field in fieldnames}
                    row['recommendations'] = '; '.join(row['recommendations']) if row['recommendations'] else ''
                    writer.writerow(row)
            
            self.logger.info(f"CSV report generated: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Error generating CSV report: {e}")
            return ""
    
    def generate_xml_report(self, filename: Optional[str] = None) -> str:
        """Generate XML report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.xml"
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            # Create root element
            root = ET.Element('security_report')
            
            # Add metadata
            metadata = ET.SubElement(root, 'metadata')
            for key, value in self._prepare_metadata().items():
                meta_elem = ET.SubElement(metadata, key)
                meta_elem.text = str(value)
            
            # Add vulnerabilities
            vulns_elem = ET.SubElement(root, 'vulnerabilities')
            for vuln in self.vulnerabilities:
                vuln_elem = ET.SubElement(vulns_elem, 'vulnerability')
                vuln_data = vuln.to_dict()
                
                for key, value in vuln_data.items():
                    if key == 'recommendations':
                        recs_elem = ET.SubElement(vuln_elem, key)
                        for rec in value:
                            rec_elem = ET.SubElement(recs_elem, 'recommendation')
                            rec_elem.text = rec
                    elif key == 'references':
                        refs_elem = ET.SubElement(vuln_elem, key)
                        for ref in value:
                            ref_elem = ET.SubElement(refs_elem, 'reference')
                            ref_elem.text = ref
                    else:
                        elem = ET.SubElement(vuln_elem, key)
                        elem.text = str(value)
            
            # Write to file
            tree = ET.ElementTree(root)
            tree.write(filepath, encoding='utf-8', xml_declaration=True)
            
            self.logger.info(f"XML report generated: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Error generating XML report: {e}")
            return ""
    
    def generate_all_formats(self, base_filename: Optional[str] = None) -> Dict[str, str]:
        """Generate reports in all available formats"""
        if not base_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"security_report_{timestamp}"
        
        reports = {}
        
        try:
            # Generate HTML report
            html_file = self.generate_html_report(f"{base_filename}.html")
            if html_file:
                reports['html'] = html_file
            
            # Generate JSON report
            json_file = self.generate_json_report(f"{base_filename}.json")
            if json_file:
                reports['json'] = json_file
            
            # Generate CSV report
            csv_file = self.generate_csv_report(f"{base_filename}.csv")
            if csv_file:
                reports['csv'] = csv_file
            
            # Generate XML report
            xml_file = self.generate_xml_report(f"{base_filename}.xml")
            if xml_file:
                reports['xml'] = xml_file
            
            self.logger.info(f"Generated {len(reports)} report formats")
            return reports
            
        except Exception as e:
            self.logger.error(f"Error generating all formats: {e}")
            return {}
    
    def _prepare_metadata(self) -> Dict[str, Any]:
        """Prepare metadata for reports"""
        metadata = self.scan_metadata.copy()
        
        # Add calculated fields
        metadata['total_vulnerabilities'] = len(self.vulnerabilities)
        metadata['critical_count'] = len([v for v in self.vulnerabilities if v.severity.lower() == 'critical'])
        metadata['high_count'] = len([v for v in self.vulnerabilities if v.severity.lower() == 'high'])
        metadata['medium_count'] = len([v for v in self.vulnerabilities if v.severity.lower() == 'medium'])
        metadata['low_count'] = len([v for v in self.vulnerabilities if v.severity.lower() == 'low'])
        metadata['info_count'] = len([v for v in self.vulnerabilities if v.severity.lower() == 'info'])
        
        return metadata
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        summary = {
            'total_findings': len(self.vulnerabilities),
            'severity_distribution': {},
            'top_vulnerability_types': {},
            'risk_score': 0
        }
        
        # Severity distribution
        for vuln in self.vulnerabilities:
            severity = vuln.severity.lower()
            summary['severity_distribution'][severity] = summary['severity_distribution'].get(severity, 0) + 1
        
        # Calculate risk score (weighted by severity)
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}
        for vuln in self.vulnerabilities:
            weight = severity_weights.get(vuln.severity.lower(), 0)
            summary['risk_score'] += weight
        
        return summary
    
    def open_html_report(self, filepath: Optional[str] = None):
        """Open HTML report in default browser"""
        if not filepath:
            filepath = self.generate_html_report()
        
        if filepath and os.path.exists(filepath):
            try:
                webbrowser.open(f'file://{os.path.abspath(filepath)}')
                self.logger.info(f"Opened HTML report in browser: {filepath}")
            except Exception as e:
                self.logger.error(f"Error opening HTML report: {e}")
    
    def get_report_statistics(self) -> Dict[str, Any]:
        """Get comprehensive report statistics"""
        stats = self._prepare_metadata()
        stats.update(self._generate_summary())
        
        # Add severity counts for easy access
        stats['severity_counts'] = {
            'critical': stats.get('critical_count', 0),
            'high': stats.get('high_count', 0),
            'medium': stats.get('medium_count', 0),
            'low': stats.get('low_count', 0),
            'info': stats.get('info_count', 0)
        }
        
        # Add vulnerability type analysis
        vuln_types = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.title.split()[0].lower()  # Extract first word as type
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        stats['vulnerability_types'] = vuln_types
        
        return stats

# Example usage
if __name__ == "__main__":
    # Initialize report generator
    generator = ReportGenerator()
    
    # Set scan metadata
    generator.set_scan_metadata({
        'target_url': 'https://example.com',
        'scan_type': 'API Security Scan',
        'scanner_version': '1.0.0'
    })
    
    # Add sample vulnerabilities
    vuln1 = VulnerabilityReport(
        title="SQL Injection",
        description="SQL injection vulnerability found in search parameter",
        severity="High",
        cvss_score=8.5,
        cwe_id="CWE-89",
        evidence="Parameter 'search' contains: ' OR '1'='1",
        location="/api/search?q=test",
        recommendations=[
            "Use parameterized queries",
            "Implement input validation",
            "Apply proper escaping"
        ],
        references=["https://owasp.org/www-community/attacks/SQL_Injection"]
    )
    
    generator.add_vulnerability(vuln1)
    
    # Generate reports
    reports = generator.generate_all_formats()
    print(f"Generated reports: {reports}")
    
    # Get statistics
    stats = generator.get_report_statistics()
    print(f"Report statistics: {stats}")
    
    # Open HTML report
    generator.open_html_report()
