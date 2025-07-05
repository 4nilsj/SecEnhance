#!/usr/bin/env python3
"""
Report Generator for Mobile Security Testing
Generates comprehensive security reports in various formats.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import jinja2
from pathlib import Path

class ReportGenerator:
    """Generate security reports in various formats."""
    
    def __init__(self, debug: bool = False):
        """Initialize report generator."""
        self.debug = debug
        self.logger = logging.getLogger(__name__)
        
    def generate_report(self, results: Dict[str, Any], output_file: str, format: str = "json") -> str:
        """Generate security report in specified format."""
        self.logger.info(f"Generating {format.upper()} report: {output_file}")
        
        if format.lower() == "json":
            return self._generate_json_report(results, output_file)
        elif format.lower() == "html":
            return self._generate_html_report(results, output_file)
        elif format.lower() == "pdf":
            return self._generate_pdf_report(results, output_file)
        elif format.lower() == "csv":
            return self._generate_csv_report(results, output_file)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json_report(self, results: Dict[str, Any], output_file: str) -> str:
        """Generate JSON report."""
        try:
            # Add report metadata
            report_data = {
                "report_info": {
                    "generated_at": datetime.now().isoformat(),
                    "tool_version": "1.0.0",
                    "format": "json"
                },
                "results": results
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            return output_file
            
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {str(e)}")
            raise
    
    def _generate_html_report(self, results: Dict[str, Any], output_file: str) -> str:
        """Generate HTML report."""
        try:
            # Create HTML template
            html_template = self._get_html_template()
            
            # Prepare data for template
            template_data = self._prepare_html_data(results)
            
            # Render template
            template = jinja2.Template(html_template)
            html_content = template.render(**template_data)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return output_file
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            raise
    
    def _generate_pdf_report(self, results: Dict[str, Any], output_file: str) -> str:
        """Generate PDF report."""
        try:
            # First generate HTML
            html_file = output_file.replace('.pdf', '.html')
            self._generate_html_report(results, html_file)
            
            # Convert HTML to PDF using weasyprint
            try:
                from weasyprint import HTML
                HTML(filename=html_file).write_pdf(output_file)
                os.remove(html_file)  # Clean up HTML file
            except ImportError:
                self.logger.warning("weasyprint not available, PDF generation skipped")
                return html_file
            
            return output_file
            
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {str(e)}")
            raise
    
    def _generate_csv_report(self, results: Dict[str, Any], output_file: str) -> str:
        """Generate CSV report."""
        try:
            import csv
            
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'Category', 'Type', 'Severity', 'Description', 'File', 'Recommendation'
                ])
                
                # Write vulnerabilities
                vulnerabilities = results.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    writer.writerow([
                        'Vulnerability',
                        vuln.get('type', 'Unknown'),
                        vuln.get('severity', 'Unknown'),
                        vuln.get('description', ''),
                        vuln.get('file', ''),
                        vuln.get('recommendation', '')
                    ])
                
                # Write security issues
                security_issues = results.get("security_issues", [])
                for issue in security_issues:
                    writer.writerow([
                        'Security Issue',
                        issue.get('type', 'Unknown'),
                        issue.get('severity', 'Unknown'),
                        issue.get('description', ''),
                        issue.get('file', ''),
                        issue.get('recommendation', '')
                    ])
            
            return output_file
            
        except Exception as e:
            self.logger.error(f"Error generating CSV report: {str(e)}")
            raise
    
    def _prepare_html_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for HTML template."""
        # Extract summary information
        summary = results.get("summary", {})
        scan_info = results.get("scan_info", {})
        
        # Categorize vulnerabilities by severity
        vulnerabilities = results.get("vulnerabilities", [])
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]
        high_vulns = [v for v in vulnerabilities if v.get("severity") == "high"]
        medium_vulns = [v for v in vulnerabilities if v.get("severity") == "medium"]
        low_vulns = [v for v in vulnerabilities if v.get("severity") == "low"]
        
        # Get analysis results
        static_analysis = results.get("static_analysis", {})
        dynamic_analysis = results.get("dynamic_analysis", {})
        network_analysis = results.get("network_analysis", {})
        storage_analysis = results.get("storage_analysis", {})
        code_analysis = results.get("code_analysis", {})
        
        return {
            "scan_info": scan_info,
            "summary": summary,
            "critical_vulnerabilities": critical_vulns,
            "high_vulnerabilities": high_vulns,
            "medium_vulnerabilities": medium_vulns,
            "low_vulnerabilities": low_vulns,
            "static_analysis": static_analysis,
            "dynamic_analysis": dynamic_analysis,
            "network_analysis": network_analysis,
            "storage_analysis": storage_analysis,
            "code_analysis": code_analysis,
            "recommendations": results.get("recommendations", []),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def _get_html_template(self) -> str:
        """Get HTML template for report."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mobile Security Analysis Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #007bff;
            margin: 0;
            font-size: 2.5em;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .summary-item {
            text-align: center;
            padding: 15px;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .summary-item h3 {
            margin: 0;
            color: #007bff;
        }
        .summary-item p {
            margin: 5px 0 0 0;
            font-size: 1.5em;
            font-weight: bold;
        }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .section {
            margin-bottom: 30px;
        }
        .section h2 {
            color: #007bff;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
        }
        .vulnerability {
            background-color: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 5px solid #007bff;
        }
        .vulnerability.critical { border-left-color: #dc3545; }
        .vulnerability.high { border-left-color: #fd7e14; }
        .vulnerability.medium { border-left-color: #ffc107; }
        .vulnerability.low { border-left-color: #28a745; }
        .vulnerability h4 {
            margin: 0 0 10px 0;
            color: #333;
        }
        .vulnerability p {
            margin: 5px 0;
        }
        .severity-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-badge.critical { background-color: #dc3545; color: white; }
        .severity-badge.high { background-color: #fd7e14; color: white; }
        .severity-badge.medium { background-color: #ffc107; color: black; }
        .severity-badge.low { background-color: #28a745; color: white; }
        .analysis-details {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }
        .recommendations {
            background-color: #e7f3ff;
            padding: 20px;
            border-radius: 8px;
            border-left: 5px solid #007bff;
        }
        .recommendations ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        .recommendations li {
            margin: 5px 0;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }
        @media print {
            body { background-color: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Mobile Security Analysis Report</h1>
            <p>Generated on {{ generated_at }}</p>
        </div>

        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>Overall Risk</h3>
                    <p class="{{ summary.overall_risk.lower() }}">{{ summary.overall_risk }}</p>
                </div>
                <div class="summary-item">
                    <h3>Critical</h3>
                    <p class="critical">{{ summary.critical }}</p>
                </div>
                <div class="summary-item">
                    <h3>High</h3>
                    <p class="high">{{ summary.high }}</p>
                </div>
                <div class="summary-item">
                    <h3>Medium</h3>
                    <p class="medium">{{ summary.medium }}</p>
                </div>
                <div class="summary-item">
                    <h3>Low</h3>
                    <p class="low">{{ summary.low }}</p>
                </div>
            </div>
        </div>

        {% if scan_info %}
        <div class="section">
            <h2>Scan Information</h2>
            <div class="analysis-details">
                <p><strong>File:</strong> {{ scan_info.file_path or scan_info.package_name or 'N/A' }}</p>
                <p><strong>Type:</strong> {{ scan_info.file_type or scan_info.device_type or 'N/A' }}</p>
                <p><strong>Date:</strong> {{ scan_info.scan_date }}</p>
                <p><strong>Tests:</strong> {{ scan_info.tests_performed | join(', ') if scan_info.tests_performed else 'N/A' }}</p>
            </div>
        </div>
        {% endif %}

        {% if critical_vulnerabilities %}
        <div class="section">
            <h2>Critical Vulnerabilities</h2>
            {% for vuln in critical_vulnerabilities %}
            <div class="vulnerability critical">
                <h4>
                    <span class="severity-badge critical">Critical</span>
                    {{ vuln.type }}
                </h4>
                <p><strong>Description:</strong> {{ vuln.description }}</p>
                {% if vuln.file %}<p><strong>File:</strong> {{ vuln.file }}</p>{% endif %}
                {% if vuln.recommendation %}<p><strong>Recommendation:</strong> {{ vuln.recommendation }}</p>{% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if high_vulnerabilities %}
        <div class="section">
            <h2>High Severity Vulnerabilities</h2>
            {% for vuln in high_vulnerabilities %}
            <div class="vulnerability high">
                <h4>
                    <span class="severity-badge high">High</span>
                    {{ vuln.type }}
                </h4>
                <p><strong>Description:</strong> {{ vuln.description }}</p>
                {% if vuln.file %}<p><strong>File:</strong> {{ vuln.file }}</p>{% endif %}
                {% if vuln.recommendation %}<p><strong>Recommendation:</strong> {{ vuln.recommendation }}</p>{% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if medium_vulnerabilities %}
        <div class="section">
            <h2>Medium Severity Vulnerabilities</h2>
            {% for vuln in medium_vulnerabilities %}
            <div class="vulnerability medium">
                <h4>
                    <span class="severity-badge medium">Medium</span>
                    {{ vuln.type }}
                </h4>
                <p><strong>Description:</strong> {{ vuln.description }}</p>
                {% if vuln.file %}<p><strong>File:</strong> {{ vuln.file }}</p>{% endif %}
                {% if vuln.recommendation %}<p><strong>Recommendation:</strong> {{ vuln.recommendation }}</p>{% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if low_vulnerabilities %}
        <div class="section">
            <h2>Low Severity Vulnerabilities</h2>
            {% for vuln in low_vulnerabilities %}
            <div class="vulnerability low">
                <h4>
                    <span class="severity-badge low">Low</span>
                    {{ vuln.type }}
                </h4>
                <p><strong>Description:</strong> {{ vuln.description }}</p>
                {% if vuln.file %}<p><strong>File:</strong> {{ vuln.file }}</p>{% endif %}
                {% if vuln.recommendation %}<p><strong>Recommendation:</strong> {{ vuln.recommendation }}</p>{% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if static_analysis %}
        <div class="section">
            <h2>Static Analysis Results</h2>
            <div class="analysis-details">
                {% if static_analysis.file_info %}
                <h4>File Information</h4>
                <p><strong>File Size:</strong> {{ static_analysis.file_info.file_size | filesizeformat }}</p>
                <p><strong>File Type:</strong> {{ static_analysis.file_info.file_type }}</p>
                {% endif %}
                
                {% if static_analysis.permissions %}
                <h4>Permissions Analysis</h4>
                <p><strong>Total Permissions:</strong> {{ static_analysis.permissions | length }}</p>
                {% for perm in static_analysis.permissions[:5] %}
                <p>- {{ perm.permission }} ({{ perm.severity }})</p>
                {% endfor %}
                {% endif %}
                
                {% if static_analysis.components %}
                <h4>Components Analysis</h4>
                <p><strong>Activities:</strong> {{ static_analysis.components.activities | length }}</p>
                <p><strong>Services:</strong> {{ static_analysis.components.services | length }}</p>
                <p><strong>Receivers:</strong> {{ static_analysis.components.receivers | length }}</p>
                <p><strong>Providers:</strong> {{ static_analysis.components.providers | length }}</p>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% if network_analysis %}
        <div class="section">
            <h2>Network Analysis Results</h2>
            <div class="analysis-details">
                {% if network_analysis.api_endpoints %}
                <h4>API Endpoints</h4>
                <p><strong>Total Endpoints:</strong> {{ network_analysis.api_endpoints | length }}</p>
                {% for endpoint in network_analysis.api_endpoints[:5] %}
                <p>- {{ endpoint.url }} ({{ endpoint.type }})</p>
                {% endfor %}
                {% endif %}
                
                {% if network_analysis.ssl_tls_analysis %}
                <h4>SSL/TLS Analysis</h4>
                <p><strong>Certificate Validation:</strong> {{ "Enabled" if network_analysis.ssl_tls_analysis.certificate_validation else "Disabled" }}</p>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% if storage_analysis %}
        <div class="section">
            <h2>Storage Analysis Results</h2>
            <div class="analysis-details">
                {% if storage_analysis.encryption_analysis %}
                <h4>Encryption Analysis</h4>
                <p><strong>Encryption Used:</strong> {{ "Yes" if storage_analysis.encryption_analysis.encryption_used else "No" }}</p>
                {% if storage_analysis.encryption_analysis.encryption_methods %}
                <p><strong>Methods:</strong> {{ storage_analysis.encryption_analysis.encryption_methods | join(', ') }}</p>
                {% endif %}
                {% endif %}
                
                {% if storage_analysis.backup_analysis %}
                <h4>Backup Analysis</h4>
                <p><strong>Backup Enabled:</strong> {{ "Yes" if storage_analysis.backup_analysis.backup_enabled else "No" }}</p>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% if code_analysis %}
        <div class="section">
            <h2>Code Analysis Results</h2>
            <div class="analysis-details">
                {% if code_analysis.code_quality %}
                <h4>Code Quality</h4>
                <p><strong>Total Files:</strong> {{ code_analysis.code_quality.total_files }}</p>
                <p><strong>Java Files:</strong> {{ code_analysis.code_quality.java_files }}</p>
                <p><strong>Kotlin Files:</strong> {{ code_analysis.code_quality.kotlin_files }}</p>
                {% endif %}
                
                {% if code_analysis.hardcoded_secrets %}
                <h4>Hardcoded Secrets</h4>
                <p><strong>Total Secrets:</strong> {{ code_analysis.hardcoded_secrets | length }}</p>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% if recommendations %}
        <div class="section">
            <h2>Security Recommendations</h2>
            <div class="recommendations">
                <ul>
                    {% for rec in recommendations %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>
        {% endif %}

        <div class="footer">
            <p>Report generated by Mobile Security Testing Tool</p>
            <p>For questions or support, please contact your security team</p>
        </div>
    </div>
</body>
</html>
        """ 