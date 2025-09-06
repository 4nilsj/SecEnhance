"""
HTML report generator using Jinja2 templates.
Generates comprehensive security scan reports with findings from ZAP and custom plugins.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from jinja2 import Environment, FileSystemLoader, Template

from utils.logger import get_logger, LoggedTimer


class ReportGenerator:
    """Generates HTML reports from scan results."""
    
    def __init__(self, templates_dir: str = "templates"):
        self.logger = get_logger(__name__)
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(exist_ok=True)
        
        # Setup Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True
        )
        
        # Create default template if it doesn't exist
        self._create_default_template()
    
    def _create_default_template(self):
        """Create default HTML template if it doesn't exist."""
        template_file = self.templates_dir / "report_template.html"
        
        if not template_file.exists():
            template_content = self._get_default_template()
            with open(template_file, 'w', encoding='utf-8') as f:
                f.write(template_content)
            self.logger.info("Created default report template")
    
    def _get_default_template(self) -> str:
        """Get the default HTML template content."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Scan Report - {{ scan_data.scan_id }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .content {
            padding: 30px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #007bff;
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #007bff;
            font-size: 2em;
        }
        .summary-card p {
            margin: 0;
            color: #666;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #333;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .alert {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .alert-header {
            padding: 15px 20px;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .alert-high { background-color: #f8d7da; border-left: 4px solid #dc3545; }
        .alert-medium { background-color: #fff3cd; border-left: 4px solid #ffc107; }
        .alert-low { background-color: #d1ecf1; border-left: 4px solid #17a2b8; }
        .alert-info { background-color: #d4edda; border-left: 4px solid #28a745; }
        .alert-body {
            padding: 20px;
            border-top: 1px solid #ddd;
        }
        .alert-body p {
            margin: 10px 0;
        }
        .risk-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .risk-high { background-color: #dc3545; color: white; }
        .risk-medium { background-color: #ffc107; color: #212529; }
        .risk-low { background-color: #17a2b8; color: white; }
        .risk-info { background-color: #28a745; color: white; }
        .performance-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .performance-table th,
        .performance-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .performance-table th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .performance-table tr:hover {
            background-color: #f5f5f5;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #ddd;
        }
        .code {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            border: 1px solid #e9ecef;
        }
        .url {
            color: #007bff;
            word-break: break-all;
        }
        .method {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            margin-right: 10px;
        }
        .method-get { background-color: #28a745; color: white; }
        .method-post { background-color: #007bff; color: white; }
        .method-put { background-color: #ffc107; color: #212529; }
        .method-delete { background-color: #dc3545; color: white; }
        .method-patch { background-color: #6f42c1; color: white; }
        .poc-section {
            margin-top: 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background-color: #f8f9fa;
        }
        .poc-section summary {
            padding: 10px 15px;
            background-color: #e9ecef;
            cursor: pointer;
            font-weight: bold;
            border-radius: 4px 4px 0 0;
        }
        .poc-section summary:hover {
            background-color: #dee2e6;
        }
        .poc-content {
            padding: 15px;
        }
        .poc-content h5 {
            margin: 10px 0 5px 0;
            color: #495057;
        }
        .references {
            margin-top: 15px;
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 4px;
        }
        .references h5 {
            margin: 0 0 10px 0;
            color: #495057;
        }
        .references ul {
            margin: 0;
            padding-left: 20px;
        }
        .references li {
            margin: 5px 0;
        }
        .references a {
            color: #007bff;
            text-decoration: none;
        }
        .references a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>API Security Scan Report</h1>
            <p>Generated on {{ report_date }} | Scan ID: {{ scan_data.scan_id }}</p>
        </div>
        
        <div class="content">
            <!-- Scan Summary -->
            <div class="section">
                <h2>Scan Summary</h2>
                <div class="summary">
                    <div class="summary-card">
                        <h3>{{ scan_data.target_url }}</h3>
                        <p>Target URL</p>
                    </div>
                    <div class="summary-card">
                        <h3>{{ scan_data.status }}</h3>
                        <p>Scan Status</p>
                    </div>
                    <div class="summary-card">
                        <h3>{{ "%.2f"|format(scan_data.total_duration or 0) }}s</h3>
                        <p>Total Duration</p>
                    </div>
                    <div class="summary-card">
                        <h3>{{ zap_alerts|length }}</h3>
                        <p>ZAP Alerts</p>
                    </div>
                    <div class="summary-card">
                        <h3>{{ custom_alerts|length }}</h3>
                        <p>Custom Plugin Alerts</p>
                    </div>
                </div>
            </div>
            
            <!-- Risk Summary -->
            <div class="section">
                <h2>Risk Summary</h2>
                <div class="summary">
                    <div class="summary-card">
                        <h3>{{ risk_counts.High or 0 }}</h3>
                        <p>High Risk</p>
                    </div>
                    <div class="summary-card">
                        <h3>{{ risk_counts.Medium or 0 }}</h3>
                        <p>Medium Risk</p>
                    </div>
                    <div class="summary-card">
                        <h3>{{ risk_counts.Low or 0 }}</h3>
                        <p>Low Risk</p>
                    </div>
                    <div class="summary-card">
                        <h3>{{ risk_counts.Informational or 0 }}</h3>
                        <p>Informational</p>
                    </div>
                </div>
            </div>
            
            <!-- Performance Statistics -->
            {% if performance_stats %}
            <div class="section">
                <h2>Performance Statistics</h2>
                <table class="performance-table">
                    <thead>
                        <tr>
                            <th>Phase</th>
                            <th>Duration</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for stat in performance_stats %}
                        <tr>
                            <td>{{ stat.phase_name }}</td>
                            <td>{{ "%.2f"|format(stat.duration) }}s</td>
                            <td>{{ stat.details or '-' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
            
            <!-- Vulnerabilities -->
            {% if vulnerabilities %}
            <div class="section">
                <h2>Security Vulnerabilities</h2>
                {% for vuln in vulnerabilities %}
                <div class="alert alert-{{ vuln.risk.lower() }}">
                    <div class="alert-header">
                        <span>
                            <span class="method method-{{ vuln.request.split()[0].lower() if vuln.request else 'get' }}">{{ vuln.request.split()[0] if vuln.request else 'GET' }}</span>
                            <span class="url">{{ vuln.url }}</span>
                        </span>
                        <span class="risk-badge risk-{{ vuln.risk.lower() }}">{{ vuln.risk }}</span>
                    </div>
                    <div class="alert-body">
                        <h4>{{ vuln.name }}</h4>
                        <p><strong>CVSS Score:</strong> {{ vuln.cvss_score }}</p>
                        <p><strong>Source:</strong> {{ vuln.source }}</p>
                        {% if vuln.plugin_name %}
                        <p><strong>Plugin:</strong> {{ vuln.plugin_name }}</p>
                        {% endif %}
                        <p><strong>Description:</strong> {{ vuln.description }}</p>
                        {% if vuln.solution %}
                        <p><strong>Solution:</strong> {{ vuln.solution }}</p>
                        {% endif %}
                        {% if vuln.cwe_id %}
                        <p><strong>CWE ID:</strong> {{ vuln.cwe_id }}</p>
                        {% endif %}
                        {% if vuln.wasc_id %}
                        <p><strong>WASC ID:</strong> {{ vuln.wasc_id }}</p>
                        {% endif %}
                        {% if vuln.evidence %}
                        <p><strong>Evidence:</strong> {{ vuln.evidence }}</p>
                        {% endif %}
                        {% if vuln.parameter %}
                        <p><strong>Parameter:</strong> {{ vuln.parameter }}</p>
                        {% endif %}
                        
                        <!-- Collapsible Proof-of-Concept -->
                        <details class="poc-section">
                            <summary>Proof-of-Concept Evidence</summary>
                            <div class="poc-content">
                                <h5>HTTP Request:</h5>
                                <div class="code">{{ vuln.request }}</div>
                                <h5>HTTP Response:</h5>
                                <div class="code">{{ vuln.response }}</div>
                            </div>
                        </details>
                        
                        {% if vuln.references %}
                        <div class="references">
                            <h5>References:</h5>
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
            {% endif %}
            
            <!-- Scan Details -->
            <div class="section">
                <h2>Scan Details</h2>
                <div class="code">
                    <strong>Scan ID:</strong> {{ scan_data.scan_id }}<br>
                    <strong>Target URL:</strong> {{ scan_data.target_url }}<br>
                    <strong>Start Time:</strong> {{ scan_data.start_time }}<br>
                    <strong>End Time:</strong> {{ scan_data.end_time or 'N/A' }}<br>
                    <strong>Input Type:</strong> {{ scan_data.input_type }}<br>
                    <strong>Input Source:</strong> {{ scan_data.input_source }}<br>
                    {% if scan_data.auth_type %}
                    <strong>Authentication:</strong> {{ scan_data.auth_type }}<br>
                    {% endif %}
                    {% if scan_data.error_message %}
                    <strong>Error:</strong> {{ scan_data.error_message }}<br>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by API Security Scanner on {{ report_date }}</p>
        </div>
    </div>
</body>
</html>"""
    
    def generate_report(self, scan_data: Dict[str, Any], vulnerabilities: List[Dict[str, Any]], 
                       performance_stats: List[Dict[str, Any]], output_path: str) -> bool:
        """
        Generate HTML report from scan data.
        
        Args:
            scan_data: Scan metadata
            vulnerabilities: List of vulnerabilities with proof-of-concept data
            performance_stats: List of performance statistics
            output_path: Path to save the report
            
        Returns:
            True if report was generated successfully
        """
        try:
            with LoggedTimer(self.logger, "Report generation"):
                # Calculate risk counts
                risk_counts = self._calculate_risk_counts_from_vulnerabilities(vulnerabilities)
                
                # Prepare template data
                template_data = {
                    'scan_data': scan_data,
                    'vulnerabilities': vulnerabilities,
                    'performance_stats': performance_stats,
                    'risk_counts': risk_counts,
                    'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                # Load and render template
                template = self.jinja_env.get_template('report_template.html')
                html_content = template.render(**template_data)
                
                # Write report to file
                output_file = Path(output_path)
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                self.logger.info(f"Report generated successfully: {output_path}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}")
            return False
    
    def _calculate_risk_counts_from_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate risk level counts from vulnerabilities."""
        risk_counts = {
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Informational': 0
        }
        
        # Count vulnerabilities by risk level
        for vuln in vulnerabilities:
            risk_level = vuln.get('risk', 'Informational')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
        
        return risk_counts
    
    def generate_json_report(self, scan_data: Dict[str, Any], vulnerabilities: List[Dict[str, Any]], 
                           performance_stats: List[Dict[str, Any]], output_path: str) -> bool:
        """
        Generate JSON report from scan data.
        
        Args:
            scan_data: Scan metadata
            vulnerabilities: List of vulnerabilities with proof-of-concept data
            performance_stats: List of performance statistics
            output_path: Path to save the JSON report
            
        Returns:
            True if report was generated successfully
        """
        try:
            with LoggedTimer(self.logger, "JSON report generation"):
                # Prepare report data
                report_data = {
                    'scan_metadata': scan_data,
                    'vulnerabilities': vulnerabilities,
                    'performance_stats': performance_stats,
                    'risk_counts': self._calculate_risk_counts_from_vulnerabilities(vulnerabilities),
                    'generated_at': datetime.now().isoformat(),
                    'report_version': '2.0'
                }
                
                # Write JSON report
                output_file = Path(output_path)
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2, default=str)
                
                self.logger.info(f"JSON report generated successfully: {output_path}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {e}")
            return False
    
    def generate_summary_report(self, scan_data: Dict[str, Any], zap_alerts: List[Dict[str, Any]], 
                              custom_alerts: List[Dict[str, Any]], performance_stats: List[Dict[str, Any]]) -> str:
        """
        Generate a text summary report.
        
        Args:
            scan_data: Scan metadata
            zap_alerts: List of ZAP alerts
            custom_alerts: List of custom plugin alerts
            performance_stats: List of performance statistics
            
        Returns:
            Text summary report
        """
        try:
            risk_counts = self._calculate_risk_counts(zap_alerts, custom_alerts)
            
            summary = []
            summary.append("=" * 60)
            summary.append("API SECURITY SCAN SUMMARY")
            summary.append("=" * 60)
            summary.append(f"Scan ID: {scan_data.get('scan_id', 'N/A')}")
            summary.append(f"Target: {scan_data.get('target_url', 'N/A')}")
            summary.append(f"Status: {scan_data.get('status', 'N/A')}")
            summary.append(f"Duration: {scan_data.get('total_duration', 0):.2f}s")
            summary.append("")
            
            summary.append("RISK SUMMARY:")
            summary.append(f"  High: {risk_counts['High']}")
            summary.append(f"  Medium: {risk_counts['Medium']}")
            summary.append(f"  Low: {risk_counts['Low']}")
            summary.append(f"  Informational: {risk_counts['Informational']}")
            summary.append("")
            
            summary.append("ALERTS SUMMARY:")
            summary.append(f"  ZAP Alerts: {len(zap_alerts)}")
            summary.append(f"  Custom Plugin Alerts: {len(custom_alerts)}")
            summary.append("")
            
            if performance_stats:
                summary.append("PERFORMANCE STATISTICS:")
                for stat in performance_stats:
                    summary.append(f"  {stat.get('phase_name', 'Unknown')}: {stat.get('duration', 0):.2f}s")
                summary.append("")
            
            if zap_alerts:
                summary.append("ZAP ALERTS:")
                for alert in zap_alerts:
                    summary.append(f"  [{alert.get('risk_level', 'Unknown')}] {alert.get('name', 'Unknown')}")
                    summary.append(f"    URL: {alert.get('url', 'N/A')}")
                    summary.append(f"    Method: {alert.get('method', 'N/A')}")
                    summary.append("")
            
            if custom_alerts:
                summary.append("CUSTOM PLUGIN ALERTS:")
                for alert in custom_alerts:
                    summary.append(f"  [{alert.get('severity', 'Unknown')}] {alert.get('title', 'Unknown')}")
                    summary.append(f"    Plugin: {alert.get('plugin_name', 'N/A')}")
                    summary.append(f"    URL: {alert.get('url', 'N/A')}")
                    summary.append("")
            
            summary.append("=" * 60)
            
            return "\n".join(summary)
            
        except Exception as e:
            self.logger.error(f"Failed to generate summary report: {e}")
            return f"Error generating summary: {e}"
