"""
Report Generator for SAST Scanner
Generates comprehensive security reports in multiple formats.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import jinja2
import markdown

from .debug_utils import debug_print, debug_log

class ReportGenerator:
    """Generates comprehensive security reports."""
    
    def __init__(self, debug: bool = False):
        """Initialize the report generator."""
        self.debug = debug
        self.templates_dir = Path(__file__).parent / "templates"
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.templates_dir)),
            autoescape=True
        )
        
        debug_log("report_generator", "Report Generator initialized")
    
    def generate_report(self, scan_results: Dict[str, Any], output_format: str = "html", 
                       output_file: Optional[str] = None) -> str:
        """Generate a comprehensive security report."""
        debug_log("report_generator", f"Generating {output_format} report")
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"sast_report_{timestamp}.{output_format}"
        
        output_path = self.reports_dir / output_file
        
        if output_format.lower() == "html":
            return self._generate_html_report(scan_results, output_path)
        elif output_format.lower() == "json":
            return self._generate_json_report(scan_results, output_path)
        elif output_format.lower() == "markdown":
            return self._generate_markdown_report(scan_results, output_path)
        elif output_format.lower() == "pdf":
            return self._generate_pdf_report(scan_results, output_path)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _generate_html_report(self, scan_results: Dict[str, Any], output_path: Path) -> str:
        """Generate HTML report."""
        try:
            # Prepare data for template
            template_data = self._prepare_template_data(scan_results)
            
            # Load and render template
            template = self.jinja_env.get_template("report_template.html")
            html_content = template.render(**template_data)
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            debug_log("report_generator", f"HTML report generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            debug_log("report_generator", f"Error generating HTML report: {e}", "ERROR")
            # Fallback to simple HTML
            return self._generate_simple_html_report(scan_results, output_path)
    
    def _generate_simple_html_report(self, scan_results: Dict[str, Any], output_path: Path) -> str:
        """Generate a simple HTML report as fallback."""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAST Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .vulnerability {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ff4444; background-color: #fff5f5; }}
        .high {{ border-left-color: #ff4444; }}
        .medium {{ border-left-color: #ffaa00; }}
        .low {{ border-left-color: #44aa44; }}
        .info {{ border-left-color: #4444ff; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SAST Security Report</h1>
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Files</td><td>{scan_results.get('summary', {}).get('total_files', 0)}</td></tr>
            <tr><td>Total Vulnerabilities</td><td>{scan_results.get('summary', {}).get('total_vulnerabilities', 0)}</td></tr>
            <tr><td>High Severity</td><td>{scan_results.get('summary', {}).get('severity_breakdown', {}).get('high', 0)}</td></tr>
            <tr><td>Medium Severity</td><td>{scan_results.get('summary', {}).get('severity_breakdown', {}).get('medium', 0)}</td></tr>
            <tr><td>Low Severity</td><td>{scan_results.get('summary', {}).get('severity_breakdown', {}).get('low', 0)}</td></tr>
        </table>
    </div>
    
    <div class="vulnerabilities">
        <h2>Vulnerabilities</h2>
        {self._generate_vulnerability_html(scan_results.get('vulnerabilities', []))}
    </div>
</body>
</html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def _generate_vulnerability_html(self, vulnerabilities: List[Dict]) -> str:
        """Generate HTML for vulnerabilities section."""
        if not vulnerabilities:
            return "<p>No vulnerabilities found.</p>"
        
        html = ""
        for vuln in vulnerabilities:
            severity_class = vuln.get('severity', 'info').lower()
            html += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln.get('type', 'Unknown')}</h3>
                <p><strong>Description:</strong> {vuln.get('description', 'No description')}</p>
                <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>
                <p><strong>File:</strong> {vuln.get('file_name', 'Unknown')}</p>
                <p><strong>Line:</strong> {vuln.get('line_number', 'Unknown')}</p>
                <p><strong>Mitigation:</strong> {vuln.get('mitigation', 'No mitigation provided')}</p>
            </div>
            """
        
        return html
    
    def _generate_json_report(self, scan_results: Dict[str, Any], output_path: Path) -> str:
        """Generate JSON report."""
        try:
            # Add report metadata
            report_data = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "tool_version": "1.0.0",
                    "report_format": "json"
                },
                "scan_results": scan_results
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            debug_log("report_generator", f"JSON report generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            debug_log("report_generator", f"Error generating JSON report: {e}", "ERROR")
            raise
    
    def _generate_markdown_report(self, scan_results: Dict[str, Any], output_path: Path) -> str:
        """Generate Markdown report."""
        try:
            markdown_content = self._generate_markdown_content(scan_results)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            
            debug_log("report_generator", f"Markdown report generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            debug_log("report_generator", f"Error generating Markdown report: {e}", "ERROR")
            raise
    
    def _generate_markdown_content(self, scan_results: Dict[str, Any]) -> str:
        """Generate Markdown content for the report."""
        content = f"""# SAST Security Report

**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

This report contains the results of a Static Application Security Testing (SAST) scan.

### Scan Overview
- **Total Files Analyzed:** {scan_results.get('summary', {}).get('total_files', 0)}
- **Total Vulnerabilities Found:** {scan_results.get('summary', {}).get('total_vulnerabilities', 0)}
- **Files with Vulnerabilities:** {scan_results.get('summary', {}).get('files_with_vulnerabilities', 0)}

### Severity Breakdown
"""
        
        severity_breakdown = scan_results.get('summary', {}).get('severity_breakdown', {})
        for severity, count in severity_breakdown.items():
            content += f"- **{severity.title()}:** {count}\n"
        
        content += "\n## Detailed Findings\n\n"
        
        # Group vulnerabilities by severity
        vulnerabilities = scan_results.get('vulnerabilities', [])
        vulnerabilities_by_severity = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            if severity not in vulnerabilities_by_severity:
                vulnerabilities_by_severity[severity] = []
            vulnerabilities_by_severity[severity].append(vuln)
        
        # Generate sections for each severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity in vulnerabilities_by_severity:
                content += f"### {severity.title()} Severity Issues\n\n"
                
                for vuln in vulnerabilities_by_severity[severity]:
                    content += self._generate_vulnerability_markdown(vuln)
                
                content += "\n"
        
        # Add AI insights section
        ai_insights = scan_results.get('ai_insights', [])
        if ai_insights:
            content += "## AI-Generated Insights\n\n"
            for insight in ai_insights:
                content += self._generate_insight_markdown(insight)
        
        # Add recommendations
        content += "\n## Recommendations\n\n"
        content += self._generate_recommendations_markdown(scan_results)
        
        return content
    
    def _generate_vulnerability_markdown(self, vuln: Dict[str, Any]) -> str:
        """Generate Markdown for a single vulnerability."""
        content = f"""#### {vuln.get('type', 'Unknown Vulnerability').title()}

- **Description:** {vuln.get('description', 'No description provided')}
- **File:** `{vuln.get('file_name', 'Unknown')}`
- **Line:** {vuln.get('line_number', 'Unknown')}
- **Severity:** {vuln.get('severity', 'Unknown')}
- **CWE:** {vuln.get('cwe', 'Unknown')}
- **Confidence:** {vuln.get('confidence', 'Unknown')}

**Code:**
```
{vuln.get('line_content', 'No code available')}
```

**Mitigation:**
{vuln.get('mitigation', 'No mitigation provided')}

---
"""
        return content
    
    def _generate_insight_markdown(self, insight: Dict[str, Any]) -> str:
        """Generate Markdown for an AI insight."""
        content = f"""### {insight.get('type', 'Unknown Insight').title()}

- **Description:** {insight.get('description', 'No description provided')}
- **File:** `{insight.get('file_name', 'Unknown')}`
- **Confidence:** {insight.get('confidence', 'Unknown')}

**Details:**
{insight.get('details', 'No details provided')}

---
"""
        return content
    
    def _generate_recommendations_markdown(self, scan_results: Dict[str, Any]) -> str:
        """Generate recommendations section."""
        recommendations = []
        
        # Generate recommendations based on findings
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        if any(v.get('type') == 'sql_injection' for v in vulnerabilities):
            recommendations.append({
                'priority': 'High',
                'title': 'Implement Parameterized Queries',
                'description': 'Replace string concatenation in SQL queries with parameterized queries or prepared statements.'
            })
        
        if any(v.get('type') == 'xss' for v in vulnerabilities):
            recommendations.append({
                'priority': 'High',
                'title': 'Implement Output Encoding',
                'description': 'Use proper output encoding for all user-controlled data displayed in web pages.'
            })
        
        if any(v.get('type') == 'hardcoded_credentials' for v in vulnerabilities):
            recommendations.append({
                'priority': 'Medium',
                'title': 'Remove Hardcoded Credentials',
                'description': 'Move credentials to environment variables or secure configuration management.'
            })
        
        if any(v.get('type') == 'weak_crypto' for v in vulnerabilities):
            recommendations.append({
                'priority': 'Medium',
                'title': 'Upgrade Cryptographic Algorithms',
                'description': 'Replace weak cryptographic algorithms with strong alternatives.'
            })
        
        # Add general recommendations
        if not recommendations:
            recommendations.append({
                'priority': 'General',
                'title': 'Implement Security Best Practices',
                'description': 'Follow security best practices including input validation, output encoding, and proper error handling.'
            })
        
        content = ""
        for rec in recommendations:
            content += f"""**{rec['priority']} Priority:** {rec['title']}

{rec['description']}

"""
        
        return content
    
    def _generate_pdf_report(self, scan_results: Dict[str, Any], output_path: Path) -> str:
        """Generate PDF report."""
        try:
            # First generate HTML
            html_path = output_path.with_suffix('.html')
            self._generate_html_report(scan_results, html_path)
            
            # Convert HTML to PDF using weasyprint
            try:
                from weasyprint import HTML
                HTML(filename=str(html_path)).write_pdf(str(output_path))
                
                # Clean up temporary HTML file
                html_path.unlink()
                
                debug_log("report_generator", f"PDF report generated: {output_path}")
                return str(output_path)
                
            except ImportError:
                debug_log("report_generator", "weasyprint not available, falling back to HTML", "WARNING")
                return str(html_path)
                
        except Exception as e:
            debug_log("report_generator", f"Error generating PDF report: {e}", "ERROR")
            raise
    
    def _prepare_template_data(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for template rendering."""
        return {
            "scan_results": scan_results,
            "generated_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "tool_version": "1.0.0",
            "severity_colors": {
                "critical": "#ff0000",
                "high": "#ff4444",
                "medium": "#ffaa00",
                "low": "#44aa44",
                "info": "#4444ff"
            }
        }
    
    def generate_summary_report(self, scan_results: Dict[str, Any], output_format: str = "html") -> str:
        """Generate a summary report."""
        debug_log("report_generator", f"Generating summary report in {output_format}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"sast_summary_{timestamp}.{output_format}"
        output_path = self.reports_dir / output_file
        
        # Create summary data
        summary_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool_version": "1.0.0",
                "report_type": "summary"
            },
            "summary": scan_results.get("summary", {}),
            "scan_info": scan_results.get("scan_info", {}),
            "top_vulnerabilities": self._get_top_vulnerabilities(scan_results.get("vulnerabilities", [])),
            "recommendations": self._generate_summary_recommendations(scan_results)
        }
        
        if output_format.lower() == "json":
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, default=str)
        elif output_format.lower() == "html":
            self._generate_summary_html(summary_data, output_path)
        else:
            raise ValueError(f"Unsupported output format for summary: {output_format}")
        
        return str(output_path)
    
    def _get_top_vulnerabilities(self, vulnerabilities: List[Dict], limit: int = 10) -> List[Dict]:
        """Get top vulnerabilities by severity."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: (severity_order.get(x.get("severity", "info"), 4), x.get("line_number", 0))
        )
        
        return sorted_vulns[:limit]
    
    def _generate_summary_recommendations(self, scan_results: Dict[str, Any]) -> List[Dict]:
        """Generate summary recommendations."""
        recommendations = []
        vulnerabilities = scan_results.get("vulnerabilities", [])
        
        # Count vulnerability types
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown")
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        # Generate recommendations based on most common issues
        if vuln_types.get("sql_injection", 0) > 0:
            recommendations.append({
                "priority": "High",
                "title": "Address SQL Injection Vulnerabilities",
                "count": vuln_types["sql_injection"],
                "description": "Implement parameterized queries to prevent SQL injection attacks."
            })
        
        if vuln_types.get("xss", 0) > 0:
            recommendations.append({
                "priority": "High",
                "title": "Address Cross-Site Scripting Vulnerabilities",
                "count": vuln_types["xss"],
                "description": "Implement proper output encoding to prevent XSS attacks."
            })
        
        if vuln_types.get("hardcoded_credentials", 0) > 0:
            recommendations.append({
                "priority": "Medium",
                "title": "Remove Hardcoded Credentials",
                "count": vuln_types["hardcoded_credentials"],
                "description": "Move credentials to environment variables or secure configuration."
            })
        
        return recommendations
    
    def _generate_summary_html(self, summary_data: Dict[str, Any], output_path: Path) -> None:
        """Generate summary HTML report."""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAST Summary Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .recommendation {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ff4444; background-color: #fff5f5; }}
        .high {{ border-left-color: #ff4444; }}
        .medium {{ border-left-color: #ffaa00; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SAST Summary Report</h1>
        <p>Generated on: {summary_data['report_metadata']['generated_at']}</p>
    </div>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Files</td><td>{summary_data['summary'].get('total_files', 0)}</td></tr>
            <tr><td>Total Vulnerabilities</td><td>{summary_data['summary'].get('total_vulnerabilities', 0)}</td></tr>
            <tr><td>High Severity</td><td>{summary_data['summary'].get('severity_breakdown', {}).get('high', 0)}</td></tr>
            <tr><td>Medium Severity</td><td>{summary_data['summary'].get('severity_breakdown', {}).get('medium', 0)}</td></tr>
            <tr><td>Low Severity</td><td>{summary_data['summary'].get('severity_breakdown', {}).get('low', 0)}</td></tr>
        </table>
    </div>
    
    <div class="recommendations">
        <h2>Top Recommendations</h2>
        {self._generate_recommendations_html(summary_data['recommendations'])}
    </div>
</body>
</html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_recommendations_html(self, recommendations: List[Dict]) -> str:
        """Generate HTML for recommendations."""
        if not recommendations:
            return "<p>No specific recommendations available.</p>"
        
        html = ""
        for rec in recommendations:
            priority_class = rec.get('priority', 'medium').lower()
            html += f"""
            <div class="recommendation {priority_class}">
                <h3>{rec['title']} ({rec['count']} instances)</h3>
                <p><strong>Priority:</strong> {rec['priority']}</p>
                <p><strong>Description:</strong> {rec['description']}</p>
            </div>
            """
        
        return html 