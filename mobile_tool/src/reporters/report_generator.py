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
        
    def generate_report(self, results: Dict[str, Any], output_file: str, format: str = "html") -> str:
        """Generate security report in specified format."""
        self.logger.info(f"Generating {format.upper()} report: {output_file}")
        
        if format.lower() == "json":
            return self._generate_json_report(results, output_file)
        elif format.lower() == "html":
            return self._generate_html_report(results, output_file)
        elif format.lower() == "dashboard" or format.lower() == "html_dashboard":
            return self._generate_dashboard_report(results, output_file)
        elif format.lower() == "pdf":
            return self._generate_pdf_report(results, output_file)
        elif format.lower() == "csv":
            return self._generate_csv_report(results, output_file)
        elif format.lower() == "xml":
            return self._generate_xml_report(results, output_file)
        elif format.lower() == "markdown":
            return self._generate_markdown_report(results, output_file)
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
    
    def _generate_dashboard_report(self, results: Dict[str, Any], output_file: str) -> str:
        """Generate interactive HTML dashboard report."""
        try:
            # Load dashboard template
            template_path = Path(__file__).parent / "templates" / "dashboard_report.html"
            with open(template_path, "r", encoding="utf-8") as f:
                dashboard_template = f.read()
            # Prepare data
            summary = results.get("summary", {})
            vulnerabilities = results.get("vulnerabilities", [])
            ai_vulns = [v for v in vulnerabilities if v.get("type", "").startswith("AI-Predicted")]
            template_data = {
                "summary": summary,
                "vulnerabilities": vulnerabilities,
                "ai_vulns": ai_vulns
            }
            # Render template
            template = jinja2.Template(dashboard_template)
            html_content = template.render(**template_data)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return output_file
        except Exception as e:
            self.logger.error(f"Error generating dashboard HTML report: {str(e)}")
            raise
    
    def _generate_xml_report(self, results: Dict[str, Any], output_file: str) -> str:
        """Generate XML report."""
        import xml.etree.ElementTree as ET
        try:
            report = ET.Element("MobileSecurityReport")
            info = ET.SubElement(report, "ReportInfo")
            ET.SubElement(info, "GeneratedAt").text = datetime.now().isoformat()
            ET.SubElement(info, "ToolVersion").text = "1.0.0"
            ET.SubElement(info, "Format").text = "xml"

            summary = results.get("summary", {})
            summary_elem = ET.SubElement(report, "Summary")
            for k, v in summary.items():
                ET.SubElement(summary_elem, k.capitalize()).text = str(v)

            vulns_elem = ET.SubElement(report, "Vulnerabilities")
            for vuln in results.get("vulnerabilities", []):
                vuln_elem = ET.SubElement(vulns_elem, "Vulnerability")
                for k, v in vuln.items():
                    ET.SubElement(vuln_elem, k.capitalize()).text = str(v)

            tree = ET.ElementTree(report)
            tree.write(output_file, encoding="utf-8", xml_declaration=True)
            return output_file
        except Exception as e:
            self.logger.error(f"Error generating XML report: {str(e)}")
            raise

    def _generate_markdown_report(self, results: Dict[str, Any], output_file: str) -> str:
        """Generate Markdown report."""
        try:
            summary = results.get("summary", {})
            scan_info = results.get("scan_info", {})
            vulns = results.get("vulnerabilities", [])
            lines = [
                f"# Mobile Security Analysis Report\n",
                f"**File:** {scan_info.get('file_path', 'N/A')}  ",
                f"**Type:** {scan_info.get('file_type', 'N/A')}  ",
                f"**Date:** {scan_info.get('scan_date', 'N/A')}  ",
                f"**Tests:** {', '.join(scan_info.get('tests_performed', []))}  \n",
                f"## Summary\n",
                f"- **Total Vulnerabilities:** {summary.get('total_vulnerabilities', 0)}",
                f"- **Critical:** {summary.get('critical', 0)}",
                f"- **High:** {summary.get('high', 0)}",
                f"- **Medium:** {summary.get('medium', 0)}",
                f"- **Low:** {summary.get('low', 0)}",
                f"- **Overall Risk:** {summary.get('overall_risk', 'Unknown')}\n",
                f"## Vulnerabilities\n"
            ]
            if not vulns:
                lines.append("No vulnerabilities found.\n")
            else:
                for v in vulns:
                    lines.append(f"### {v.get('title', v.get('type', 'Vulnerability'))}")
                    lines.append(f"- **Type:** {v.get('type', '')}")
                    lines.append(f"- **Severity:** {v.get('severity', '')}")
                    lines.append(f"- **Description:** {v.get('description', '')}")
                    lines.append(f"- **File:** {v.get('file', '')}")
                    lines.append(f"- **Recommendation:** {v.get('recommendation', '')}\n")
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            return output_file
        except Exception as e:
            self.logger.error(f"Error generating Markdown report: {str(e)}")
            raise
    
    def _prepare_html_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for HTML template with false positive filtering."""
        # Extract summary information
        summary = results.get("summary", {})
        scan_info = results.get("scan_info", {})
        
        # Filter out false positives from Android framework files
        def is_framework_file(file_path: str) -> bool:
            """Check if file is from Android framework (false positive)."""
            if not file_path:
                return False
            
            # Android framework files to exclude
            framework_patterns = [
                'abc_', 'android_', 'support_', 'androidx_',  # Android support libraries
                'res/drawable/abc_', 'res/layout/abc_', 'res/color/abc_',  # AppCompat resources
                'res/drawable-v24/', 'res/drawable-v21/', 'res/layout-v21/',  # Version-specific resources
                'res/color-v23/', 'res/color-v21/',  # Version-specific colors
                'META-INF/', 'AndroidManifest.xml',  # APK metadata
                'classes.dex', 'resources.arsc',  # APK core files
                'res/anim/', 'res/transition/', 'res/interpolator/',  # Animation resources
                'res/menu/', 'res/navigation/', 'res/xml/',  # Other resources
                'res/values/', 'res/values-v',  # Values resources
                'res/mipmap-', 'res/drawable-',  # Image resources
                'assets/', 'lib/', 'libs/'  # Assets and libraries
            ]
            
            file_path_lower = file_path.lower()
            return any(pattern in file_path_lower for pattern in framework_patterns)
        
        def clean_vulnerability(vuln: Dict[str, Any]) -> Dict[str, Any]:
            """Clean and enhance vulnerability data."""
            # Skip framework files
            if is_framework_file(vuln.get('file', '')):
                return None
            
            # Clean up pattern data
            pattern = vuln.get('pattern', '')
            if pattern and len(pattern) > 100:
                pattern = pattern[:100] + "..."
            
            # Enhance with better descriptions
            vuln_type = vuln.get('type', '').lower()
            descriptions = {
                'root_detection': 'Application attempts to detect if device is rooted',
                'emulator_detection': 'Application attempts to detect if running in emulator',
                'insecure_crypto': 'Weak or deprecated cryptographic algorithm detected',
                'input_validation': 'Potential input validation vulnerability',
                'network_intercepting': 'HTTP traffic detected (should use HTTPS)',
                'insecure_storage': 'Sensitive data stored insecurely',
                'keyboard_cache': 'Keyboard cache not properly disabled',
                'insecure_logging': 'Sensitive information logged insecurely',
                'hardcoded_secrets': 'Hardcoded secrets found in code',
                'sql_injection': 'Potential SQL injection vulnerability',
                'path_traversal': 'Potential path traversal vulnerability',
                'command_injection': 'Potential command injection vulnerability',
                'webview_security': 'WebView security configuration issue',
                'intent_injection': 'Potential intent injection vulnerability',
                'certificate_bypass': 'SSL certificate validation bypass',
                'clipboard_exposure': 'Sensitive data exposed to clipboard',
                'sensitive_data_handling': 'Sensitive data handled insecurely'
            }
            
            # Create enhanced vulnerability object
            enhanced_vuln = {
                'title': vuln.get('title') or vuln.get('type', 'Security Issue'),
                'type': vuln.get('type', 'Unknown'),
                'severity': vuln.get('severity', 'medium'),
                'description': vuln.get('description') or descriptions.get(vuln_type, 'Security issue detected'),
                'file': vuln.get('file', ''),
                'line': vuln.get('line', ''),
                'pattern': pattern,
                'recommendation': vuln.get('recommendation', 'Review and fix this security issue')
            }
            
            return enhanced_vuln
        
        # Get all vulnerabilities and filter
        all_vulnerabilities = results.get("vulnerabilities", [])
        all_security_issues = results.get("security_issues", [])
        
        # Combine and filter vulnerabilities
        combined_vulns = all_vulnerabilities + all_security_issues
        filtered_vulns = []
        
        for vuln in combined_vulns:
            cleaned_vuln = clean_vulnerability(vuln)
            if cleaned_vuln:
                filtered_vulns.append(cleaned_vuln)
        
        # Categorize by severity
        critical_vulns = [v for v in filtered_vulns if v.get("severity") == "critical"]
        high_vulns = [v for v in filtered_vulns if v.get("severity") == "high"]
        medium_vulns = [v for v in filtered_vulns if v.get("severity") == "medium"]
        low_vulns = [v for v in filtered_vulns if v.get("severity") == "low"]
        
        # Get analysis results
        static_analysis = results.get("static_analysis", {}) or {"message": "No static analysis results."}
        dynamic_analysis = results.get("dynamic_analysis", {}) or {"message": "No dynamic analysis results."}
        network_analysis = results.get("network_analysis", {}) or {"message": "No network analysis results."}
        storage_analysis = results.get("storage_analysis", {}) or {"message": "No storage analysis results."}
        code_analysis = static_analysis.get("code_analysis", {}) or results.get("code_analysis", {}) or {"message": "No code analysis results."}
        
        # Generate recommendations
        recommendations = results.get("recommendations", [])
        if not recommendations:
            recommendations = [
                "Implement proper input validation for all user inputs",
                "Use HTTPS for all network communications",
                "Store sensitive data in encrypted storage",
                "Implement certificate pinning for network communications",
                "Disable keyboard cache for sensitive input fields",
                "Use secure logging practices",
                "Implement proper session management",
                "Regular security audits and penetration testing",
                "Use ProGuard/R8 for code obfuscation",
                "Implement proper error handling"
            ]
        
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
            "recommendations": recommendations,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def _get_html_template(self) -> str:
        """Get clean, modern HTML template for report."""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mobile Security Analysis Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --success: #059669;
            --warning: #d97706;
            --danger: #dc2626;
            --info: #0891b2;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-300: #d1d5db;
            --gray-400: #9ca3af;
            --gray-500: #6b7280;
            --gray-600: #4b5563;
            --gray-700: #374151;
            --gray-800: #1f2937;
            --gray-900: #111827;
            --white: #ffffff;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.6;
            color: var(--gray-800);
            background: var(--gray-50);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .header {
            background: var(--white);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--gray-900);
            margin-bottom: 0.5rem;
        }
        
        .header .subtitle {
            color: var(--gray-600);
            font-size: 1.1rem;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .summary-card {
            background: var(--white);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            border-left: 4px solid var(--primary);
        }
        
        .summary-card.critical { border-left-color: var(--danger); }
        .summary-card.high { border-left-color: var(--warning); }
        .summary-card.medium { border-left-color: var(--info); }
        .summary-card.low { border-left-color: var(--success); }
        
        .summary-card h3 {
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--gray-500);
            margin-bottom: 0.5rem;
        }
        
        .summary-card .value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--gray-900);
        }
        
        .summary-card .label {
            font-size: 0.875rem;
            color: var(--gray-600);
            margin-top: 0.25rem;
        }
        
        .section {
            background: var(--white);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        .section h2 {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--gray-900);
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .section h2 .icon {
            font-size: 1.25rem;
        }
        
        .vulnerability-item {
            border: 1px solid var(--gray-200);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            background: var(--gray-50);
        }
        
        .vulnerability-item.critical { border-left: 4px solid var(--danger); }
        .vulnerability-item.high { border-left: 4px solid var(--warning); }
        .vulnerability-item.medium { border-left: 4px solid var(--info); }
        .vulnerability-item.low { border-left: 4px solid var(--success); }
        
        .vulnerability-header {
            display: flex;
            justify-content: between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }
        
        .vulnerability-title {
            font-weight: 600;
            color: var(--gray-900);
            flex: 1;
        }
        
        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .severity-badge.critical {
            background: var(--danger);
            color: var(--white);
        }
        
        .severity-badge.high {
            background: var(--warning);
            color: var(--white);
        }
        
        .severity-badge.medium {
            background: var(--info);
            color: var(--white);
        }
        
        .severity-badge.low {
            background: var(--success);
            color: var(--white);
        }
        
        .vulnerability-details {
            margin-bottom: 1rem;
        }
        
        .detail-row {
            display: flex;
            margin-bottom: 0.5rem;
        }
        
        .detail-label {
            font-weight: 500;
            color: var(--gray-700);
            min-width: 120px;
        }
        
        .detail-value {
            color: var(--gray-600);
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.875rem;
        }
        
        .recommendation {
            background: var(--primary);
            color: var(--white);
            padding: 1rem;
            border-radius: 8px;
            font-size: 0.875rem;
        }
        
        .no-issues {
            text-align: center;
            padding: 3rem 2rem;
            color: var(--gray-500);
        }
        
        .no-issues .icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }
        
        .no-issues h3 {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .no-issues p {
            font-size: 0.875rem;
        }
        
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--gray-500);
            font-size: 0.875rem;
        }
        
        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .header { padding: 1.5rem; }
            .header h1 { font-size: 2rem; }
            .summary-grid { grid-template-columns: 1fr; }
            .section { padding: 1.5rem; }
            .vulnerability-header { flex-direction: column; gap: 0.5rem; }
            .detail-row { flex-direction: column; gap: 0.25rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Mobile Security Analysis Report</h1>
            <p class="subtitle">{{ scan_info.file_path }} • {{ generated_at }}</p>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card critical">
                <h3>Critical Issues</h3>
                <div class="value">{{ critical_vulnerabilities|length }}</div>
                <div class="label">Immediate attention required</div>
            </div>
            <div class="summary-card high">
                <h3>High Risk Issues</h3>
                <div class="value">{{ high_vulnerabilities|length }}</div>
                <div class="label">Address within 1 week</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium Risk Issues</h3>
                <div class="value">{{ medium_vulnerabilities|length }}</div>
                <div class="label">Address within 1 month</div>
            </div>
            <div class="summary-card low">
                <h3>Low Risk Issues</h3>
                <div class="value">{{ low_vulnerabilities|length }}</div>
                <div class="label">Address when possible</div>
            </div>
        </div>
        
        {% if critical_vulnerabilities %}
        <div class="section">
            <h2><span class="icon">🚨</span>Critical Security Issues</h2>
            {% for vuln in critical_vulnerabilities %}
            <div class="vulnerability-item critical">
                <div class="vulnerability-header">
                    <div class="vulnerability-title">{{ vuln.title or vuln.type }}</div>
                    <span class="severity-badge critical">Critical</span>
                </div>
                <div class="vulnerability-details">
                    {% if vuln.description %}
                    <div class="detail-row">
                        <span class="detail-label">Description:</span>
                        <span class="detail-value">{{ vuln.description }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.file %}
                    <div class="detail-row">
                        <span class="detail-label">File:</span>
                        <span class="detail-value">{{ vuln.file }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.line %}
                    <div class="detail-row">
                        <span class="detail-label">Line:</span>
                        <span class="detail-value">{{ vuln.line }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.pattern %}
                    <div class="detail-row">
                        <span class="detail-label">Pattern:</span>
                        <span class="detail-value">{{ vuln.pattern }}</span>
                    </div>
                    {% endif %}
                </div>
                {% if vuln.recommendation %}
                <div class="recommendation">
                    <strong>Recommendation:</strong> {{ vuln.recommendation }}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if high_vulnerabilities %}
        <div class="section">
            <h2><span class="icon">⚠️</span>High Risk Security Issues</h2>
            {% for vuln in high_vulnerabilities %}
            <div class="vulnerability-item high">
                <div class="vulnerability-header">
                    <div class="vulnerability-title">{{ vuln.title or vuln.type }}</div>
                    <span class="severity-badge high">High</span>
                </div>
                <div class="vulnerability-details">
                    {% if vuln.description %}
                    <div class="detail-row">
                        <span class="detail-label">Description:</span>
                        <span class="detail-value">{{ vuln.description }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.file %}
                    <div class="detail-row">
                        <span class="detail-label">File:</span>
                        <span class="detail-value">{{ vuln.file }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.line %}
                    <div class="detail-row">
                        <span class="detail-label">Line:</span>
                        <span class="detail-value">{{ vuln.line }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.pattern %}
                    <div class="detail-row">
                        <span class="detail-label">Pattern:</span>
                        <span class="detail-value">{{ vuln.pattern }}</span>
                    </div>
                    {% endif %}
                </div>
                {% if vuln.recommendation %}
                <div class="recommendation">
                    <strong>Recommendation:</strong> {{ vuln.recommendation }}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if medium_vulnerabilities %}
        <div class="section">
            <h2><span class="icon">🔍</span>Medium Risk Security Issues</h2>
            {% for vuln in medium_vulnerabilities %}
            <div class="vulnerability-item medium">
                <div class="vulnerability-header">
                    <div class="vulnerability-title">{{ vuln.title or vuln.type }}</div>
                    <span class="severity-badge medium">Medium</span>
                </div>
                <div class="vulnerability-details">
                    {% if vuln.description %}
                    <div class="detail-row">
                        <span class="detail-label">Description:</span>
                        <span class="detail-value">{{ vuln.description }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.file %}
                    <div class="detail-row">
                        <span class="detail-label">File:</span>
                        <span class="detail-value">{{ vuln.file }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.line %}
                    <div class="detail-row">
                        <span class="detail-label">Line:</span>
                        <span class="detail-value">{{ vuln.line }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.pattern %}
                    <div class="detail-row">
                        <span class="detail-label">Pattern:</span>
                        <span class="detail-value">{{ vuln.pattern }}</span>
                    </div>
                    {% endif %}
                </div>
                {% if vuln.recommendation %}
                <div class="recommendation">
                    <strong>Recommendation:</strong> {{ vuln.recommendation }}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if low_vulnerabilities %}
        <div class="section">
            <h2><span class="icon">ℹ️</span>Low Risk Security Issues</h2>
            {% for vuln in low_vulnerabilities %}
            <div class="vulnerability-item low">
                <div class="vulnerability-header">
                    <div class="vulnerability-title">{{ vuln.title or vuln.type }}</div>
                    <span class="severity-badge low">Low</span>
                </div>
                <div class="vulnerability-details">
                    {% if vuln.description %}
                    <div class="detail-row">
                        <span class="detail-label">Description:</span>
                        <span class="detail-value">{{ vuln.description }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.file %}
                    <div class="detail-row">
                        <span class="detail-label">File:</span>
                        <span class="detail-value">{{ vuln.file }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.line %}
                    <div class="detail-row">
                        <span class="detail-label">Line:</span>
                        <span class="detail-value">{{ vuln.line }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.pattern %}
                    <div class="detail-row">
                        <span class="detail-label">Pattern:</span>
                        <span class="detail-value">{{ vuln.pattern }}</span>
                    </div>
                    {% endif %}
                </div>
                {% if vuln.recommendation %}
                <div class="recommendation">
                    <strong>Recommendation:</strong> {{ vuln.recommendation }}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if not critical_vulnerabilities and not high_vulnerabilities and not medium_vulnerabilities and not low_vulnerabilities %}
        <div class="section">
            <div class="no-issues">
                <div class="icon">✅</div>
                <h3>No Security Issues Found</h3>
                <p>Great job! No security vulnerabilities were detected in this analysis.</p>
            </div>
        </div>
        {% endif %}
        
        {% if recommendations %}
        <div class="section">
            <h2><span class="icon">💡</span>General Security Recommendations</h2>
            <ul style="list-style: none; padding: 0;">
                {% for rec in recommendations %}
                <li style="padding: 0.75rem 0; border-bottom: 1px solid var(--gray-200); color: var(--gray-700);">
                    • {{ rec }}
                </li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        <div class="footer">
            <p>Report generated by Mobile Security Tool • {{ generated_at }}</p>
        </div>
    </div>
</body>
</html>
        ''' 