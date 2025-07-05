"""
Report Generator for Threat Modeling Tool
Generates comprehensive threat modeling reports in multiple formats.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from jinja2 import Template
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .debug_utils import debug_print, debug_log

class ReportGenerator:
    """Generate threat modeling reports in various formats."""
    
    def __init__(self):
        """Initialize the report generator."""
        self.console = Console()
        self.templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, str]:
        """Load report templates."""
        return {
            "markdown": self._get_markdown_template(),
            "html": self._get_html_template(),
            "json": "{}"  # JSON doesn't need a template
        }
    
    def generate_report(self, threats: List[Dict], architecture: Dict, 
                       methodology: str, output_format: str = "markdown", 
                       output_file: Optional[str] = None) -> str:
        """Generate a comprehensive threat modeling report."""
        debug_log("report", f"Generating {output_format} report")
        
        # Prepare report data
        report_data = self._prepare_report_data(threats, architecture, methodology)
        
        # Generate report content
        if output_format == "markdown":
            content = self._generate_markdown_report(report_data)
        elif output_format == "html":
            content = self._generate_html_report(report_data)
        elif output_format == "json":
            content = self._generate_json_report(report_data)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        # Save to file if specified
        if output_file:
            self._save_report(content, output_file, output_format)
        
        debug_log("report", f"Report generated successfully: {output_format}")
        return content
    
    def _prepare_report_data(self, threats: List[Dict], architecture: Dict, 
                           methodology: str) -> Dict[str, Any]:
        """Prepare data for report generation."""
        debug_log("report", "Preparing report data")
        
        # Calculate summary statistics
        total_threats = len(threats)
        severity_counts = {}
        category_counts = {}
        
        for threat in threats:
            severity = threat.get("severity", "Unknown")
            category = threat.get("category", "Unknown")
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Get top threats by risk score
        top_threats = sorted(threats, key=lambda x: x.get("risk_score", 0), reverse=True)[:5]
        
        # Calculate average risk score
        avg_risk_score = sum(t.get("risk_score", 0) for t in threats) / len(threats) if threats else 0
        
        return {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "methodology": methodology,
                "architecture_name": architecture.get("name", "Unknown"),
                "total_threats": total_threats,
                "avg_risk_score": round(avg_risk_score, 2)
            },
            "architecture": architecture,
            "threats": threats,
            "summary": {
                "severity_counts": severity_counts,
                "category_counts": category_counts,
                "top_threats": top_threats
            }
        }
    
    def _generate_markdown_report(self, report_data: Dict[str, Any]) -> str:
        """Generate markdown report."""
        debug_log("report", "Generating markdown report")
        
        template = Template(self.templates["markdown"])
        return template.render(**report_data)
    
    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML report."""
        debug_log("report", "Generating HTML report")
        
        template = Template(self.templates["html"])
        return template.render(**report_data)
    
    def _generate_json_report(self, report_data: Dict[str, Any]) -> str:
        """Generate JSON report."""
        debug_log("report", "Generating JSON report")
        
        return json.dumps(report_data, indent=2)
    
    def _save_report(self, content: str, output_file: str, output_format: str) -> None:
        """Save report to file."""
        debug_log("report", f"Saving report to: {output_file}")
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.console.print(f"[green]Report saved to: {output_file}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]Error saving report: {e}[/red]")
            debug_log("report", f"Error saving report: {e}", "ERROR")
    
    def display_summary(self, threats: List[Dict], architecture: Dict, methodology: str) -> None:
        """Display a summary of the threat analysis."""
        debug_log("report", "Displaying threat analysis summary")
        
        # Create summary panel
        summary_text = f"""
[bold]Threat Modeling Summary[/bold]

Application: {architecture.get('name', 'Unknown')}
Methodology: {methodology}
Total Threats: {len(threats)}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        panel = Panel(summary_text, title="Threat Analysis Results", border_style="blue")
        self.console.print(panel)
        
        # Display severity breakdown
        if threats:
            severity_table = Table(title="Threats by Severity")
            severity_table.add_column("Severity", style="cyan")
            severity_table.add_column("Count", style="magenta")
            severity_table.add_column("Percentage", style="green")
            
            severity_counts = {}
            for threat in threats:
                severity = threat.get("severity", "Unknown")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            total = len(threats)
            for severity, count in severity_counts.items():
                percentage = (count / total) * 100
                severity_table.add_row(severity, str(count), f"{percentage:.1f}%")
            
            self.console.print(severity_table)
            
            # Display top threats
            if threats:
                self.console.print("\n[bold]Top 5 Threats by Risk Score[/bold]")
                top_threats = sorted(threats, key=lambda x: x.get("risk_score", 0), reverse=True)[:5]
                
                threat_table = Table()
                threat_table.add_column("Rank", style="cyan")
                threat_table.add_column("Threat", style="yellow")
                threat_table.add_column("Category", style="blue")
                threat_table.add_column("Risk Score", style="red")
                threat_table.add_column("Severity", style="magenta")
                
                for i, threat in enumerate(top_threats, 1):
                    threat_table.add_row(
                        str(i),
                        threat.get("title", "Unknown"),
                        threat.get("category", "Unknown"),
                        f"{threat.get('risk_score', 0):.1f}",
                        threat.get("severity", "Unknown")
                    )
                
                self.console.print(threat_table)
    
    def _get_markdown_template(self) -> str:
        """Get markdown report template."""
        return """# Threat Modeling Report

## Executive Summary

**Application:** {{ metadata.architecture_name }}  
**Methodology:** {{ metadata.methodology }}  
**Analysis Date:** {{ metadata.generated_at }}  
**Total Threats Identified:** {{ metadata.total_threats }}  
**Average Risk Score:** {{ metadata.avg_risk_score }}

### Key Findings

{% if summary.top_threats %}
**Top Threats:**
{% for threat in summary.top_threats %}
- **{{ threat.title }}** (Risk Score: {{ "%.1f"|format(threat.risk_score) }}, Severity: {{ threat.severity }})
{% endfor %}
{% endif %}

## Architecture Overview

**Description:** {{ architecture.description }}

### Components
{% for component in architecture.components %}
- **{{ component.name }}** ({{ component.type }})
  - Description: {{ component.description }}
  {% if component.technologies %}Technologies: {{ component.technologies|join(', ') }}{% endif %}
  {% if component.external %}[EXTERNAL]{% endif %}
{% endfor %}

### Data Flows
{% for flow in architecture.data_flows %}
- **{{ flow.from }}** → **{{ flow.to }}**
  - Protocol: {{ flow.protocol }}
  - Data Type: {{ flow.data_type }}
  {% if flow.encrypted %}✓ Encrypted{% else %}✗ Not Encrypted{% endif %}
{% endfor %}

### Trust Boundaries
{% for boundary in architecture.trust_boundaries %}
- **{{ boundary.name }}**
  - Components: {{ boundary.components|join(', ') }}
  - Description: {{ boundary.description }}
{% endfor %}

### Assets
{% for asset in architecture.assets %}
- **{{ asset.name }}** ({{ asset.type }})
  - Value: {{ asset.value }}
  - Description: {{ asset.description }}
{% endfor %}

## Threat Analysis

### Threat Summary by Severity

{% for severity, count in summary.severity_counts.items() %}
- **{{ severity }}:** {{ count }} threats
{% endfor %}

### Threat Summary by Category

{% for category, count in summary.category_counts.items() %}
- **{{ category }}:** {{ count }} threats
{% endfor %}

### Detailed Threat Analysis

{% for threat in threats %}
#### {{ threat.title }}

**Category:** {{ threat.category }}  
**Severity:** {{ threat.severity }}  
**Risk Score:** {{ "%.1f"|format(threat.risk_score) }}  
**Methodology:** {{ threat.methodology }}

**Description:** {{ threat.description }}

{% if threat.examples %}
**Examples:**
{% for example in threat.examples %}
- {{ example }}
{% endfor %}
{% endif %}

{% if threat.affected_components %}
**Affected Components:**
{% for component in threat.affected_components %}
- {{ component }}
{% endfor %}
{% endif %}

{% if threat.affected_data_flows %}
**Affected Data Flows:**
{% for flow in threat.affected_data_flows %}
- {{ flow }}
{% endfor %}
{% endif %}

{% if threat.mitigations %}
**Recommended Mitigations:**
{% for mitigation in threat.mitigations %}
- {{ mitigation }}
{% endfor %}
{% endif %}

{% if threat.dread_scores %}
**DREAD Scores:**
- Damage: {{ threat.dread_scores.Damage }}
- Reproducibility: {{ threat.dread_scores.Reproducibility }}
- Exploitability: {{ threat.dread_scores.Exploitability }}
- Affected Users: {{ threat.dread_scores.Affected_Users }}
- Discoverability: {{ threat.dread_scores.Discoverability }}
{% endif %}

---
{% endfor %}

## Risk Assessment

### Overall Risk Level

Based on the analysis, this application has an average risk score of **{{ metadata.avg_risk_score }}**.

{% if metadata.avg_risk_score >= 7 %}
**Risk Level: HIGH** - Immediate attention required. Critical vulnerabilities need to be addressed before deployment.
{% elif metadata.avg_risk_score >= 4 %}
**Risk Level: MEDIUM** - Several security concerns identified. Address high-priority threats before deployment.
{% else %}
**Risk Level: LOW** - Relatively secure architecture. Continue monitoring and address remaining threats.
{% endif %}

## Recommendations

### Immediate Actions (High Priority)
{% for threat in threats if threat.severity == "High" %}
- Address **{{ threat.title }}** - {{ threat.description }}
{% endfor %}

### Short-term Actions (Medium Priority)
{% for threat in threats if threat.severity == "Medium" %}
- Review **{{ threat.title }}** - {{ threat.description }}
{% endfor %}

### Long-term Actions (Low Priority)
{% for threat in threats if threat.severity == "Low" %}
- Monitor **{{ threat.title }}** - {{ threat.description }}
{% endfor %}

## Methodology Details

This threat analysis was conducted using the **{{ metadata.methodology }}** methodology:

{% if metadata.methodology == "STRIDE" %}
- **S**poofing: Identity spoofing and session hijacking
- **T**ampering: Data and configuration tampering
- **R**epudiation: Action repudiation and audit failures
- **I**nformation Disclosure: Sensitive data exposure
- **D**enial of Service: Resource exhaustion and service disruption
- **E**levation of Privilege: Privilege escalation and code execution
{% elif metadata.methodology == "PASTA" %}
- Process for Attack Simulation and Threat Analysis
- Focuses on business impact and attack simulation
- Considers threat intelligence and attack vectors
{% elif metadata.methodology == "DREAD" %}
- **D**amage: Potential damage to business
- **R**eproducibility: How easy to reproduce the attack
- **E**xploitability: How easy to exploit the vulnerability
- **A**ffected Users: Number of affected users
- **D**iscoverability: How easy to discover the vulnerability
{% endif %}

---

*Report generated by Threat Modeling Tool on {{ metadata.generated_at }}*
"""
    
    def _get_html_template(self) -> str:
        """Get HTML report template."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Modeling Report - {{ metadata.architecture_name }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .summary { background: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .threat { border: 1px solid #ddd; margin: 20px 0; padding: 15px; border-radius: 5px; }
        .high { border-left: 5px solid #ff4444; }
        .medium { border-left: 5px solid #ffaa00; }
        .low { border-left: 5px solid #44aa44; }
        .table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .table th, .table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .table th { background-color: #f2f2f2; }
        .risk-high { color: #ff4444; font-weight: bold; }
        .risk-medium { color: #ffaa00; font-weight: bold; }
        .risk-low { color: #44aa44; font-weight: bold; }
        h1, h2, h3 { color: #333; }
        .recommendations { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Threat Modeling Report</h1>
        <p><strong>Application:</strong> {{ metadata.architecture_name }}</p>
        <p><strong>Methodology:</strong> {{ metadata.methodology }}</p>
        <p><strong>Analysis Date:</strong> {{ metadata.generated_at }}</p>
        <p><strong>Total Threats:</strong> {{ metadata.total_threats }}</p>
        <p><strong>Average Risk Score:</strong> {{ metadata.avg_risk_score }}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Description:</strong> {{ architecture.description }}</p>
        
        {% if summary.top_threats %}
        <h3>Top Threats:</h3>
        <ul>
        {% for threat in summary.top_threats %}
            <li><strong>{{ threat.title }}</strong> (Risk Score: {{ "%.1f"|format(threat.risk_score) }}, Severity: {{ threat.severity }})</li>
        {% endfor %}
        </ul>
        {% endif %}
    </div>

    <h2>Architecture Overview</h2>
    
    <h3>Components</h3>
    <table class="table">
        <tr><th>Name</th><th>Type</th><th>Description</th><th>External</th></tr>
        {% for component in architecture.components %}
        <tr>
            <td>{{ component.name }}</td>
            <td>{{ component.type }}</td>
            <td>{{ component.description }}</td>
            <td>{% if component.external %}Yes{% else %}No{% endif %}</td>
        </tr>
        {% endfor %}
    </table>

    <h3>Data Flows</h3>
    <table class="table">
        <tr><th>From</th><th>To</th><th>Protocol</th><th>Data Type</th><th>Encrypted</th></tr>
        {% for flow in architecture.data_flows %}
        <tr>
            <td>{{ flow.from }}</td>
            <td>{{ flow.to }}</td>
            <td>{{ flow.protocol }}</td>
            <td>{{ flow.data_type }}</td>
            <td>{% if flow.encrypted %}Yes{% else %}No{% endif %}</td>
        </tr>
        {% endfor %}
    </table>

    <h2>Threat Analysis</h2>
    
    <h3>Threat Summary</h3>
    <table class="table">
        <tr><th>Severity</th><th>Count</th></tr>
        {% for severity, count in summary.severity_counts.items() %}
        <tr><td>{{ severity }}</td><td>{{ count }}</td></tr>
        {% endfor %}
    </table>

    {% for threat in threats %}
    <div class="threat {{ threat.severity.lower() }}">
        <h3>{{ threat.title }}</h3>
        <p><strong>Category:</strong> {{ threat.category }}</p>
        <p><strong>Severity:</strong> <span class="risk-{{ threat.severity.lower() }}">{{ threat.severity }}</span></p>
        <p><strong>Risk Score:</strong> {{ "%.1f"|format(threat.risk_score) }}</p>
        <p><strong>Description:</strong> {{ threat.description }}</p>
        
        {% if threat.examples %}
        <p><strong>Examples:</strong></p>
        <ul>
        {% for example in threat.examples %}
            <li>{{ example }}</li>
        {% endfor %}
        </ul>
        {% endif %}
        
        {% if threat.mitigations %}
        <p><strong>Recommended Mitigations:</strong></p>
        <ul>
        {% for mitigation in threat.mitigations %}
            <li>{{ mitigation }}</li>
        {% endfor %}
        </ul>
        {% endif %}
    </div>
    {% endfor %}

    <div class="recommendations">
        <h2>Recommendations</h2>
        
        <h3>Immediate Actions (High Priority)</h3>
        <ul>
        {% for threat in threats if threat.severity == "High" %}
            <li>Address <strong>{{ threat.title }}</strong> - {{ threat.description }}</li>
        {% endfor %}
        </ul>
        
        <h3>Short-term Actions (Medium Priority)</h3>
        <ul>
        {% for threat in threats if threat.severity == "Medium" %}
            <li>Review <strong>{{ threat.title }}</strong> - {{ threat.description }}</li>
        {% endfor %}
        </ul>
        
        <h3>Long-term Actions (Low Priority)</h3>
        <ul>
        {% for threat in threats if threat.severity == "Low" %}
            <li>Monitor <strong>{{ threat.title }}</strong> - {{ threat.description }}</li>
        {% endfor %}
        </ul>
    </div>

    <hr>
    <p><em>Report generated by Threat Modeling Tool on {{ metadata.generated_at }}</em></p>
</body>
</html>""" 