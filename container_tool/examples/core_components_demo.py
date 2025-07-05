#!/usr/bin/env python3
"""
Core Components Demo
Demonstrates the four core components of the Container Security Scanner:
1. Extracting container images and their layers
2. Generating a Software Bill of Materials (SBOM) for each layer
3. Matching the packages against a vulnerability database (like NVD)
4. Reporting the vulnerabilities
"""

import json
import os
import sys
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from container_security_scanner import ContainerSecurityScanner
from analyzers.sbom_analyzer import SBOMAnalyzer
from analyzers.vulnerability_analyzer import VulnerabilityAnalyzer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

def demo_sbom_generation():
    """Demonstrate SBOM generation for container images."""
    console = Console()
    console.print(Panel.fit(
        "[bold cyan]Core Component 1 & 2: Image Extraction & SBOM Generation[/bold cyan]\n"
        "Extracting container images and generating Software Bill of Materials for each layer",
        border_style="cyan"
    ))
    
    # Sample images to demonstrate
    sample_images = [
        "nginx:latest",
        "python:3.9-slim",
        "node:16-alpine",
        "ubuntu:20.04"
    ]
    
    sbom_analyzer = SBOMAnalyzer(debug=True)
    
    for image_name in sample_images:
        console.print(f"\n[bold yellow]Analyzing image: {image_name}[/bold yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Extracting image and generating SBOM...", total=None)
            
            try:
                # Extract image and generate SBOM
                sbom_results = sbom_analyzer.extract_image_and_generate_sbom(image_name)
                progress.update(task, completed=True)
                
                # Display SBOM summary
                if sbom_results and not sbom_results.get("errors"):
                    sbom = sbom_results.get("sbom", {})
                    
                    # Create SBOM summary table
                    table = Table(title=f"SBOM Summary for {image_name}")
                    table.add_column("Component", style="cyan")
                    table.add_column("Count", style="magenta")
                    table.add_column("Details", style="green")
                    
                    table.add_row(
                        "OS Packages", 
                        str(len(sbom.get("os_packages", []))),
                        f"Package managers: {', '.join(sbom.get('package_managers_detected', []))}"
                    )
                    table.add_row(
                        "Language Packages", 
                        str(len(sbom.get("language_packages", []))),
                        "Python, Node.js, Java, Go, Ruby, PHP packages"
                    )
                    table.add_row(
                        "Total Packages", 
                        str(sbom.get("total_packages", 0)),
                        "Combined OS and language packages"
                    )
                    table.add_row(
                        "Layers", 
                        str(len(sbom_results.get("layers", []))),
                        "Docker image layers analyzed"
                    )
                    
                    console.print(table)
                    
                    # Show sample packages
                    if sbom.get("os_packages"):
                        console.print("\n[bold]Sample OS Packages:[/bold]")
                        for i, pkg in enumerate(sbom["os_packages"][:5]):
                            console.print(f"  • {pkg.get('name', 'N/A')} {pkg.get('version', 'N/A')} ({pkg.get('package_manager', 'N/A')})")
                        if len(sbom["os_packages"]) > 5:
                            console.print(f"  ... and {len(sbom['os_packages']) - 5} more")
                    
                    if sbom.get("language_packages"):
                        console.print("\n[bold]Sample Language Packages:[/bold]")
                        for i, pkg in enumerate(sbom["language_packages"][:5]):
                            console.print(f"  • {pkg.get('name', 'N/A')} {pkg.get('version', 'N/A')} ({pkg.get('language', 'N/A')})")
                        if len(sbom["language_packages"]) > 5:
                            console.print(f"  ... and {len(sbom['language_packages']) - 5} more")
                
                else:
                    console.print(f"[red]Error generating SBOM for {image_name}: {sbom_results.get('errors', ['Unknown error'])}[/red]")
                    
            except Exception as e:
                console.print(f"[red]Exception during SBOM generation: {str(e)}[/red]")

def demo_vulnerability_scanning():
    """Demonstrate vulnerability database matching."""
    console = Console()
    console.print(Panel.fit(
        "[bold cyan]Core Component 3: Vulnerability Database Matching[/bold cyan]\n"
        "Matching packages against vulnerability databases (NVD, Red Hat, Ubuntu)",
        border_style="cyan"
    ))
    
    # Sample SBOM data for demonstration
    sample_sbom_data = {
        "sbom": {
            "os_packages": [
                {
                    "name": "openssl",
                    "version": "1.1.1f-1ubuntu2",
                    "package_manager": "apt",
                    "language": "os"
                },
                {
                    "name": "nginx",
                    "version": "1.18.0-0ubuntu1",
                    "package_manager": "apt",
                    "language": "os"
                },
                {
                    "name": "curl",
                    "version": "7.68.0-1ubuntu2.7",
                    "package_manager": "apt",
                    "language": "os"
                }
            ],
            "language_packages": [
                {
                    "name": "requests",
                    "version": "2.25.1",
                    "package_manager": "pip",
                    "language": "python"
                },
                {
                    "name": "lodash",
                    "version": "4.17.21",
                    "package_manager": "npm",
                    "language": "nodejs"
                },
                {
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "package_manager": "maven",
                    "language": "java"
                }
            ],
            "total_packages": 6,
            "package_managers_detected": ["apt", "pip", "npm", "maven"]
        }
    }
    
    vulnerability_analyzer = VulnerabilityAnalyzer(debug=True)
    
    console.print("\n[bold yellow]Scanning SBOM for vulnerabilities...[/bold yellow]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Querying vulnerability databases...", total=None)
        
        try:
            # Scan SBOM for vulnerabilities
            vuln_results = vulnerability_analyzer.scan_sbom(sample_sbom_data)
            progress.update(task, completed=True)
            
            # Display vulnerability summary
            summary = vuln_results.get("summary", {})
            
            vuln_table = Table(title="Vulnerability Scan Results")
            vuln_table.add_column("Severity", style="cyan")
            vuln_table.add_column("Count", style="magenta")
            vuln_table.add_column("Description", style="green")
            
            vuln_table.add_row("Critical", str(summary.get("critical", 0)), "Immediate action required")
            vuln_table.add_row("High", str(summary.get("high", 0)), "Prompt remediation needed")
            vuln_table.add_row("Medium", str(summary.get("medium", 0)), "Address within 30 days")
            vuln_table.add_row("Low", str(summary.get("low", 0)), "Monitor and plan updates")
            vuln_table.add_row("Info", str(summary.get("info", 0)), "Informational findings")
            vuln_table.add_row("Total", str(summary.get("total_vulnerabilities", 0)), "All vulnerabilities found")
            
            console.print(vuln_table)
            
            # Show databases queried
            databases = vuln_results.get("databases_queried", [])
            console.print(f"\n[bold]Vulnerability Databases Queried:[/bold] {', '.join(databases)}")
            
            # Show sample vulnerabilities
            vulnerabilities = vuln_results.get("vulnerabilities", [])
            if vulnerabilities:
                console.print("\n[bold]Sample Vulnerabilities Found:[/bold]")
                for i, vuln in enumerate(vulnerabilities[:3]):
                    console.print(f"  • {vuln.get('cve_id', 'N/A')} - {vuln.get('severity', 'N/A').upper()}")
                    console.print(f"    Package: {vuln.get('query_package', 'N/A')} {vuln.get('query_version', 'N/A')}")
                    console.print(f"    Database: {vuln.get('database', 'N/A')}")
                    console.print(f"    Description: {vuln.get('description', 'N/A')[:100]}...")
                    console.print()
                if len(vulnerabilities) > 3:
                    console.print(f"  ... and {len(vulnerabilities) - 3} more vulnerabilities")
            
        except Exception as e:
            console.print(f"[red]Exception during vulnerability scanning: {str(e)}[/red]")

def demo_comprehensive_reporting():
    """Demonstrate comprehensive vulnerability reporting."""
    console = Console()
    console.print(Panel.fit(
        "[bold cyan]Core Component 4: Vulnerability Reporting[/bold cyan]\n"
        "Generating comprehensive vulnerability reports with risk assessment and remediation guidance",
        border_style="cyan"
    ))
    
    # Sample vulnerability scan results
    sample_vuln_results = {
        "scan_date": "2024-01-15T10:30:00",
        "vulnerabilities": [
            {
                "cve_id": "CVE-2021-3711",
                "description": "OpenSSL vulnerability in SM2 decryption",
                "severity": "critical",
                "cvss_score": 9.8,
                "query_package": "openssl",
                "query_version": "1.1.1f-1ubuntu2",
                "database": "nvd",
                "published_date": "2021-08-24",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3711"]
            },
            {
                "cve_id": "CVE-2021-23017",
                "description": "nginx vulnerability in resolver",
                "severity": "high",
                "cvss_score": 7.5,
                "query_package": "nginx",
                "query_version": "1.18.0-0ubuntu1",
                "database": "nvd",
                "published_date": "2021-05-25",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"]
            },
            {
                "cve_id": "CVE-2021-22947",
                "description": "curl vulnerability in FTP wildcard matching",
                "severity": "medium",
                "cvss_score": 6.5,
                "query_package": "curl",
                "query_version": "7.68.0-1ubuntu2.7",
                "database": "nvd",
                "published_date": "2021-09-15",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-22947"]
            }
        ],
        "summary": {
            "total_vulnerabilities": 3,
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 0,
            "info": 0
        },
        "packages_scanned": 6,
        "databases_queried": ["nvd", "redhat", "ubuntu"]
    }
    
    vulnerability_analyzer = VulnerabilityAnalyzer(debug=True)
    
    console.print("\n[bold yellow]Generating comprehensive vulnerability report...[/bold yellow]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Generating report...", total=None)
        
        try:
            # Generate comprehensive report
            report = vulnerability_analyzer.generate_vulnerability_report(sample_vuln_results)
            progress.update(task, completed=True)
            
            # Display report sections
            console.print("\n[bold]📊 Executive Summary[/bold]")
            exec_summary = report.get("executive_summary", {})
            console.print(f"  Overall Risk Level: [bold]{exec_summary.get('overall_risk_level', 'N/A')}[/bold]")
            console.print(f"  Total Vulnerabilities: {exec_summary.get('total_vulnerabilities', 0)}")
            console.print(f"  Packages Scanned: {exec_summary.get('packages_scanned', 0)}")
            
            key_findings = exec_summary.get("key_findings", [])
            if key_findings:
                console.print("  Key Findings:")
                for finding in key_findings:
                    console.print(f"    • {finding}")
            
            # Risk Assessment
            console.print("\n[bold]⚠️ Risk Assessment[/bold]")
            risk_assessment = report.get("risk_assessment", {})
            console.print(f"  Risk Level: [bold]{risk_assessment.get('risk_level', 'N/A')}[/bold]")
            
            risk_factors = risk_assessment.get("risk_factors", [])
            if risk_factors:
                console.print("  Risk Factors:")
                for factor in risk_factors:
                    console.print(f"    • {factor}")
            
            # Attack Surface
            attack_surface = risk_assessment.get("attack_surface", {})
            if attack_surface:
                console.print("  Attack Surface:")
                console.print(f"    • Remote Code Execution: {attack_surface.get('remote_code_execution', 0)}")
                console.print(f"    • Privilege Escalation: {attack_surface.get('privilege_escalation', 0)}")
                console.print(f"    • Information Disclosure: {attack_surface.get('information_disclosure', 0)}")
                console.print(f"    • Denial of Service: {attack_surface.get('denial_of_service', 0)}")
            
            # Remediation Guidance
            console.print("\n[bold]🔧 Remediation Guidance[/bold]")
            remediation = report.get("remediation_guidance", {})
            
            immediate_actions = remediation.get("immediate_actions", [])
            if immediate_actions:
                console.print("  [bold red]Immediate Actions Required:[/bold red]")
                for action in immediate_actions:
                    console.print(f"    • {action.get('cve_id', 'N/A')}: {action.get('action', 'N/A')}")
                    console.print(f"      Package: {action.get('package', 'N/A')}")
            
            short_term_actions = remediation.get("short_term_actions", [])
            if short_term_actions:
                console.print("  [bold yellow]Short-term Actions (30 days):[/bold yellow]")
                for action in short_term_actions:
                    console.print(f"    • {action.get('cve_id', 'N/A')}: {action.get('action', 'N/A')}")
            
            # Compliance Impact
            console.print("\n[bold]📋 Compliance Impact[/bold]")
            compliance = report.get("compliance_impact", {})
            
            for standard, details in compliance.items():
                status = "✅ Compliant" if details.get("compliant") else "❌ Non-compliant"
                console.print(f"  {standard.upper()}: {status}")
                console.print(f"    Issues: {details.get('issues', 0)}")
                console.print(f"    Requirements: {', '.join(details.get('requirements', []))}")
            
        except Exception as e:
            console.print(f"[red]Exception during report generation: {str(e)}[/red]")

def demo_integrated_workflow():
    """Demonstrate the complete integrated workflow."""
    console = Console()
    console.print(Panel.fit(
        "[bold cyan]Complete Integrated Workflow[/bold cyan]\n"
        "Demonstrating all four core components working together",
        border_style="cyan"
    ))
    
    # Initialize the main scanner
    scanner = ContainerSecurityScanner(debug=True)
    
    # Sample image for demonstration
    sample_image = "nginx:latest"
    
    console.print(f"\n[bold yellow]Running complete scan on: {sample_image}[/bold yellow]")
    
    try:
        # Run comprehensive scan with all core components
        results = scanner.scan_docker_image(
            sample_image, 
            tests=["sbom", "vulnerabilities", "secrets", "compliance", "configuration"]
        )
        
        # Display integrated results
        console.print("\n[bold]🎯 Integrated Scan Results[/bold]")
        
        # SBOM Summary
        sbom_analysis = results.get("sbom_analysis", {})
        if sbom_analysis:
            sbom = sbom_analysis.get("sbom", {})
            console.print(f"  📦 SBOM Generated: {sbom.get('total_packages', 0)} packages across {len(sbom_analysis.get('layers', []))} layers")
        
        # Vulnerability Summary
        vuln_analysis = results.get("vulnerability_analysis", {})
        if vuln_analysis:
            summary = vuln_analysis.get("summary", {})
            console.print(f"  🔍 Vulnerabilities Found: {summary.get('total_vulnerabilities', 0)} total")
            console.print(f"    Critical: {summary.get('critical', 0)}, High: {summary.get('high', 0)}, Medium: {summary.get('medium', 0)}")
        
        # Overall Summary
        overall_summary = results.get("summary", {})
        console.print(f"  🎯 Overall Risk Level: [bold]{overall_summary.get('overall_risk', 'N/A')}[/bold]")
        
        # Generate and save report
        report_file = scanner.generate_report("integrated_demo_report.json", "json")
        console.print(f"  📄 Comprehensive Report: {report_file}")
        
    except Exception as e:
        console.print(f"[red]Exception during integrated workflow: {str(e)}[/red]")

def main():
    """Main demo function."""
    console = Console()
    
    console.print(Panel.fit(
        "[bold green]Container Security Scanner - Core Components Demo[/bold green]\n"
        "This demo showcases the four core components:\n"
        "1. 🔍 Image Extraction & Layer Analysis\n"
        "2. 📦 SBOM Generation for Each Layer\n"
        "3. 🛡️ Vulnerability Database Matching\n"
        "4. 📊 Comprehensive Vulnerability Reporting",
        border_style="green"
    ))
    
    # Run individual component demos
    demo_sbom_generation()
    demo_vulnerability_scanning()
    demo_comprehensive_reporting()
    demo_integrated_workflow()
    
    console.print(Panel.fit(
        "[bold green]✅ Core Components Demo Complete![/bold green]\n"
        "All four core components have been demonstrated successfully.\n"
        "The Container Security Scanner provides comprehensive container security analysis.",
        border_style="green"
    ))

if __name__ == "__main__":
    main() 