#!/usr/bin/env python3
"""
Container Security Scanner
A comprehensive container security testing tool for senior AppSec engineers.
Supports Docker images, Kubernetes configurations, runtime security, and compliance checking.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

import docker
import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel

from .analyzers.docker_analyzer import DockerAnalyzer
from .analyzers.kubernetes_analyzer import KubernetesAnalyzer
from .analyzers.runtime_analyzer import RuntimeAnalyzer
from .analyzers.vulnerability_analyzer import VulnerabilityAnalyzer
from .analyzers.compliance_analyzer import ComplianceAnalyzer
from .analyzers.secret_analyzer import SecretAnalyzer
from .analyzers.sbom_analyzer import SBOMAnalyzer
from .analyzers.debian_package_analyzer import DebianPackageAnalyzer
from .analyzers.vulnerability_matcher import VulnerabilityMatcher
from .reporting.report_generator import ReportGenerator
from .utils.debug_utils import setup_debug_logging, debug_print

class ContainerSecurityScanner:
    """Main class for container security scanning."""
    
    def __init__(self, config_file: str = None, debug: bool = False):
        """Initialize the container security scanner."""
        self.console = Console()
        self.debug = debug
        self.results = {
            "scan_info": {},
            "sbom_analysis": {},
            "debian_analysis": {},
            "vulnerability_matching": {},
            "docker_analysis": {},
            "kubernetes_analysis": {},
            "runtime_analysis": {},
            "vulnerability_analysis": {},
            "compliance_analysis": {},
            "secret_analysis": {},
            "vulnerabilities": [],
            "summary": {}
        }
        
        # Initialize analyzers
        self.sbom_analyzer = SBOMAnalyzer(debug=debug)
        self.debian_analyzer = DebianPackageAnalyzer(debug=debug)
        self.vulnerability_matcher = VulnerabilityMatcher(debug=debug)
        self.docker_analyzer = DockerAnalyzer(debug=debug)
        self.kubernetes_analyzer = KubernetesAnalyzer(debug=debug)
        self.runtime_analyzer = RuntimeAnalyzer(debug=debug)
        self.vulnerability_analyzer = VulnerabilityAnalyzer(debug=debug)
        self.compliance_analyzer = ComplianceAnalyzer(debug=debug)
        self.secret_analyzer = SecretAnalyzer(debug=debug)
        self.report_generator = ReportGenerator(debug=debug)
        
        # Setup logging
        self._setup_logging()
        
        # Initialize Docker client
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            self.console.print(f"[yellow]Warning: Docker client not available: {str(e)}[/yellow]")
            self.docker_client = None
        
        # Load configuration
        if config_file and os.path.exists(config_file):
            self._load_config(config_file)
    
    def _setup_logging(self):
        """Setup logging configuration."""
        if self.debug:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.StreamHandler(sys.stdout),
                    logging.FileHandler('container_security_debug.log')
                ]
            )
        else:
            logging.basicConfig(level=logging.INFO)
    
    def _load_config(self, config_file: str):
        """Load configuration from file."""
        try:
            with open(config_file, 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            self.console.print(f"[red]Error loading config: {str(e)}[/red]")
            self.config = {}
    
    def scan_debian_image_phase1_step2(self, image_name: str) -> Dict[str, Any]:
        """
        Phase 1, Step 2: Package Vulnerability Matching
        Combines Phase 1, Step 1 (image extraction) with vulnerability matching
        """
        self.console.print(f"[bold cyan]Phase 1, Step 2: Package Vulnerability Matching - {image_name}[/bold cyan]")
        
        # Update scan info
        self.results["scan_info"] = {
            "target_type": "debian_image_phase1_step2",
            "target_name": image_name,
            "scan_date": datetime.now().isoformat(),
            "phase": "1",
            "step": "2",
            "description": "Basic OS Package Vulnerability Scanning for Debian-based images - Package Vulnerability Matching"
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Phase 1, Step 1: Extract Debian image and analyze layers
            task = progress.add_task("Phase 1, Step 1: Extracting Debian image and analyzing layers...", total=None)
            
            try:
                # Extract Debian image using specialized analyzer
                debian_results = self.debian_analyzer.extract_debian_image(image_name)
                self.results["debian_analysis"] = debian_results
                
                # Generate extraction report
                extraction_report = self.debian_analyzer.generate_extraction_report(debian_results)
                self.results["debian_analysis"]["extraction_report"] = extraction_report
                
                progress.update(task, completed=True)
                
                # Display extraction summary
                self._display_debian_extraction_summary(debian_results)
                
            except Exception as e:
                debug_print(f"Error in Phase 1, Step 1: {str(e)}")
                self.results["debian_analysis"]["errors"] = [str(e)]
                progress.update(task, completed=True)
                return self.results
            
            # Phase 1, Step 2: Match packages against vulnerability database
            task = progress.add_task("Phase 1, Step 2: Matching packages against vulnerability database...", total=None)
            
            try:
                # Match packages against vulnerability database
                vulnerability_results = self.vulnerability_matcher.match_debian_packages(debian_results)
                self.results["vulnerability_matching"] = vulnerability_results
                
                progress.update(task, completed=True)
                
                # Display vulnerability matching summary
                self._display_vulnerability_matching_summary(vulnerability_results)
                
            except Exception as e:
                debug_print(f"Error in Phase 1, Step 2: {str(e)}")
                self.results["vulnerability_matching"]["errors"] = [str(e)]
                progress.update(task, completed=True)
        
        return self.results
    
    def scan_debian_image_phase1(self, image_name: str) -> Dict[str, Any]:
        """
        Phase 1: Basic OS Package Vulnerability Scanning for Debian-based images
        Step 1: Image Extraction - Use Docker SDK to pull an image and extract its layers
        """
        self.console.print(f"[bold cyan]Phase 1, Step 1: Debian Image Extraction - {image_name}[/bold cyan]")
        
        # Update scan info
        self.results["scan_info"] = {
            "target_type": "debian_image_phase1",
            "target_name": image_name,
            "scan_date": datetime.now().isoformat(),
            "phase": "1",
            "step": "1",
            "description": "Basic OS Package Vulnerability Scanning for Debian-based images - Image Extraction"
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Phase 1, Step 1: Extract Debian image and analyze layers
            task = progress.add_task("Extracting Debian image and analyzing layers...", total=None)
            
            try:
                # Extract Debian image using specialized analyzer
                debian_results = self.debian_analyzer.extract_debian_image(image_name)
                self.results["debian_analysis"] = debian_results
                
                # Generate extraction report
                extraction_report = self.debian_analyzer.generate_extraction_report(debian_results)
                self.results["debian_analysis"]["extraction_report"] = extraction_report
                
                progress.update(task, completed=True)
                
                # Display extraction summary
                self._display_debian_extraction_summary(debian_results)
                
            except Exception as e:
                debug_print(f"Error in Phase 1, Step 1: {str(e)}")
                self.results["debian_analysis"]["errors"] = [str(e)]
                progress.update(task, completed=True)
        
        return self.results
    
    def _display_vulnerability_matching_summary(self, vulnerability_results: Dict[str, Any]):
        """Display summary of vulnerability matching results."""
        self.console.print("\n[bold]🔍 Vulnerability Matching Summary[/bold]")
        
        # Create summary table
        table = Table(title="Phase 1, Step 2 Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        scan_info = vulnerability_results.get('scan_info', {})
        overall_stats = vulnerability_results.get('overall_statistics', {})
        risk_assessment = vulnerability_results.get('risk_assessment', {})
        
        table.add_row("Scan ID", scan_info.get('scan_id', 'N/A'))
        table.add_row("Total Packages Checked", str(overall_stats.get('total_packages', 0)))
        table.add_row("Vulnerable Packages", str(overall_stats.get('vulnerable_packages', 0)))
        table.add_row("Secure Packages", str(overall_stats.get('secure_packages', 0)))
        table.add_row("Total Vulnerabilities", str(overall_stats.get('total_vulnerabilities', 0)))
        table.add_row("Vulnerability Rate", f"{overall_stats.get('vulnerability_rate', 0):.1f}%")
        
        self.console.print(table)
        
        # Severity breakdown
        if overall_stats.get('total_vulnerabilities', 0) > 0:
            self.console.print(f"\n[bold]🚨 Vulnerability Severity Breakdown[/bold]")
            
            severity_table = Table(title="Severity Distribution")
            severity_table.add_column("Severity", style="cyan")
            severity_table.add_column("Count", style="magenta")
            severity_table.add_column("Percentage", style="green")
            
            total_vulns = overall_stats.get('total_vulnerabilities', 0)
            
            for severity in ['critical_vulnerabilities', 'high_vulnerabilities', 'medium_vulnerabilities', 'low_vulnerabilities']:
                count = overall_stats.get(severity, 0)
                if count > 0:
                    percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
                    severity_name = severity.replace('_vulnerabilities', '').upper()
                    severity_table.add_row(severity_name, str(count), f"{percentage:.1f}%")
            
            self.console.print(severity_table)
        
        # Risk assessment
        if risk_assessment:
            self.console.print(f"\n[bold]⚠️ Risk Assessment[/bold]")
            
            risk_table = Table(title="Risk Analysis")
            risk_table.add_column("Metric", style="cyan")
            risk_table.add_column("Value", style="magenta")
            
            risk_table.add_row("Risk Level", risk_assessment.get('risk_level', 'N/A'))
            risk_table.add_row("Risk Score", str(risk_assessment.get('risk_score', 0)))
            risk_table.add_row("Risk Description", risk_assessment.get('risk_description', 'N/A'))
            
            self.console.print(risk_table)
            
            # Recommendations
            recommendations = risk_assessment.get('recommendations', [])
            if recommendations:
                self.console.print(f"\n[bold]📋 Security Recommendations[/bold]")
                for i, rec in enumerate(recommendations[:5], 1):  # Show first 5
                    self.console.print(f"  {i}. {rec}")
                if len(recommendations) > 5:
                    self.console.print(f"  ... and {len(recommendations) - 5} more recommendations")
        
        # Top vulnerable packages
        package_summaries = vulnerability_results.get('package_summaries', [])
        vulnerable_packages = [p for p in package_summaries if p.get('total_vulnerabilities', 0) > 0]
        
        if vulnerable_packages:
            self.console.print(f"\n[bold]📦 Top Vulnerable Packages[/bold]")
            
            # Sort by total vulnerabilities
            vulnerable_packages.sort(key=lambda x: x.get('total_vulnerabilities', 0), reverse=True)
            
            package_table = Table(title="Vulnerable Packages")
            package_table.add_column("Package", style="cyan")
            package_table.add_column("Version", style="magenta")
            package_table.add_column("Total Vulns", style="red")
            package_table.add_column("Critical", style="red")
            package_table.add_column("High", style="yellow")
            
            for package in vulnerable_packages[:10]:  # Show top 10
                package_table.add_row(
                    package.get('package_name', 'N/A'),
                    package.get('package_version', 'N/A'),
                    str(package.get('total_vulnerabilities', 0)),
                    str(package.get('critical_vulnerabilities', 0)),
                    str(package.get('high_vulnerabilities', 0))
                )
            
            self.console.print(package_table)
        
        # Show errors if any
        errors = vulnerability_results.get('errors', [])
        if errors:
            self.console.print(f"\n[bold red]❌ Errors ({len(errors)})[/bold red]")
            for error in errors:
                self.console.print(f"  • {error}")
    
    def scan_docker_image(self, image_name: str, tests: List[str] = None) -> Dict[str, Any]:
        """Scan Docker image for security issues with core components."""
        self.console.print(f"[bold cyan]Scanning Docker image: {image_name}[/bold cyan]")
        
        # Update scan info
        self.results["scan_info"] = {
            "target_type": "docker_image",
            "target_name": image_name,
            "scan_date": datetime.now().isoformat(),
            "tests_performed": tests or ["sbom", "vulnerabilities", "secrets", "compliance", "configuration"]
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # 1. Extract container images and their layers
            if "sbom" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Extracting image and generating SBOM...", total=None)
                self.results["sbom_analysis"] = self.sbom_analyzer.extract_image_and_generate_sbom(image_name)
                progress.update(task, completed=True)
            
            # 2. Generate Software Bill of Materials (SBOM) for each layer
            if "sbom" in self.results["scan_info"]["tests_performed"] and self.results["sbom_analysis"]:
                task = progress.add_task("Analyzing SBOM components...", total=None)
                # SBOM analysis is already done in the previous step
                # Additional SBOM processing can be added here
                progress.update(task, completed=True)
            
            # 3. Match packages against vulnerability database
            if "vulnerabilities" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Scanning for vulnerabilities...", total=None)
                if self.results["sbom_analysis"]:
                    # Use SBOM data for vulnerability scanning
                    self.results["vulnerability_analysis"] = self.vulnerability_analyzer.scan_sbom(self.results["sbom_analysis"])
                else:
                    # Fallback to direct image scanning
                    self.results["vulnerability_analysis"] = self.vulnerability_analyzer.scan_image(image_name)
                progress.update(task, completed=True)
            
            # Docker Image Analysis
            if "configuration" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Analyzing Docker image configuration...", total=None)
                self.results["docker_analysis"] = self.docker_analyzer.analyze_image(image_name)
                progress.update(task, completed=True)
            
            # Secret Analysis
            if "secrets" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Scanning for secrets...", total=None)
                self.results["secret_analysis"] = self.secret_analyzer.scan_image(image_name)
                progress.update(task, completed=True)
            
            # Compliance Analysis
            if "compliance" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Checking compliance...", total=None)
                self.results["compliance_analysis"] = self.compliance_analyzer.check_docker_compliance(image_name)
                progress.update(task, completed=True)
        
        # 4. Generate comprehensive vulnerability report
        if self.results["vulnerability_analysis"]:
            task = progress.add_task("Generating vulnerability report...", total=None)
            vulnerability_report = self.vulnerability_analyzer.generate_vulnerability_report(
                self.results["vulnerability_analysis"]
            )
            self.results["vulnerability_report"] = vulnerability_report
            progress.update(task, completed=True)
        
        # Generate vulnerability summary
        self._generate_vulnerability_summary()
        
        return self.results
    
    def _display_debian_extraction_summary(self, debian_results: Dict[str, Any]):
        """Display summary of Debian image extraction results."""
        self.console.print("\n[bold]🐧 Debian Image Extraction Summary[/bold]")
        
        # Create summary table
        table = Table(title="Phase 1, Step 1 Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Image Name", debian_results.get("image_name", "N/A"))
        table.add_row("Extraction Time", f"{debian_results.get('extraction_time', 0):.2f} seconds")
        table.add_row("Total Layers", str(len(debian_results.get("layers", []))))
        table.add_row("Total Size", f"{debian_results.get('total_size', 0) / (1024*1024):.2f} MB")
        table.add_row("Extraction Path", debian_results.get("extraction_path", "N/A"))
        
        # Add Debian-specific information
        debian_info = debian_results.get("debian_info", {})
        if debian_info:
            table.add_row("Distribution", debian_info.get("distribution", "N/A"))
            table.add_row("Version", debian_info.get("version", "N/A"))
            table.add_row("Codename", debian_info.get("codename", "N/A"))
            table.add_row("Package Count", str(debian_info.get("package_count", 0)))
        
        self.console.print(table)
        
        # Show layer summary
        layers = debian_results.get("layers", [])
        if layers:
            self.console.print(f"\n[bold]📦 Layer Analysis ({len(layers)} layers)[/bold]")
            
            layer_table = Table(title="Layer Summary")
            layer_table.add_column("Layer", style="cyan")
            layer_table.add_column("Size (MB)", style="magenta")
            layer_table.add_column("Files", style="green")
            layer_table.add_column("Debian Files", style="yellow")
            layer_table.add_column("Packages", style="blue")
            
            for layer in layers:
                layer_table.add_row(
                    f"Layer {layer.get('index', 0)}",
                    f"{layer.get('size', 0) / (1024*1024):.2f}",
                    str(layer.get('files', {}).get('total', 0)),
                    str(layer.get('files', {}).get('debian_files', 0)),
                    str(len(layer.get('debian_packages', [])))
                )
            
            self.console.print(layer_table)
        
        # Show errors if any
        errors = debian_results.get("errors", [])
        if errors:
            self.console.print(f"\n[bold red]❌ Errors ({len(errors)})[/bold red]")
            for error in errors:
                self.console.print(f"  • {error}")
    
    def scan_kubernetes_manifests(self, manifest_path: str, tests: List[str] = None) -> Dict[str, Any]:
        """Scan Kubernetes manifests for security issues."""
        self.console.print(f"[bold cyan]Scanning Kubernetes manifests: {manifest_path}[/bold cyan]")
        
        # Update scan info
        self.results["scan_info"] = {
            "target_type": "kubernetes_manifests",
            "target_path": manifest_path,
            "scan_date": datetime.now().isoformat(),
            "tests_performed": tests or ["rbac", "network_policies", "secrets", "compliance", "configuration"]
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Kubernetes Configuration Analysis
            if "configuration" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Analyzing Kubernetes configuration...", total=None)
                self.results["kubernetes_analysis"] = self.kubernetes_analyzer.analyze_manifests(manifest_path)
                progress.update(task, completed=True)
            
            # RBAC Analysis
            if "rbac" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Analyzing RBAC configuration...", total=None)
                rbac_results = self.kubernetes_analyzer.analyze_rbac(manifest_path)
                self.results["kubernetes_analysis"]["rbac_analysis"] = rbac_results
                progress.update(task, completed=True)
            
            # Network Policy Analysis
            if "network_policies" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Analyzing network policies...", total=None)
                network_results = self.kubernetes_analyzer.analyze_network_policies(manifest_path)
                self.results["kubernetes_analysis"]["network_analysis"] = network_results
                progress.update(task, completed=True)
            
            # Secret Analysis
            if "secrets" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Scanning for secrets in manifests...", total=None)
                self.results["secret_analysis"] = self.secret_analyzer.scan_kubernetes_manifests(manifest_path)
                progress.update(task, completed=True)
            
            # Compliance Analysis
            if "compliance" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Checking Kubernetes compliance...", total=None)
                self.results["compliance_analysis"] = self.compliance_analyzer.check_kubernetes_compliance(manifest_path)
                progress.update(task, completed=True)
        
        # Generate vulnerability summary
        self._generate_vulnerability_summary()
        
        return self.results
    
    def scan_runtime_security(self, container_id: str = None, tests: List[str] = None) -> Dict[str, Any]:
        """Scan running containers for security issues."""
        self.console.print(f"[bold cyan]Scanning runtime security for container: {container_id or 'all'}[/bold cyan]")
        
        # Update scan info
        self.results["scan_info"] = {
            "target_type": "runtime_security",
            "container_id": container_id,
            "scan_date": datetime.now().isoformat(),
            "tests_performed": tests or ["processes", "network", "filesystem", "capabilities", "privileges"]
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Runtime Security Analysis
            task = progress.add_task("Analyzing runtime security...", total=None)
            self.results["runtime_analysis"] = self.runtime_analyzer.analyze_runtime(container_id)
            progress.update(task, completed=True)
        
        # Generate vulnerability summary
        self._generate_vulnerability_summary()
        
        return self.results
    
    def scan_registry(self, registry_url: str, tests: List[str] = None) -> Dict[str, Any]:
        """Scan container registry for security issues."""
        self.console.print(f"[bold cyan]Scanning container registry: {registry_url}[/bold cyan]")
        
        # Update scan info
        self.results["scan_info"] = {
            "target_type": "container_registry",
            "registry_url": registry_url,
            "scan_date": datetime.now().isoformat(),
            "tests_performed": tests or ["vulnerabilities", "secrets", "compliance", "policies"]
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Registry Analysis
            task = progress.add_task("Analyzing registry security...", total=None)
            registry_results = {
                "registry_url": registry_url,
                "images_scanned": 0,
                "vulnerabilities_found": 0,
                "secrets_found": 0,
                "compliance_issues": 0
            }
            
            # This would integrate with registry APIs
            # For now, we'll simulate the results
            self.results["registry_analysis"] = registry_results
            progress.update(task, completed=True)
        
        # Generate vulnerability summary
        self._generate_vulnerability_summary()
        
        return self.results
    
    def batch_scan(self, scan_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform batch scanning of multiple targets."""
        self.console.print(f"[bold cyan]Batch scanning {len(scan_list)} targets[/bold cyan]")
        
        batch_results = {
            "batch_info": {
                "total_targets": len(scan_list),
                "scan_date": datetime.now().isoformat(),
                "successful_scans": 0,
                "failed_scans": 0
            },
            "results": []
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            for i, scan_config in enumerate(scan_list):
                task = progress.add_task(f"Scanning target {i+1}/{len(scan_list)}...", total=None)
                
                try:
                    scan_type = scan_config.get("type", "docker_image")
                    
                    if scan_type == "docker_image":
                        result = self.scan_docker_image(
                            scan_config["target"],
                            scan_config.get("tests")
                        )
                    elif scan_type == "kubernetes_manifests":
                        result = self.scan_kubernetes_manifests(
                            scan_config["target"],
                            scan_config.get("tests")
                        )
                    elif scan_type == "runtime_security":
                        result = self.scan_runtime_security(
                            scan_config.get("target"),
                            scan_config.get("tests")
                        )
                    elif scan_type == "registry":
                        result = self.scan_registry(
                            scan_config["target"],
                            scan_config.get("tests")
                        )
                    elif scan_type == "debian_phase1":
                        result = self.scan_debian_image_phase1(
                            scan_config["target"]
                        )
                    elif scan_type == "debian_phase1_step2":
                        result = self.scan_debian_image_phase1_step2(
                            scan_config["target"]
                        )
                    else:
                        raise ValueError(f"Unknown scan type: {scan_type}")
                    
                    batch_results["results"].append({
                        "scan_config": scan_config,
                        "result": result
                    })
                    batch_results["batch_info"]["successful_scans"] += 1
                    
                except Exception as e:
                    self.console.print(f"[red]Error scanning {scan_config.get('target', 'unknown')}: {str(e)}[/red]")
                    batch_results["batch_info"]["failed_scans"] += 1
                
                progress.update(task, completed=True)
        
        return batch_results
    
    def _generate_vulnerability_summary(self):
        """Generate vulnerability summary from all analysis results."""
        vulnerabilities = []
        
        # Collect vulnerabilities from all analyzers
        for analysis_type, results in self.results.items():
            if analysis_type in ["docker_analysis", "kubernetes_analysis", "runtime_analysis", 
                               "vulnerability_analysis", "compliance_analysis", "secret_analysis"]:
                if "vulnerabilities" in results:
                    vulnerabilities.extend(results["vulnerabilities"])
        
        # Add SBOM-related vulnerabilities
        if "sbom_analysis" in self.results and self.results["sbom_analysis"]:
            sbom_vulns = self.results["sbom_analysis"].get("vulnerabilities", [])
            vulnerabilities.extend(sbom_vulns)
        
        # Add Debian analysis vulnerabilities
        if "debian_analysis" in self.results and self.results["debian_analysis"]:
            debian_vulns = self.results["debian_analysis"].get("vulnerabilities", [])
            vulnerabilities.extend(debian_vulns)
        
        # Add vulnerability matching vulnerabilities
        if "vulnerability_matching" in self.results and self.results["vulnerability_matching"]:
            matching_vulns = self.results["vulnerability_matching"].get("vulnerabilities", [])
            vulnerabilities.extend(matching_vulns)
        
        # Categorize vulnerabilities
        critical = [v for v in vulnerabilities if v.get("severity") == "critical"]
        high = [v for v in vulnerabilities if v.get("severity") == "high"]
        medium = [v for v in vulnerabilities if v.get("severity") == "medium"]
        low = [v for v in vulnerabilities if v.get("severity") == "low"]
        
        # Determine overall risk level
        if critical:
            overall_risk = "Critical"
        elif high:
            overall_risk = "High"
        elif medium:
            overall_risk = "Medium"
        elif low:
            overall_risk = "Low"
        else:
            overall_risk = "Secure"
        
        self.results["vulnerabilities"] = vulnerabilities
        self.results["summary"] = {
            "total_vulnerabilities": len(vulnerabilities),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "overall_risk": overall_risk
        }
    
    def generate_report(self, output_file: str = None, format: str = "json") -> str:
        """Generate security report."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"container_security_report_{timestamp}.{format}"
        
        self.console.print(f"[bold green]Generating {format.upper()} report: {output_file}[/bold green]")
        
        return self.report_generator.generate_report(
            self.results, 
            output_file, 
            format
        )
    
    def print_summary(self):
        """Print analysis summary."""
        summary = self.results.get("summary", {})
        
        # Create summary table
        table = Table(title="Container Security Analysis Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Total Vulnerabilities", str(summary.get("total_vulnerabilities", 0)))
        table.add_row("Critical", str(summary.get("critical", 0)))
        table.add_row("High", str(summary.get("high", 0)))
        table.add_row("Medium", str(summary.get("medium", 0)))
        table.add_row("Low", str(summary.get("low", 0)))
        table.add_row("Overall Risk", summary.get("overall_risk", "Unknown"))
        
        self.console.print(table)
        
        # Print scan info
        scan_info = self.results.get("scan_info", {})
        info_panel = Panel(
            f"Target Type: {scan_info.get('target_type', 'N/A')}\n"
            f"Target: {scan_info.get('target_name', scan_info.get('target_path', scan_info.get('registry_url', 'N/A')))}\n"
            f"Date: {scan_info.get('scan_date', 'N/A')}\n"
            f"Tests: {', '.join(scan_info.get('tests_performed', []))}",
            title="Scan Information",
            border_style="blue"
        )
        self.console.print(info_panel)
        
        # Print SBOM summary if available
        if "sbom_analysis" in self.results and self.results["sbom_analysis"]:
            sbom = self.results["sbom_analysis"].get("sbom", {})
            if sbom:
                sbom_panel = Panel(
                    f"OS Packages: {len(sbom.get('os_packages', []))}\n"
                    f"Language Packages: {len(sbom.get('language_packages', []))}\n"
                    f"Total Packages: {sbom.get('total_packages', 0)}\n"
                    f"Package Managers: {', '.join(sbom.get('package_managers_detected', []))}",
                    title="SBOM Summary",
                    border_style="green"
                )
                self.console.print(sbom_panel)
        
        # Print Debian analysis summary if available
        if "debian_analysis" in self.results and self.results["debian_analysis"]:
            debian_info = self.results["debian_analysis"].get("debian_info", {})
            if debian_info:
                debian_panel = Panel(
                    f"Distribution: {debian_info.get('distribution', 'N/A')}\n"
                    f"Version: {debian_info.get('version', 'N/A')}\n"
                    f"Codename: {debian_info.get('codename', 'N/A')}\n"
                    f"Package Count: {debian_info.get('package_count', 0)}\n"
                    f"Layers: {len(self.results['debian_analysis'].get('layers', []))}",
                    title="Debian Analysis Summary",
                    border_style="yellow"
                )
                self.console.print(debian_panel)

def main():
    """Main function for container security scanning."""
    parser = argparse.ArgumentParser(description="Container Security Scanner")
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--image", help="Docker image to scan")
    input_group.add_argument("--kubernetes", help="Kubernetes manifest file or directory to scan")
    input_group.add_argument("--runtime", help="Container ID for runtime security scan (or 'all' for all containers)")
    input_group.add_argument("--registry", help="Container registry URL to scan")
    input_group.add_argument("--batch", help="JSON file containing list of targets for batch scanning")
    input_group.add_argument("--debian-phase1", help="Debian image for Phase 1, Step 1 analysis")
    input_group.add_argument("--debian-phase1-step2", help="Debian image for Phase 1, Step 2 analysis")
    
    # Analysis options
    parser.add_argument("--tests", help="Comma-separated list of tests to run")
    parser.add_argument("--comprehensive", action="store_true", help="Run comprehensive analysis")
    
    # Output options
    parser.add_argument("--output", help="Output file for report")
    parser.add_argument("--format", choices=["json", "html", "pdf", "csv"], default="json", help="Report format")
    
    # Configuration
    parser.add_argument("--config", help="Configuration file")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Setup debug logging if requested
    if args.debug:
        setup_debug_logging()
        debug_print("Debug mode enabled.")
    
    # Initialize scanner
    scanner = ContainerSecurityScanner(config_file=args.config, debug=args.debug)
    
    try:
        debug_print("Parsed arguments:", args)
        
        # Determine tests to run
        if args.comprehensive:
            tests = ["sbom", "vulnerabilities", "secrets", "compliance", "configuration", "rbac", "network_policies"]
        elif args.tests:
            tests = args.tests.split(",")
        else:
            tests = None
        
        debug_print("Tests to run:", tests)
        
        # Run scanning
        if args.debian_phase1:
            debug_print("Starting Debian Phase 1, Step 1 analysis for:", args.debian_phase1)
            results = scanner.scan_debian_image_phase1(args.debian_phase1)
        elif args.debian_phase1_step2:
            debug_print("Starting Debian Phase 1, Step 2 analysis for:", args.debian_phase1_step2)
            results = scanner.scan_debian_image_phase1_step2(args.debian_phase1_step2)
        elif args.image:
            debug_print("Starting Docker image scan for:", args.image)
            results = scanner.scan_docker_image(args.image, tests)
        elif args.kubernetes:
            debug_print("Starting Kubernetes manifest scan for:", args.kubernetes)
            results = scanner.scan_kubernetes_manifests(args.kubernetes, tests)
        elif args.runtime:
            debug_print("Starting runtime security scan for:", args.runtime)
            results = scanner.scan_runtime_security(args.runtime, tests)
        elif args.registry:
            debug_print("Starting registry scan for:", args.registry)
            results = scanner.scan_registry(args.registry, tests)
        elif args.batch:
            debug_print("Starting batch scan with file:", args.batch)
            with open(args.batch, 'r') as f:
                scan_list = json.load(f)
            results = scanner.batch_scan(scan_list)
        
        # Print summary
        if args.verbose:
            scanner.print_summary()
        
        # Generate report
        report_file = scanner.generate_report(args.output, args.format)
        if args.verbose:
            print(f"\n✅ Container security scan completed successfully!")
            print(f"📄 Report saved: {report_file}")
        
        debug_print("Scan complete. Report file:", report_file)
        
    except Exception as e:
        print(f"❌ Error during container security scan: {str(e)}")
        debug_print("Exception occurred:", str(e))
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 