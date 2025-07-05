#!/usr/bin/env python3
"""
Comprehensive Threat Modeling Tool
Supports STRIDE, PASTA, and DREAD methodologies for application security analysis.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .debug_utils import setup_debug_logging, debug_print, debug_log
from .model_parser import ArchitectureParser
from .threat_engine import ThreatEngine
from .report_generator import ReportGenerator
from .ai_assisted_threat_discovery import AIAssistedThreatDiscovery

console = Console()

class ThreatModeler:
    """Main threat modeling application."""
    
    def __init__(self, debug: bool = False):
        """Initialize the threat modeler."""
        setup_debug_logging(debug)
        self.parser = ArchitectureParser()
        self.engine = ThreatEngine()
        self.report_gen = ReportGenerator()
        self.ai_discovery = AIAssistedThreatDiscovery(debug=debug)
        debug_log("main", "Threat modeler initialized")
    
    def run_interactive(self) -> None:
        """Run interactive threat modeling session."""
        console.print(Panel.fit(
            "[bold blue]Threat Modeling Tool - Interactive Mode[/bold blue]\n"
            "This will guide you through creating a threat model for your application.",
            border_style="blue"
        ))
        
        # Get architecture information
        architecture = self._get_architecture_interactive()
        
        # Select methodology
        methodology = self._select_methodology()
        
        # Ask about AI capabilities
        use_ai = self._ask_about_ai_capabilities()
        
        # Run threat analysis
        if use_ai:
            threats = self._analyze_threats_with_ai(architecture, methodology)
        else:
            threats = self._analyze_threats(architecture, methodology)
        
        # Generate report
        self._generate_report(threats, architecture, methodology)
    
    def run_file_input(self, input_file: str, methodology: str = "STRIDE", use_ai: bool = False) -> None:
        """Run threat modeling with file input."""
        console.print(Panel.fit(
            f"[bold blue]Threat Modeling Tool - File Input Mode[/bold blue]\n"
            f"Input file: {input_file}\n"
            f"Methodology: {methodology}\n"
            f"AI Analysis: {'Enabled' if use_ai else 'Disabled'}",
            border_style="blue"
        ))
        
        # Parse architecture from file
        architecture = self._parse_architecture_file(input_file)
        
        # Run threat analysis
        if use_ai:
            threats = self._analyze_threats_with_ai(architecture, methodology)
        else:
            threats = self._analyze_threats(architecture, methodology)
        
        # Generate report
        self._generate_report(threats, architecture, methodology)
    
    def _ask_about_ai_capabilities(self) -> bool:
        """Ask user about using AI capabilities."""
        console.print("\n[bold]AI-Assisted Threat Discovery[/bold]")
        console.print("The tool can use AI to enhance threat discovery with:")
        console.print("• CVE database analysis using transformer models")
        console.print("• Architecture pattern recognition")
        console.print("• Natural language processing of design documents")
        console.print("• Predictive threat modeling")
        
        return click.confirm("Enable AI-assisted threat discovery?")
    
    def _analyze_threats_with_ai(self, architecture: Dict, methodology: str) -> List[Dict]:
        """Analyze threats using both traditional and AI methods."""
        debug_log("main", "Running AI-assisted threat analysis")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            # Traditional analysis
            task1 = progress.add_task("Running traditional threat analysis...", total=None)
            traditional_threats = self.engine.analyze_threats(architecture, methodology)
            progress.update(task1, completed=True)
            
            # AI analysis
            task2 = progress.add_task("Running AI-assisted analysis...", total=None)
            ai_results = self.ai_discovery.comprehensive_threat_analysis(
                architecture=architecture,
                enable_cve_analysis=True,
                enable_pattern_recognition=True,
                enable_nlp_analysis=False,  # No design document in interactive mode
                enable_predictive_modeling=True
            )
            progress.update(task2, completed=True)
        
        # Combine traditional and AI threats
        combined_threats = self._combine_traditional_and_ai_threats(traditional_threats, ai_results)
        
        debug_log("main", f"AI-assisted analysis completed. Found {len(combined_threats)} total threats")
        return combined_threats
    
    def _combine_traditional_and_ai_threats(self, traditional_threats: List[Dict], 
                                          ai_results: Dict) -> List[Dict]:
        """Combine traditional and AI-identified threats."""
        combined = traditional_threats.copy()
        
        # Add AI-identified threats
        ai_threats = ai_results.get("combined_threats", [])
        for ai_threat in ai_threats:
            # Check if threat already exists
            existing = False
            for trad_threat in combined:
                if (ai_threat["title"].lower() in trad_threat.get("title", "").lower() or
                    trad_threat.get("title", "").lower() in ai_threat["title"].lower()):
                    # Update existing threat with AI insights
                    trad_threat["ai_enhanced"] = True
                    trad_threat["ai_confidence"] = ai_threat.get("confidence", 0.0)
                    trad_threat["ai_sources"] = ai_threat.get("sources", [])
                    existing = True
                    break
            
            if not existing:
                # Add new AI-identified threat
                combined.append({
                    "title": ai_threat["title"],
                    "category": "AI-Identified",
                    "description": ai_threat["description"],
                    "severity": ai_threat["severity"],
                    "risk_score": ai_threat["risk_score"],
                    "methodology": "AI-Assisted",
                    "ai_enhanced": True,
                    "ai_confidence": ai_threat.get("confidence", 0.0),
                    "ai_sources": ai_threat.get("sources", []),
                    "mitigations": ai_threat.get("mitigations", [])
                })
        
        # Sort by risk score
        combined.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        
        return combined
    
    def _get_architecture_interactive(self) -> Dict:
        """Get architecture information interactively."""
        debug_log("interactive", "Starting interactive architecture input")
        
        architecture = {
            "name": "",
            "description": "",
            "components": [],
            "data_flows": [],
            "trust_boundaries": [],
            "assets": []
        }
        
        # Basic information
        architecture["name"] = click.prompt("Application name", type=str)
        architecture["description"] = click.prompt("Application description", type=str)
        
        # Components
        console.print("\n[bold]Components[/bold]")
        while click.confirm("Add a component?"):
            component = {
                "name": click.prompt("Component name"),
                "type": click.prompt("Component type", 
                                   type=click.Choice(["web_server", "database", "api", "client", "gateway", "service", "other"])),
                "description": click.prompt("Component description"),
                "technologies": click.prompt("Technologies used (comma-separated)").split(","),
                "external": click.confirm("Is this an external component?")
            }
            architecture["components"].append(component)
        
        # Data flows
        console.print("\n[bold]Data Flows[/bold]")
        while click.confirm("Add a data flow?"):
            flow = {
                "from": click.prompt("From component"),
                "to": click.prompt("To component"),
                "data_type": click.prompt("Data type", 
                                        type=click.Choice(["user_data", "auth_data", "config_data", "log_data", "other"])),
                "protocol": click.prompt("Protocol (HTTP, HTTPS, TCP, etc.)"),
                "encrypted": click.confirm("Is data encrypted in transit?")
            }
            architecture["data_flows"].append(flow)
        
        # Trust boundaries
        console.print("\n[bold]Trust Boundaries[/bold]")
        while click.confirm("Add a trust boundary?"):
            boundary = {
                "name": click.prompt("Boundary name"),
                "components": click.prompt("Components in boundary (comma-separated)").split(","),
                "description": click.prompt("Boundary description")
            }
            architecture["trust_boundaries"].append(boundary)
        
        # Assets
        console.print("\n[bold]Assets[/bold]")
        while click.confirm("Add an asset?"):
            asset = {
                "name": click.prompt("Asset name"),
                "type": click.prompt("Asset type", 
                                   type=click.Choice(["data", "service", "infrastructure", "user", "other"])),
                "value": click.prompt("Asset value", 
                                    type=click.Choice(["low", "medium", "high", "critical"])),
                "description": click.prompt("Asset description")
            }
            architecture["assets"].append(asset)
        
        debug_log("interactive", "Architecture input completed", architecture)
        return architecture
    
    def _select_methodology(self) -> str:
        """Select threat modeling methodology."""
        console.print("\n[bold]Select Threat Modeling Methodology[/bold]")
        
        methodologies = {
            "1": "STRIDE",
            "2": "PASTA", 
            "3": "DREAD"
        }
        
        for key, value in methodologies.items():
            console.print(f"{key}. {value}")
        
        choice = click.prompt("Select methodology", type=click.Choice(["1", "2", "3"]))
        methodology = methodologies[choice]
        
        debug_log("interactive", f"Selected methodology: {methodology}")
        return methodology
    
    def _parse_architecture_file(self, file_path: str) -> Dict:
        """Parse architecture from file."""
        debug_log("file_input", f"Parsing architecture from: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                if file_path.endswith('.json'):
                    architecture = json.load(f)
                elif file_path.endswith('.yaml') or file_path.endswith('.yml'):
                    import yaml
                    architecture = yaml.safe_load(f)
                else:
                    # Assume text format
                    architecture = self.parser.parse_text_architecture(f.read())
            
            debug_log("file_input", "Architecture parsed successfully", architecture)
            return architecture
            
        except Exception as e:
            console.print(f"[red]Error parsing architecture file: {e}[/red]")
            debug_log("file_input", f"Error parsing file: {e}", "ERROR")
            sys.exit(1)
    
    def _analyze_threats(self, architecture: Dict, methodology: str) -> List[Dict]:
        """Analyze threats using selected methodology."""
        debug_log("analysis", f"Starting threat analysis with {methodology}")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing threats...", total=None)
            
            threats = self.engine.analyze_threats(architecture, methodology)
            
            progress.update(task, completed=True)
        
        debug_log("analysis", f"Threat analysis completed. Found {len(threats)} threats")
        return threats
    
    def _generate_report(self, threats: List[Dict], architecture: Dict, methodology: str) -> None:
        """Generate threat modeling report."""
        debug_log("report", "Generating threat modeling report")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Generating report...", total=None)
            
            report = self.report_gen.generate_report(threats, architecture, methodology)
            
            progress.update(task, completed=True)
        
        # Display summary
        self._display_summary(threats, architecture, methodology)
        
        debug_log("report", "Report generation completed")
    
    def _display_summary(self, threats: List[Dict], architecture: Dict, methodology: str) -> None:
        """Display threat analysis summary."""
        console.print("\n[bold green]Threat Analysis Summary[/bold green]")
        
        # Summary table
        table = Table(title="Threat Analysis Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Application", architecture.get("name", "Unknown"))
        table.add_row("Methodology", methodology)
        table.add_row("Total Threats", str(len(threats)))
        
        # Count AI-enhanced threats
        ai_enhanced = sum(1 for t in threats if t.get("ai_enhanced", False))
        if ai_enhanced > 0:
            table.add_row("AI-Enhanced Threats", str(ai_enhanced))
        
        # Count by severity
        severity_counts = {}
        for threat in threats:
            severity = threat.get("severity", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in severity_counts.items():
            table.add_row(f"Threats ({severity})", str(count))
        
        console.print(table)
        
        # Top threats
        if threats:
            console.print("\n[bold]Top Threats by Risk Score[/bold]")
            top_threats = sorted(threats, key=lambda x: x.get("risk_score", 0), reverse=True)[:5]
            
            threat_table = Table()
            threat_table.add_column("Threat", style="cyan")
            threat_table.add_column("Category", style="yellow")
            threat_table.add_column("Risk Score", style="red")
            threat_table.add_column("AI Enhanced", style="green")
            
            for threat in top_threats:
                ai_marker = "✓" if threat.get("ai_enhanced", False) else ""
                threat_table.add_row(
                    threat.get("title", "Unknown"),
                    threat.get("category", "Unknown"),
                    str(threat.get("risk_score", 0)),
                    ai_marker
                )
            
            console.print(threat_table)

@click.command()
@click.option('--input-file', '-i', help='Input architecture file (JSON, YAML, or text)')
@click.option('--methodology', '-m', 
              type=click.Choice(['STRIDE', 'PASTA', 'DREAD']), 
              default='STRIDE',
              help='Threat modeling methodology')
@click.option('--output-format', '-o',
              type=click.Choice(['markdown', 'html', 'pdf']),
              default='markdown',
              help='Output report format')
@click.option('--output-file', '-f', help='Output file path')
@click.option('--ai', is_flag=True, help='Enable AI-assisted threat discovery')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def main(input_file: Optional[str], methodology: str, output_format: str, 
         output_file: Optional[str], ai: bool, debug: bool) -> None:
    """Comprehensive Threat Modeling Tool for Application Security Analysis."""
    
    try:
        modeler = ThreatModeler(debug=debug)
        
        if input_file:
            modeler.run_file_input(input_file, methodology, ai)
        else:
            modeler.run_interactive()
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Threat modeling interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        debug_print(f"Unexpected error: {e}", level="ERROR")
        sys.exit(1)

if __name__ == "__main__":
    main() 