#!/usr/bin/env python3
"""
Mobile Security Testing Tool
A comprehensive automated mobile client-side security testing tool similar to Drozer and MobSF.
"""

import argparse
import json
import os
import sys
import logging
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import requests
import subprocess
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from prompt_toolkit import prompt
from prompt_toolkit.shortcuts import confirm

# Import our modules
from analyzers.static_analyzer import StaticAnalyzer
from analyzers.dynamic_analyzer import DynamicAnalyzer
from analyzers.network_analyzer import NetworkAnalyzer
from analyzers.storage_analyzer import StorageAnalyzer
from analyzers.code_analyzer import CodeAnalyzer
from reporters.report_generator import ReportGenerator
from utils.file_utils import FileUtils
from utils.config_manager import ConfigManager
from utils.debug_utils import setup_debug_logging, debug_print
from ai.vulnerability_detector import AIVulnerabilityDetector

class MobileSecurityTester:
    """Main class for mobile security testing."""
    
    def __init__(self, config_file: str = None, debug: bool = False):
        """Initialize the mobile security tester."""
        self.console = Console()
        self.debug = debug
        
        # Use default config if none specified
        if config_file is None:
            config_file = "config/default_config.json"
        
        self.config = ConfigManager(config_file)
        self.results = {
            "scan_info": {},
            "static_analysis": {},
            "dynamic_analysis": {},
            "network_analysis": {},
            "storage_analysis": {},
            "code_analysis": {},
            "vulnerabilities": [],
            "summary": {}
        }
        
        # Initialize analyzers
        self.static_analyzer = StaticAnalyzer(debug=debug)
        self.dynamic_analyzer = DynamicAnalyzer(debug=debug)
        self.network_analyzer = NetworkAnalyzer(debug=debug)
        self.storage_analyzer = StorageAnalyzer(debug=debug)
        self.code_analyzer = CodeAnalyzer(debug=debug, config=self.config.config)
        self.report_generator = ReportGenerator(debug=debug)
        self.ai_vuln_detector = AIVulnerabilityDetector()
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup logging configuration."""
        if self.debug:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.StreamHandler(sys.stdout),
                    logging.FileHandler('mobile_security_debug.log')
                ]
            )
        else:
            logging.basicConfig(level=logging.INFO)
    
    def analyze_apk(self, apk_path: str, tests: List[str] = None) -> Dict[str, Any]:
        """Analyze Android APK file."""
        self.console.print(f"[bold cyan]Analyzing APK: {apk_path}[/bold cyan]")
        
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        
        # Update scan info
        self.results["scan_info"] = {
            "file_path": apk_path,
            "file_type": "APK",
            "scan_date": datetime.now().isoformat(),
            "tests_performed": tests or ["static", "dynamic", "network", "storage", "code"]
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Static Analysis
            if "static" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing static analysis...", total=None)
                self.results["static_analysis"] = self.static_analyzer.analyze_apk(apk_path)
                progress.update(task, completed=True)
            
            # Code Analysis
            if "code" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing code analysis (APKTool decompilation + security scanning)...", total=None)
                self.console.print("[yellow]Note: Code analysis includes APKTool decompilation which may take several minutes for large APKs[/yellow]")
                self.results["code_analysis"] = self.code_analyzer.analyze_apk(apk_path)
                progress.update(task, completed=True)
            
            # Storage Analysis
            if "storage" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing storage analysis...", total=None)
                self.results["storage_analysis"] = self.storage_analyzer.analyze_apk(apk_path)
                progress.update(task, completed=True)
            
            # Network Analysis
            if "network" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing network analysis...", total=None)
                self.results["network_analysis"] = self.network_analyzer.analyze_apk(apk_path)
                progress.update(task, completed=True)
            
            # Dynamic Analysis (if device connected)
            if "dynamic" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing dynamic analysis...", total=None)
                self.results["dynamic_analysis"] = self.dynamic_analyzer.analyze_apk(apk_path)
                progress.update(task, completed=True)
        
        # Generate vulnerability summary
        self.console.print("[green]Generating vulnerability summary...[/green]")
        self._generate_vulnerability_summary()
        
        # AI-powered vulnerability detection
        self.console.print("[green]Running AI-powered vulnerability detection...[/green]")
        ai_vulns = self.ai_vuln_detector.analyze(self.results)
        if ai_vulns:
            self.results.setdefault('vulnerabilities', []).extend(ai_vulns)
        
        self.console.print("[bold green]✅ APK analysis completed successfully![/bold green]")
        return self.results
    
    def analyze_ipa(self, ipa_path: str, tests: List[str] = None) -> Dict[str, Any]:
        """Analyze iOS IPA file."""
        self.console.print(f"[bold cyan]Analyzing IPA: {ipa_path}[/bold cyan]")
        
        if not os.path.exists(ipa_path):
            raise FileNotFoundError(f"IPA file not found: {ipa_path}")
        
        # Update scan info
        self.results["scan_info"] = {
            "file_path": ipa_path,
            "file_type": "IPA",
            "scan_date": datetime.now().isoformat(),
            "tests_performed": tests or ["static", "code", "storage", "network"]
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Static Analysis
            if "static" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing static analysis...", total=None)
                self.results["static_analysis"] = self.static_analyzer.analyze_ipa(ipa_path)
                progress.update(task, completed=True)
            
            # Code Analysis
            if "code" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing code analysis...", total=None)
                self.results["code_analysis"] = self.code_analyzer.analyze_ipa(ipa_path)
                progress.update(task, completed=True)
            
            # Storage Analysis
            if "storage" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing storage analysis...", total=None)
                self.results["storage_analysis"] = self.storage_analyzer.analyze_ipa(ipa_path)
                progress.update(task, completed=True)
            
            # Network Analysis
            if "network" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing network analysis...", total=None)
                self.results["network_analysis"] = self.network_analyzer.analyze_ipa(ipa_path)
                progress.update(task, completed=True)
        
        # Generate vulnerability summary
        self.console.print("[green]Generating vulnerability summary...[/green]")
        self._generate_vulnerability_summary()
        
        # AI-powered vulnerability detection
        self.console.print("[green]Running AI-powered vulnerability detection...[/green]")
        ai_vulns = self.ai_vuln_detector.analyze(self.results)
        if ai_vulns:
            self.results.setdefault('vulnerabilities', []).extend(ai_vulns)
        
        self.console.print("[bold green]✅ IPA analysis completed successfully![/bold green]")
        return self.results
    
    def analyze_device(self, device_type: str, package_name: str = None) -> Dict[str, Any]:
        """Analyze live device."""
        self.console.print(f"[bold cyan]Analyzing {device_type} device[/bold cyan]")
        
        self.results["scan_info"] = {
            "device_type": device_type,
            "package_name": package_name,
            "scan_date": datetime.now().isoformat(),
            "tests_performed": ["dynamic", "network", "storage"]
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Dynamic Analysis
            task = progress.add_task("Performing dynamic analysis...", total=None)
            self.results["dynamic_analysis"] = self.dynamic_analyzer.analyze_device(device_type, package_name)
            progress.update(task, completed=True)
            
            # Network Analysis
            task = progress.add_task("Performing network analysis...", total=None)
            self.results["network_analysis"] = self.network_analyzer.analyze_device(device_type, package_name)
            progress.update(task, completed=True)
            
            # Storage Analysis
            task = progress.add_task("Performing storage analysis...", total=None)
            self.results["storage_analysis"] = self.storage_analyzer.analyze_device(device_type, package_name)
            progress.update(task, completed=True)
        
        # Generate vulnerability summary
        self._generate_vulnerability_summary()
        
        return self.results
    
    def batch_analyze(self, directory: str, file_type: str = "apk") -> Dict[str, Any]:
        """Analyze multiple files in batch."""
        self.console.print(f"[bold cyan]Batch analyzing {file_type} files in: {directory}[/bold cyan]")
        
        if not os.path.exists(directory):
            raise FileNotFoundError(f"Directory not found: {directory}")
        
        batch_results = {
            "batch_info": {
                "directory": directory,
                "file_type": file_type,
                "scan_date": datetime.now().isoformat(),
                "total_files": 0,
                "successful_scans": 0,
                "failed_scans": 0
            },
            "results": []
        }
        
        # Find all files of specified type
        file_extension = ".apk" if file_type.lower() == "apk" else ".ipa"
        files = list(Path(directory).glob(f"*{file_extension}"))
        
        batch_results["batch_info"]["total_files"] = len(files)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            for i, file_path in enumerate(files):
                task = progress.add_task(f"Analyzing {file_path.name}...", total=None)
                
                try:
                    if file_type.lower() == "apk":
                        result = self.analyze_apk(str(file_path))
                    else:
                        result = self.analyze_ipa(str(file_path))
                    
                    batch_results["results"].append({
                        "file": str(file_path),
                        "result": result
                    })
                    batch_results["batch_info"]["successful_scans"] += 1
                    
                except Exception as e:
                    self.console.print(f"[red]Error analyzing {file_path}: {str(e)}[/red]")
                    batch_results["batch_info"]["failed_scans"] += 1
                
                progress.update(task, completed=True)
        
        return batch_results
    
    def _generate_vulnerability_summary(self):
        """Generate vulnerability summary from all analysis results."""
        vulnerabilities = []
        
        # Collect vulnerabilities from all analyzers
        for analysis_type, results in self.results.items():
            if analysis_type in ["static_analysis", "dynamic_analysis", "network_analysis", 
                               "storage_analysis", "code_analysis"]:
                if "vulnerabilities" in results:
                    vulnerabilities.extend(results["vulnerabilities"])
        
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
    
    def generate_report(self, output_file: str = None, format: str = "html") -> str:
        """Generate security report."""
        if output_file is None:
            # Create default reports directory structure
            reports_dir = Path("reports/cli")
            reports_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate timestamp-based filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"mobile_security_report_{timestamp}.{format}"
            output_file = str(reports_dir / filename)
        else:
            # If output_file is provided but doesn't have a directory, put it in reports/cli
            output_path = Path(output_file)
            if not output_path.parent.name:
                reports_dir = Path("reports/cli")
                reports_dir.mkdir(parents=True, exist_ok=True)
                output_file = str(reports_dir / output_path.name)
        
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
        table = Table(title="Mobile Security Analysis Summary")
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
            f"File: {scan_info.get('file_path', 'N/A')}\n"
            f"Type: {scan_info.get('file_type', 'N/A')}\n"
            f"Date: {scan_info.get('scan_date', 'N/A')}\n"
            f"Tests: {', '.join(scan_info.get('tests_performed', []))}",
            title="Scan Information",
            border_style="blue"
        )
        self.console.print(info_panel)

def main():
    """Main function for mobile security testing."""
    parser = argparse.ArgumentParser(description="Mobile Security Testing Tool")
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--apk", help="APK file to analyze")
    input_group.add_argument("--ipa", help="IPA file to analyze")
    input_group.add_argument("--device", choices=["android", "ios"], help="Analyze live device")
    input_group.add_argument("--batch", help="Directory containing APK/IPA files for batch analysis")
    input_group.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    
    # Analysis options
    parser.add_argument("--tests", help="Comma-separated list of tests to run (static,dynamic,network,storage,code,ai)")
    parser.add_argument("--package", help="Package name for device analysis")
    parser.add_argument("--comprehensive", action="store_true", help="Run comprehensive analysis")
    parser.add_argument("--quick", action="store_true", help="Run quick analysis (static + network only)")
    parser.add_argument("--deep", action="store_true", help="Run deep analysis (includes AI-powered detection)")
    
    # Scan profiles
    parser.add_argument("--profile", choices=["basic", "standard", "comprehensive", "compliance", "penetration"], 
                       help="Predefined scan profile")
    
    # Output options
    parser.add_argument("--output", help="Output file for report")
    parser.add_argument("--format", choices=["json", "html", "pdf", "csv", "xml", "markdown", "dashboard"], 
                       default="html", help="Report format")
    parser.add_argument("--no-report", action="store_true", help="Skip report generation")
    
    # Configuration
    parser.add_argument("--config", help="Configuration file")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")
    
    args = parser.parse_args()
    
    # Setup debug logging if requested
    if args.debug:
        setup_debug_logging()
        debug_print("Debug mode enabled.")
    
    # Initialize tester
    tester = MobileSecurityTester(config_file=args.config, debug=args.debug)
    
    try:
        debug_print("Parsed arguments:", args)
        
        # Handle interactive mode
        if args.interactive:
            run_interactive_mode(tester)
            return
        
        # Determine tests to run based on profile or arguments
        tests = determine_tests_to_run(args)
        debug_print("Tests to run:", tests)
        
        # Run analysis
        if args.apk:
            debug_print("Starting APK analysis for:", args.apk)
            results = tester.analyze_apk(args.apk, tests)
        elif args.ipa:
            debug_print("Starting IPA analysis for:", args.ipa)
            results = tester.analyze_ipa(args.ipa, tests)
        elif args.device:
            debug_print(f"Starting device analysis for {args.device}, package={args.package}")
            results = tester.analyze_device(args.device, args.package)
        elif args.batch:
            # Determine file type from directory contents
            apk_files = list(Path(args.batch).glob("*.apk"))
            ipa_files = list(Path(args.batch).glob("*.ipa"))
            debug_print(f"Batch analysis: {len(apk_files)} APKs, {len(ipa_files)} IPAs found.")
            if apk_files and not ipa_files:
                file_type = "apk"
            elif ipa_files and not apk_files:
                file_type = "ipa"
            else:
                file_type = "apk"  # Default to APK
            debug_print(f"Batch analysis file type: {file_type}")
            results = tester.batch_analyze(args.batch, file_type)
        
        # Print summary
        if not args.quiet:
            if args.verbose:
                tester.print_summary()
            else:
                print_quick_summary(results)
        
        # Generate report
        if not args.no_report:
            report_file = tester.generate_report(args.output, args.format)
            if not args.quiet:
                print(f"\n✅ Analysis completed successfully!")
                print(f"📄 Report saved: {report_file}")
            debug_print("Analysis complete. Report file:", report_file)
        else:
            if not args.quiet:
                print(f"\n✅ Analysis completed successfully!")
                
    except Exception as e:
        print(f"❌ Error during analysis: {str(e)}")
        debug_print("Exception occurred:", str(e))
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

def determine_tests_to_run(args) -> List[str]:
    """Determine which tests to run based on arguments and profiles."""
    if args.profile:
        return get_profile_tests(args.profile)
    elif args.comprehensive:
        return ["static", "dynamic", "network", "storage", "code", "ai"]
    elif args.quick:
        return ["static", "network"]
    elif args.deep:
        return ["static", "dynamic", "network", "storage", "code", "ai"]
    elif args.tests:
        return args.tests.split(",")
    else:
        return ["static", "network", "storage", "code"]

def get_profile_tests(profile: str) -> List[str]:
    """Get test list for predefined scan profiles."""
    profiles = {
        "basic": ["static", "network"],
        "standard": ["static", "network", "storage", "code"],
        "comprehensive": ["static", "dynamic", "network", "storage", "code"],
        "compliance": ["static", "network", "storage", "code", "ai"],
        "penetration": ["static", "dynamic", "network", "storage", "code", "ai"]
    }
    return profiles.get(profile, ["static", "network", "storage", "code"])

def run_interactive_mode(tester):
    """Run the tool in interactive mode."""
    console = Console()
    console.print("[bold green]Welcome to the Interactive Mobile Security Testing CLI![/bold green]")
    console.print("[cyan]Let's get started with your mobile app security analysis.[/cyan]\n")

    # Step 1: Select input type
    input_types = ["APK/IPA File", "Live Device", "Batch Directory"]
    console.print("Select input type:")
    for i, input_type in enumerate(input_types, 1):
        console.print(f"{i}. {input_type}")
    
    choice = prompt("Enter your choice", choices=["1", "2", "3"], default="1")
    
    if choice == "1":
        # File analysis
        while True:
            file_path = prompt("Enter the path to your APK or IPA file")
            if os.path.exists(file_path) and file_path.lower().endswith((".apk", ".ipa")):
                break
            console.print("[red]Invalid file. Please enter a valid APK or IPA file path.[/red]")
        
        # Choose scan profile
        profiles = ["basic", "standard", "comprehensive", "compliance", "penetration"]
        console.print("\nSelect scan profile:")
        for i, profile in enumerate(profiles, 1):
            console.print(f"{i}. {profile.capitalize()}")
        
        profile_choice = prompt("Enter your choice", choices=["1", "2", "3", "4", "5"], default="2")
        selected_profile = profiles[int(profile_choice) - 1]
        tests = get_profile_tests(selected_profile)
        
        # Run analysis
        ext = Path(file_path).suffix.lower()
        console.print(f"\n[bold]Running {selected_profile} analysis on:[/bold] {file_path}")
        if ext == ".apk":
            results = tester.analyze_apk(file_path, tests=tests)
        else:
            results = tester.analyze_ipa(file_path, tests=tests)
            
    elif choice == "2":
        # Device analysis
        device_type = prompt("Select device type", choices=["android", "ios"], default="android")
        package_name = prompt("Enter package name (optional)")
        results = tester.analyze_device(device_type, package_name)
        
    else:
        # Batch analysis
        while True:
            directory = prompt("Enter directory path containing APK/IPA files")
            if os.path.exists(directory) and os.path.isdir(directory):
                break
            console.print("[red]Invalid directory. Please enter a valid path.[/red]")
        
        # Determine file type
        apk_files = list(Path(directory).glob("*.apk"))
        ipa_files = list(Path(directory).glob("*.ipa"))
        
        if apk_files and ipa_files:
            file_type = prompt("Select file type", choices=["apk", "ipa"], default="apk")
        elif apk_files:
            file_type = "apk"
        elif ipa_files:
            file_type = "ipa"
        else:
            console.print("[red]No APK or IPA files found in directory.[/red]")
            return
        
        results = tester.batch_analyze(directory, file_type)

    # Show results
    console.print("\n[bold green]Analysis Complete![/bold green]")
    print_quick_summary(results)
    
    # Show AI predictions if available
    ai_vulns = [v for v in results.get("vulnerabilities", []) if v.get("type", "").startswith("AI-Predicted")]
    if ai_vulns:
        console.print("\n[bold magenta]AI-Predicted Vulnerabilities:[/bold magenta]")
        for vuln in ai_vulns[:5]:  # Show top 5
            console.print(f"- [red]{vuln['type']}[/red]: {vuln['description']}")

    # Generate report
    if confirm("Do you want to save the report?", default=True):
        formats = ["html", "json", "pdf", "csv", "xml", "markdown", "dashboard"]
        console.print("\nSelect report format:")
        for i, fmt in enumerate(formats, 1):
            console.print(f"{i}. {fmt.upper()}")
        
        format_choice = prompt("Enter your choice", choices=[str(i) for i in range(1, len(formats) + 1)], default="1")
        selected_format = formats[int(format_choice) - 1]
        
        out_path = prompt("Enter output file name (optional)", default="")
        report_file = tester.generate_report(out_path, selected_format)
        console.print(f"[green]Report saved to {report_file}[/green]")

    console.print("\n[bold green]Thank you for using the Interactive CLI![/bold green]")

def print_quick_summary(results):
    """Print a quick summary of results."""
    summary = results.get("summary", {})
    scan_info = results.get("scan_info", {})
    
    print(f"\n📊 Security Analysis Summary")
    print(f"   File: {scan_info.get('file_path', 'N/A')}")
    print(f"   Type: {scan_info.get('file_type', 'N/A')}")
    print(f"   Overall Risk: {summary.get('overall_risk', 'Unknown')}")
    print(f"   Total Issues: {summary.get('total_vulnerabilities', 0)}")
    print(f"   Critical: {summary.get('critical', 0)} | High: {summary.get('high', 0)} | Medium: {summary.get('medium', 0)} | Low: {summary.get('low', 0)}") 