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

# Import our modules
from .analyzers.static_analyzer import StaticAnalyzer
from .analyzers.dynamic_analyzer import DynamicAnalyzer
from .analyzers.network_analyzer import NetworkAnalyzer
from .analyzers.storage_analyzer import StorageAnalyzer
from .analyzers.code_analyzer import CodeAnalyzer
from .reporters.report_generator import ReportGenerator
from .utils.file_utils import FileUtils
from .utils.config_manager import ConfigManager

class MobileSecurityTester:
    """Main class for mobile security testing."""
    
    def __init__(self, config_file: str = None, debug: bool = False):
        """Initialize the mobile security tester."""
        self.console = Console()
        self.debug = debug
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
        self.code_analyzer = CodeAnalyzer(debug=debug)
        self.report_generator = ReportGenerator(debug=debug)
        
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
                task = progress.add_task("Performing code analysis...", total=None)
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
        self._generate_vulnerability_summary()
        
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
        self._generate_vulnerability_summary()
        
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
    
    def generate_report(self, output_file: str = None, format: str = "json") -> str:
        """Generate security report."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"mobile_security_report_{timestamp}.{format}"
        
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
    
    # Analysis options
    parser.add_argument("--tests", help="Comma-separated list of tests to run (static,dynamic,network,storage,code)")
    parser.add_argument("--package", help="Package name for device analysis")
    parser.add_argument("--comprehensive", action="store_true", help="Run comprehensive analysis")
    
    # Output options
    parser.add_argument("--output", help="Output file for report")
    parser.add_argument("--format", choices=["json", "html", "pdf", "csv"], default="json", help="Report format")
    
    # Configuration
    parser.add_argument("--config", help="Configuration file")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Initialize tester
    tester = MobileSecurityTester(config_file=args.config, debug=args.debug)
    
    try:
        # Determine tests to run
        if args.comprehensive:
            tests = ["static", "dynamic", "network", "storage", "code"]
        elif args.tests:
            tests = args.tests.split(",")
        else:
            tests = ["static", "network", "storage", "code"]
        
        # Run analysis
        if args.apk:
            results = tester.analyze_apk(args.apk, tests)
        elif args.ipa:
            results = tester.analyze_ipa(args.ipa, tests)
        elif args.device:
            results = tester.analyze_device(args.device, args.package)
        elif args.batch:
            # Determine file type from directory contents
            apk_files = list(Path(args.batch).glob("*.apk"))
            ipa_files = list(Path(args.batch).glob("*.ipa"))
            
            if apk_files and not ipa_files:
                file_type = "apk"
            elif ipa_files and not apk_files:
                file_type = "ipa"
            else:
                file_type = "apk"  # Default to APK
            
            results = tester.batch_analyze(args.batch, file_type)
        
        # Print summary
        if args.verbose:
            tester.print_summary()
        
        # Generate report
        report_file = tester.generate_report(args.output, args.format)
        
        if args.verbose:
            print(f"\n✅ Analysis completed successfully!")
            print(f"📄 Report saved: {report_file}")
        
    except Exception as e:
        print(f"❌ Error during analysis: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 