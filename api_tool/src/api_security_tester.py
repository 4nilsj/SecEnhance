#!/usr/bin/env python3
"""
API Security Testing Tool
A comprehensive API security testing tool for senior AppSec engineers.
Supports REST APIs, GraphQL, authentication bypass, business logic testing, and advanced fuzzing.
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
from urllib.parse import urljoin, urlparse

import httpx
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel

from .analyzers.rest_api_analyzer import RESTAPIAnalyzer
from .analyzers.graphql_analyzer import GraphQLAnalyzer
from .analyzers.authentication_analyzer import AuthenticationAnalyzer
from .analyzers.business_logic_analyzer import BusinessLogicAnalyzer
from .analyzers.fuzzing_analyzer import FuzzingAnalyzer
from .analyzers.rate_limit_analyzer import RateLimitAnalyzer
from .reporting.report_generator import ReportGenerator
from .utils.debug_utils import setup_debug_logging, debug_print

class APISecurityTester:
    """Main class for API security testing."""
    
    def __init__(self, config_file: str = None, debug: bool = False):
        """Initialize the API security tester."""
        self.console = Console()
        self.debug = debug
        self.results = {
            "scan_info": {},
            "rest_analysis": {},
            "graphql_analysis": {},
            "auth_analysis": {},
            "business_logic_analysis": {},
            "fuzzing_analysis": {},
            "rate_limit_analysis": {},
            "vulnerabilities": [],
            "summary": {}
        }
        
        # Initialize analyzers
        self.rest_analyzer = RESTAPIAnalyzer(debug=debug)
        self.graphql_analyzer = GraphQLAnalyzer(debug=debug)
        self.auth_analyzer = AuthenticationAnalyzer(debug=debug)
        self.business_logic_analyzer = BusinessLogicAnalyzer(debug=debug)
        self.fuzzing_analyzer = FuzzingAnalyzer(debug=debug)
        self.rate_limit_analyzer = RateLimitAnalyzer(debug=debug)
        self.report_generator = ReportGenerator(debug=debug)
        
        # Setup logging
        self._setup_logging()
        
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
                    logging.FileHandler('api_security_debug.log')
                ]
            )
        else:
            logging.basicConfig(level=logging.INFO)
    
    def _load_config(self, config_file: str):
        """Load configuration from file."""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except Exception as e:
            self.console.print(f"[red]Error loading config: {str(e)}[/red]")
            self.config = {}
    
    def analyze_rest_api(self, base_url: str, openapi_spec: str = None, 
                        endpoints: List[str] = None, tests: List[str] = None) -> Dict[str, Any]:
        """Analyze REST API security."""
        self.console.print(f"[bold cyan]Analyzing REST API: {base_url}[/bold cyan]")
        
        # Update scan info
        self.results["scan_info"] = {
            "api_type": "REST",
            "base_url": base_url,
            "openapi_spec": openapi_spec,
            "scan_date": datetime.now().isoformat(),
            "tests_performed": tests or ["authentication", "authorization", "input_validation", "business_logic", "rate_limiting"]
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # REST API Analysis
            task = progress.add_task("Performing REST API analysis...", total=None)
            self.results["rest_analysis"] = self.rest_analyzer.analyze(
                base_url, openapi_spec, endpoints
            )
            progress.update(task, completed=True)
            
            # Authentication Analysis
            if "authentication" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing authentication analysis...", total=None)
                self.results["auth_analysis"] = self.auth_analyzer.analyze_rest_auth(
                    base_url, self.results["rest_analysis"]
                )
                progress.update(task, completed=True)
            
            # Business Logic Analysis
            if "business_logic" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing business logic analysis...", total=None)
                self.results["business_logic_analysis"] = self.business_logic_analyzer.analyze_rest(
                    base_url, self.results["rest_analysis"]
                )
                progress.update(task, completed=True)
            
            # Rate Limiting Analysis
            if "rate_limiting" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing rate limiting analysis...", total=None)
                self.results["rate_limit_analysis"] = self.rate_limit_analyzer.analyze_rest(
                    base_url, self.results["rest_analysis"]
                )
                progress.update(task, completed=True)
        
        # Generate vulnerability summary
        self._generate_vulnerability_summary()
        
        return self.results
    
    def analyze_graphql(self, endpoint: str, schema: str = None, 
                       queries: List[str] = None, tests: List[str] = None) -> Dict[str, Any]:
        """Analyze GraphQL API security."""
        self.console.print(f"[bold cyan]Analyzing GraphQL API: {endpoint}[/bold cyan]")
        
        # Update scan info
        self.results["scan_info"] = {
            "api_type": "GraphQL",
            "endpoint": endpoint,
            "schema": schema,
            "scan_date": datetime.now().isoformat(),
            "tests_performed": tests or ["introspection", "authentication", "authorization", "injection", "rate_limiting"]
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # GraphQL Analysis
            task = progress.add_task("Performing GraphQL analysis...", total=None)
            self.results["graphql_analysis"] = self.graphql_analyzer.analyze(
                endpoint, schema, queries
            )
            progress.update(task, completed=True)
            
            # Authentication Analysis
            if "authentication" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing GraphQL authentication analysis...", total=None)
                self.results["auth_analysis"] = self.auth_analyzer.analyze_graphql_auth(
                    endpoint, self.results["graphql_analysis"]
                )
                progress.update(task, completed=True)
            
            # Rate Limiting Analysis
            if "rate_limiting" in self.results["scan_info"]["tests_performed"]:
                task = progress.add_task("Performing GraphQL rate limiting analysis...", total=None)
                self.results["rate_limit_analysis"] = self.rate_limit_analyzer.analyze_graphql(
                    endpoint, self.results["graphql_analysis"]
                )
                progress.update(task, completed=True)
        
        # Generate vulnerability summary
        self._generate_vulnerability_summary()
        
        return self.results
    
    def fuzz_api(self, base_url: str, api_type: str = "rest", 
                 fuzzing_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform advanced API fuzzing."""
        self.console.print(f"[bold cyan]Fuzzing {api_type.upper()} API: {base_url}[/bold cyan]")
        
        # Update scan info
        self.results["scan_info"] = {
            "api_type": api_type.upper(),
            "base_url": base_url,
            "scan_date": datetime.now().isoformat(),
            "tests_performed": ["fuzzing"]
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            task = progress.add_task("Performing API fuzzing...", total=None)
            self.results["fuzzing_analysis"] = self.fuzzing_analyzer.fuzz_api(
                base_url, api_type, fuzzing_config
            )
            progress.update(task, completed=True)
        
        # Generate vulnerability summary
        self._generate_vulnerability_summary()
        
        return self.results
    
    def batch_analyze(self, api_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze multiple APIs in batch."""
        self.console.print(f"[bold cyan]Batch analyzing {len(api_list)} APIs[/bold cyan]")
        
        batch_results = {
            "batch_info": {
                "total_apis": len(api_list),
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
            
            for i, api_config in enumerate(api_list):
                task = progress.add_task(f"Analyzing API {i+1}/{len(api_list)}...", total=None)
                
                try:
                    if api_config.get("type", "rest").lower() == "rest":
                        result = self.analyze_rest_api(
                            api_config["url"],
                            api_config.get("openapi_spec"),
                            api_config.get("endpoints"),
                            api_config.get("tests")
                        )
                    else:
                        result = self.analyze_graphql(
                            api_config["url"],
                            api_config.get("schema"),
                            api_config.get("queries"),
                            api_config.get("tests")
                        )
                    
                    batch_results["results"].append({
                        "api_config": api_config,
                        "result": result
                    })
                    batch_results["batch_info"]["successful_scans"] += 1
                    
                except Exception as e:
                    self.console.print(f"[red]Error analyzing API {api_config.get('url', 'unknown')}: {str(e)}[/red]")
                    batch_results["batch_info"]["failed_scans"] += 1
                
                progress.update(task, completed=True)
        
        return batch_results
    
    def _generate_vulnerability_summary(self):
        """Generate vulnerability summary from all analysis results."""
        vulnerabilities = []
        
        # Collect vulnerabilities from all analyzers
        for analysis_type, results in self.results.items():
            if analysis_type in ["rest_analysis", "graphql_analysis", "auth_analysis", 
                               "business_logic_analysis", "fuzzing_analysis", "rate_limit_analysis"]:
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
            output_file = f"api_security_report_{timestamp}.{format}"
        
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
        table = Table(title="API Security Analysis Summary")
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
            f"API Type: {scan_info.get('api_type', 'N/A')}\n"
            f"URL: {scan_info.get('base_url', scan_info.get('endpoint', 'N/A'))}\n"
            f"Date: {scan_info.get('scan_date', 'N/A')}\n"
            f"Tests: {', '.join(scan_info.get('tests_performed', []))}",
            title="Scan Information",
            border_style="blue"
        )
        self.console.print(info_panel)

def main():
    """Main function for API security testing."""
    parser = argparse.ArgumentParser(description="API Security Testing Tool")
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--rest", help="REST API base URL to analyze")
    input_group.add_argument("--graphql", help="GraphQL endpoint to analyze")
    input_group.add_argument("--fuzz", help="API endpoint to fuzz")
    input_group.add_argument("--batch", help="JSON file containing list of APIs for batch analysis")
    
    # Analysis options
    parser.add_argument("--openapi", help="OpenAPI specification file")
    parser.add_argument("--schema", help="GraphQL schema file")
    parser.add_argument("--endpoints", help="Comma-separated list of specific endpoints to test")
    parser.add_argument("--queries", help="Comma-separated list of GraphQL queries to test")
    parser.add_argument("--tests", help="Comma-separated list of tests to run")
    parser.add_argument("--api-type", choices=["rest", "graphql"], default="rest", help="API type for fuzzing")
    parser.add_argument("--fuzz-config", help="JSON file with fuzzing configuration")
    
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
    
    # Initialize tester
    tester = APISecurityTester(config_file=args.config, debug=args.debug)
    
    try:
        debug_print("Parsed arguments:", args)
        
        # Determine tests to run
        if args.tests:
            tests = args.tests.split(",")
        else:
            tests = None
        
        debug_print("Tests to run:", tests)
        
        # Run analysis
        if args.rest:
            debug_print("Starting REST API analysis for:", args.rest)
            results = tester.analyze_rest_api(
                args.rest, 
                args.openapi, 
                args.endpoints.split(",") if args.endpoints else None,
                tests
            )
        elif args.graphql:
            debug_print("Starting GraphQL analysis for:", args.graphql)
            results = tester.analyze_graphql(
                args.graphql,
                args.schema,
                args.queries.split(",") if args.queries else None,
                tests
            )
        elif args.fuzz:
            debug_print("Starting API fuzzing for:", args.fuzz)
            fuzz_config = None
            if args.fuzz_config:
                with open(args.fuzz_config, 'r') as f:
                    fuzz_config = json.load(f)
            results = tester.fuzz_api(args.fuzz, args.api_type, fuzz_config)
        elif args.batch:
            debug_print("Starting batch analysis with file:", args.batch)
            with open(args.batch, 'r') as f:
                api_list = json.load(f)
            results = tester.batch_analyze(api_list)
        
        # Print summary
        if args.verbose:
            tester.print_summary()
        
        # Generate report
        report_file = tester.generate_report(args.output, args.format)
        if args.verbose:
            print(f"\n✅ Analysis completed successfully!")
            print(f"📄 Report saved: {report_file}")
        
        debug_print("Analysis complete. Report file:", report_file)
        
    except Exception as e:
        print(f"❌ Error during analysis: {str(e)}")
        debug_print("Exception occurred:", str(e))
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 