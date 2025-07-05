"""
AI-Enabled SAST Scanner
Static Application Security Testing with AI-powered analysis and context understanding.
"""

import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from .debug_utils import setup_debug_logging, debug_print, debug_log, debug_performance
from .analyzers.code_analyzer import CodeAnalyzer
from .analyzers.ai_analyzer import AIAnalyzer
from .analyzers.vulnerability_detector import VulnerabilityDetector
from .analyzers.context_analyzer import ContextAnalyzer
from .report_generator import ReportGenerator

console = Console()

class SASTScanner:
    """AI-enabled Static Application Security Testing scanner."""
    
    def __init__(self, debug: bool = False, max_workers: int = 4):
        """Initialize the SAST scanner."""
        setup_debug_logging(debug)
        self.debug = debug
        self.max_workers = max_workers
        
        # Initialize analyzers
        self.code_analyzer = CodeAnalyzer(debug=debug)
        self.ai_analyzer = AIAnalyzer(debug=debug)
        self.vulnerability_detector = VulnerabilityDetector(debug=debug)
        self.context_analyzer = ContextAnalyzer(debug=debug)
        self.report_generator = ReportGenerator(debug=debug)
        
        # Results storage
        self.scan_results = {
            "scan_info": {},
            "files_analyzed": [],
            "vulnerabilities": [],
            "ai_insights": [],
            "summary": {}
        }
        
        # Thread safety
        self.results_lock = threading.Lock()
        
        debug_log("sast_scanner", "SAST Scanner initialized")
    
    def scan_file(self, file_path: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """Scan a single file for security vulnerabilities."""
        start_time = datetime.now()
        debug_log("sast_scanner", f"Starting scan of file: {file_path}")
        
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Initialize file results
        file_results = {
            "file_path": str(file_path),
            "file_name": file_path.name,
            "file_size": file_path.stat().st_size,
            "file_type": self._get_file_type(file_path),
            "scan_timestamp": datetime.now().isoformat(),
            "vulnerabilities": [],
            "ai_insights": [],
            "context_analysis": {},
            "code_metrics": {},
            "scan_duration": 0.0
        }
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            file_results["content_length"] = len(content)
            
            # Perform code analysis
            debug_print(f"Analyzing code structure for {file_path.name}", "INFO", "sast_scanner")
            code_analysis = self.code_analyzer.analyze_code(content, str(file_path))
            file_results["code_metrics"] = code_analysis
            
            # Perform context analysis
            debug_print(f"Analyzing context for {file_path.name}", "INFO", "sast_scanner")
            context_analysis = self.context_analyzer.analyze_context(
                content, str(file_path), context
            )
            file_results["context_analysis"] = context_analysis
            
            # Perform vulnerability detection
            debug_print(f"Detecting vulnerabilities in {file_path.name}", "INFO", "sast_scanner")
            vulnerabilities = self.vulnerability_detector.detect_vulnerabilities(
                content, str(file_path), code_analysis
            )
            file_results["vulnerabilities"] = vulnerabilities
            
            # Perform AI analysis
            debug_print(f"Running AI analysis on {file_path.name}", "INFO", "sast_scanner")
            ai_insights = self.ai_analyzer.analyze_file(
                content, str(file_path), code_analysis, context_analysis
            )
            file_results["ai_insights"] = ai_insights
            
            # Calculate scan duration
            scan_duration = (datetime.now() - start_time).total_seconds()
            file_results["scan_duration"] = scan_duration
            
            debug_log("sast_scanner", f"File scan completed: {file_path.name}", 
                     data={"duration": scan_duration, "vulnerabilities": len(vulnerabilities)})
            
            return file_results
            
        except Exception as e:
            debug_log("sast_scanner", f"Error scanning file {file_path}: {e}", "ERROR")
            file_results["error"] = str(e)
            file_results["scan_duration"] = (datetime.now() - start_time).total_seconds()
            return file_results
    
    def scan_directory(self, directory_path: str, file_patterns: Optional[List[str]] = None) -> Dict[str, Any]:
        """Scan a directory for security vulnerabilities."""
        start_time = datetime.now()
        debug_log("sast_scanner", f"Starting directory scan: {directory_path}")
        
        directory_path = Path(directory_path)
        if not directory_path.exists() or not directory_path.is_dir():
            raise NotADirectoryError(f"Directory not found: {directory_path}")
        
        # Initialize scan results
        self.scan_results = {
            "scan_info": {
                "scan_type": "directory",
                "directory_path": str(directory_path),
                "start_time": start_time.isoformat(),
                "file_patterns": file_patterns or ["*.py", "*.js", "*.java", "*.cpp", "*.c", "*.php", "*.rb", "*.go"]
            },
            "files_analyzed": [],
            "vulnerabilities": [],
            "ai_insights": [],
            "summary": {}
        }
        
        # Find files to scan
        files_to_scan = self._find_files(directory_path, file_patterns)
        debug_log("sast_scanner", f"Found {len(files_to_scan)} files to scan")
        
        if not files_to_scan:
            console.print("[yellow]No files found matching the specified patterns[/yellow]")
            return self.scan_results
        
        # Scan files with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Scanning files...", total=len(files_to_scan))
            
            # Use ThreadPoolExecutor for parallel scanning
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all scan tasks
                future_to_file = {
                    executor.submit(self.scan_file, str(file_path)): file_path 
                    for file_path in files_to_scan
                }
                
                # Process completed scans
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        file_result = future.result()
                        self._add_file_result(file_result)
                        progress.update(task, advance=1)
                        
                        # Update progress description
                        progress.update(task, description=f"Scanned {file_path.name}")
                        
                    except Exception as e:
                        debug_log("sast_scanner", f"Error scanning {file_path}: {e}", "ERROR")
                        progress.update(task, advance=1)
        
        # Generate summary
        self._generate_summary()
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        self.scan_results["scan_info"]["end_time"] = datetime.now().isoformat()
        self.scan_results["scan_info"]["total_duration"] = scan_duration
        
        debug_log("sast_scanner", "Directory scan completed", 
                 data={"duration": scan_duration, "files": len(files_to_scan)})
        
        return self.scan_results
    
    def _find_files(self, directory: Path, patterns: Optional[List[str]] = None) -> List[Path]:
        """Find files matching the specified patterns."""
        if patterns is None:
            patterns = ["*.py", "*.js", "*.java", "*.cpp", "*.c", "*.php", "*.rb", "*.go"]
        
        files = []
        for pattern in patterns:
            files.extend(directory.rglob(pattern))
        
        # Remove duplicates and sort
        files = sorted(list(set(files)))
        
        # Filter out common directories to ignore
        ignore_dirs = {".git", "__pycache__", "node_modules", "venv", "env", ".pytest_cache"}
        files = [f for f in files if not any(ignore_dir in f.parts for ignore_dir in ignore_dirs)]
        
        return files
    
    def _add_file_result(self, file_result: Dict[str, Any]) -> None:
        """Add file result to scan results (thread-safe)."""
        with self.results_lock:
            self.scan_results["files_analyzed"].append(file_result)
            
            # Add vulnerabilities
            if "vulnerabilities" in file_result:
                for vuln in file_result["vulnerabilities"]:
                    vuln["file_path"] = file_result["file_path"]
                    vuln["file_name"] = file_result["file_name"]
                    self.scan_results["vulnerabilities"].append(vuln)
            
            # Add AI insights
            if "ai_insights" in file_result:
                for insight in file_result["ai_insights"]:
                    insight["file_path"] = file_result["file_path"]
                    insight["file_name"] = file_result["file_name"]
                    self.scan_results["ai_insights"].append(insight)
    
    def _generate_summary(self) -> None:
        """Generate summary statistics for the scan."""
        files_analyzed = self.scan_results["files_analyzed"]
        vulnerabilities = self.scan_results["vulnerabilities"]
        
        # Calculate statistics
        total_files = len(files_analyzed)
        total_vulnerabilities = len(vulnerabilities)
        total_lines = sum(f.get("code_metrics", {}).get("total_lines", 0) for f in files_analyzed)
        
        # Vulnerability severity breakdown
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Vulnerability type breakdown
        type_counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown")
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        # File type breakdown
        file_type_counts = {}
        for file_result in files_analyzed:
            file_type = file_result.get("file_type", "unknown")
            file_type_counts[file_type] = file_type_counts.get(file_type, 0) + 1
        
        self.scan_results["summary"] = {
            "total_files": total_files,
            "total_vulnerabilities": total_vulnerabilities,
            "total_lines": total_lines,
            "severity_breakdown": severity_counts,
            "type_breakdown": type_counts,
            "file_type_breakdown": file_type_counts,
            "files_with_vulnerabilities": len([f for f in files_analyzed if f.get("vulnerabilities")]),
            "average_vulnerabilities_per_file": total_vulnerabilities / total_files if total_files > 0 else 0
        }
    
    def _get_file_type(self, file_path: Path) -> str:
        """Determine the file type based on extension."""
        extension = file_path.suffix.lower()
        
        type_mapping = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp",
            ".php": "php",
            ".rb": "ruby",
            ".go": "go",
            ".rs": "rust",
            ".swift": "swift",
            ".kt": "kotlin",
            ".scala": "scala",
            ".cs": "csharp",
            ".vb": "vb",
            ".sql": "sql",
            ".sh": "shell",
            ".ps1": "powershell",
            ".bat": "batch",
            ".yml": "yaml",
            ".yaml": "yaml",
            ".json": "json",
            ".xml": "xml",
            ".html": "html",
            ".css": "css"
        }
        
        return type_mapping.get(extension, "unknown")
    
    def display_summary(self) -> None:
        """Display scan summary in the console."""
        summary = self.scan_results.get("summary", {})
        
        console.print("\n[bold blue]SAST Scan Summary[/bold blue]")
        console.print("=" * 50)
        
        # Basic statistics
        stats_table = Table(title="Scan Statistics")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="magenta")
        
        stats_table.add_row("Total Files", str(summary.get("total_files", 0)))
        stats_table.add_row("Total Lines", str(summary.get("total_lines", 0)))
        stats_table.add_row("Total Vulnerabilities", str(summary.get("total_vulnerabilities", 0)))
        stats_table.add_row("Files with Vulnerabilities", str(summary.get("files_with_vulnerabilities", 0)))
        stats_table.add_row("Avg Vulnerabilities/File", f"{summary.get('average_vulnerabilities_per_file', 0):.2f}")
        
        console.print(stats_table)
        
        # Severity breakdown
        if summary.get("severity_breakdown"):
            console.print("\n[bold]Vulnerability Severity Breakdown[/bold]")
            severity_table = Table()
            severity_table.add_column("Severity", style="cyan")
            severity_table.add_column("Count", style="magenta")
            
            for severity, count in summary["severity_breakdown"].items():
                color = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "green",
                    "info": "blue"
                }.get(severity.lower(), "white")
                severity_table.add_row(severity.title(), str(count), style=color)
            
            console.print(severity_table)
        
        # Top vulnerability types
        if summary.get("type_breakdown"):
            console.print("\n[bold]Top Vulnerability Types[/bold]")
            type_table = Table()
            type_table.add_column("Type", style="cyan")
            type_table.add_column("Count", style="magenta")
            
            sorted_types = sorted(summary["type_breakdown"].items(), 
                                key=lambda x: x[1], reverse=True)[:10]
            
            for vuln_type, count in sorted_types:
                type_table.add_row(vuln_type.title(), str(count))
            
            console.print(type_table)
    
    def generate_report(self, output_format: str = "html", output_file: Optional[str] = None) -> str:
        """Generate a comprehensive report of the scan results."""
        debug_log("sast_scanner", f"Generating {output_format} report")
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"sast_report_{timestamp}.{output_format}"
        
        report_path = self.report_generator.generate_report(
            self.scan_results, output_format, output_file
        )
        
        debug_log("sast_scanner", f"Report generated: {report_path}")
        return report_path
    
    def get_vulnerabilities_by_severity(self, severity: str) -> List[Dict]:
        """Get vulnerabilities filtered by severity."""
        return [v for v in self.scan_results["vulnerabilities"] 
                if v.get("severity", "").lower() == severity.lower()]
    
    def get_vulnerabilities_by_type(self, vuln_type: str) -> List[Dict]:
        """Get vulnerabilities filtered by type."""
        return [v for v in self.scan_results["vulnerabilities"] 
                if v.get("type", "").lower() == vuln_type.lower()]
    
    def get_files_with_vulnerabilities(self) -> List[Dict]:
        """Get files that contain vulnerabilities."""
        return [f for f in self.scan_results["files_analyzed"] 
                if f.get("vulnerabilities")]
    
    def export_results(self, format: str = "json") -> str:
        """Export scan results in specified format."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"sast_results_{timestamp}.{format}"
        
        if format.lower() == "json":
            with open(output_file, 'w') as f:
                json.dump(self.scan_results, f, indent=2, default=str)
        elif format.lower() == "yaml":
            import yaml
            with open(output_file, 'w') as f:
                yaml.dump(self.scan_results, f, default_flow_style=False)
        else:
            raise ValueError(f"Unsupported export format: {format}")
        
        debug_log("sast_scanner", f"Results exported to: {output_file}")
        return output_file 