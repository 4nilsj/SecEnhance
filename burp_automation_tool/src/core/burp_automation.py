#!/usr/bin/env python3
"""
Burp Suite Automation Framework
Main automation engine for BChecks, Extensions, and Bambdas (no REST API required)
"""

import os
import sys
import yaml
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from utils.config_manager import ConfigManager
from utils.logger import setup_logger
from analyzers.bcheck_analyzer import BCheckAnalyzer
from analyzers.extension_analyzer import ExtensionAnalyzer
from analyzers.bambda_analyzer import BambdaAnalyzer
from reporters.report_generator import ReportGenerator


class BurpAutomation:
    """
    Main automation class for Burp Suite components (no REST API required)
    """
    
    def __init__(self, config_path: str = "config/burp_config.yaml"):
        """
        Initialize Burp Suite automation
        
        Args:
            config_path: Path to configuration file
        """
        self.config_manager = ConfigManager(config_path)
        self.logger = setup_logger("burp_automation")
        self.config = self.config_manager.load_config()
        
        # Initialize analyzers
        self.bcheck_analyzer = BCheckAnalyzer()
        self.extension_analyzer = ExtensionAnalyzer()
        self.bambda_analyzer = BambdaAnalyzer()
        
        # Initialize reporter
        self.report_generator = ReportGenerator()
        
        # No REST API connection required
        self.logger.info("Burp Suite Automation initialized (no REST API required)")
    
    def connect_to_burp(self) -> bool:
        """
        Placeholder for compatibility (no REST API connection required)
        
        Returns:
            bool: Always True since no connection needed
        """
        self.logger.info("No REST API connection required for this toolkit")
        return True
    
    def load_bchecks(self, bcheck_dir: str = "bchecks/") -> List[Dict[str, Any]]:
        """
        Load BChecks from directory
        
        Args:
            bcheck_dir: Directory containing BChecks
            
        Returns:
            List of loaded BChecks
        """
        bchecks = []
        bcheck_path = Path(bcheck_dir)
        
        if not bcheck_path.exists():
            self.logger.warning(f"BCheck directory not found: {bcheck_dir}")
            return bchecks
        
        for bcheck_file in bcheck_path.rglob("*.bcheck"):
            try:
                bcheck_data = self.bcheck_analyzer.load_bcheck(bcheck_file)
                bchecks.append(bcheck_data)
                self.logger.info(f"Loaded BCheck: {bcheck_file.name}")
            except Exception as e:
                self.logger.error(f"Error loading BCheck {bcheck_file}: {e}")
        
        return bchecks
    
    def load_extensions(self, extension_dir: str = "extensions/") -> List[Dict[str, Any]]:
        """
        Load extensions from directory
        
        Args:
            extension_dir: Directory containing extensions
            
        Returns:
            List of loaded extensions
        """
        extensions = []
        extension_path = Path(extension_dir)
        
        if not extension_path.exists():
            self.logger.warning(f"Extension directory not found: {extension_dir}")
            return extensions
        
        # Load Java extensions
        java_ext_dir = extension_path / "java_extensions"
        if java_ext_dir.exists():
            for jar_file in java_ext_dir.glob("*.jar"):
                try:
                    ext_data = self.extension_analyzer.load_java_extension(jar_file)
                    extensions.append(ext_data)
                    self.logger.info(f"Loaded Java extension: {jar_file.name}")
                except Exception as e:
                    self.logger.error(f"Error loading Java extension {jar_file}: {e}")
        
        # Load Python extensions
        python_ext_dir = extension_path / "python_extensions"
        if python_ext_dir.exists():
            for py_file in python_ext_dir.glob("*.py"):
                try:
                    ext_data = self.extension_analyzer.load_python_extension(py_file)
                    extensions.append(ext_data)
                    self.logger.info(f"Loaded Python extension: {py_file.name}")
                except Exception as e:
                    self.logger.error(f"Error loading Python extension {py_file}: {e}")
        
        return extensions
    
    def load_bambdas(self, bambda_dir: str = "bambdas/") -> List[Dict[str, Any]]:
        """
        Load Bambdas from directory
        
        Args:
            bambda_dir: Directory containing Bambdas
            
        Returns:
            List of loaded Bambdas
        """
        bambdas = []
        bambda_path = Path(bambda_dir)
        
        if not bambda_path.exists():
            self.logger.warning(f"Bambda directory not found: {bambda_dir}")
            return bambdas
        
        # Load request Bambdas
        request_bambda_dir = bambda_path / "request_bambdas"
        if request_bambda_dir.exists():
            for py_file in request_bambda_dir.glob("*.py"):
                try:
                    bambda_data = self.bambda_analyzer.load_request_bambda(py_file)
                    bambdas.append(bambda_data)
                    self.logger.info(f"Loaded request Bambda: {py_file.name}")
                except Exception as e:
                    self.logger.error(f"Error loading request Bambda {py_file}: {e}")
        
        # Load response Bambdas
        response_bambda_dir = bambda_path / "response_bambdas"
        if response_bambda_dir.exists():
            for py_file in response_bambda_dir.glob("*.py"):
                try:
                    bambda_data = self.bambda_analyzer.load_response_bambda(py_file)
                    bambdas.append(bambda_data)
                    self.logger.info(f"Loaded response Bambda: {py_file.name}")
                except Exception as e:
                    self.logger.error(f"Error loading response Bambda {py_file}: {e}")
        
        return bambdas
    
    def run_security_scan(self, target_url: str, scan_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run comprehensive security scan
        
        Args:
            target_url: Target URL to scan
            scan_config: Scan configuration
            
        Returns:
            Scan results
        """
        self.logger.info(f"Starting security scan for: {target_url}")
        
        # No REST API connection required
        self.logger.info("Proceeding with local component analysis (no REST API needed)")
        
        # Load all components
        bchecks = self.load_bchecks()
        extensions = self.load_extensions()
        bambdas = self.load_bambdas()
        
        # Initialize scan results
        scan_results = {
            "target_url": target_url,
            "scan_timestamp": datetime.now().isoformat(),
            "bchecks_loaded": len(bchecks),
            "extensions_loaded": len(extensions),
            "bambdas_loaded": len(bambdas),
            "vulnerabilities": [],
            "warnings": [],
            "info": []
        }
        
        # Run BChecks
        for bcheck in bchecks:
            try:
                bcheck_results = self.bcheck_analyzer.run_bcheck(bcheck, target_url)
                scan_results["vulnerabilities"].extend(bcheck_results.get("vulnerabilities", []))
                scan_results["warnings"].extend(bcheck_results.get("warnings", []))
                scan_results["info"].extend(bcheck_results.get("info", []))
            except Exception as e:
                self.logger.error(f"Error running BCheck {bcheck.get('name', 'Unknown')}: {e}")
        
        # Run extensions
        for extension in extensions:
            try:
                ext_results = self.extension_analyzer.run_extension(extension, target_url)
                scan_results["vulnerabilities"].extend(ext_results.get("vulnerabilities", []))
                scan_results["warnings"].extend(ext_results.get("warnings", []))
                scan_results["info"].extend(ext_results.get("info", []))
            except Exception as e:
                self.logger.error(f"Error running extension {extension.get('name', 'Unknown')}: {e}")
        
        # Run Bambdas
        for bambda in bambdas:
            try:
                bambda_results = self.bambda_analyzer.run_bambda(bambda, target_url)
                scan_results["vulnerabilities"].extend(bambda_results.get("vulnerabilities", []))
                scan_results["warnings"].extend(bambda_results.get("warnings", []))
                scan_results["info"].extend(bambda_results.get("info", []))
            except Exception as e:
                self.logger.error(f"Error running Bambda {bambda.get('name', 'Unknown')}: {e}")
        
        self.logger.info(f"Security scan completed. Found {len(scan_results['vulnerabilities'])} vulnerabilities")
        return scan_results
    
    def generate_report(self, scan_results: Dict[str, Any], report_format: str = "html") -> str:
        """
        Generate security report
        
        Args:
            scan_results: Results from security scan
            report_format: Report format (html, json, pdf)
            
        Returns:
            Path to generated report
        """
        return self.report_generator.generate_report(scan_results, report_format)
    
    def run_automated_test_suite(self, targets: List[str], config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run automated test suite on multiple targets
        
        Args:
            targets: List of target URLs
            config: Test configuration
            
        Returns:
            Test suite results
        """
        self.logger.info(f"Starting automated test suite for {len(targets)} targets")
        
        suite_results = {
            "test_suite_timestamp": datetime.now().isoformat(),
            "targets_scanned": len(targets),
            "total_vulnerabilities": 0,
            "target_results": {},
            "summary": {}
        }
        
        for target in targets:
            try:
                self.logger.info(f"Scanning target: {target}")
                target_results = self.run_security_scan(target, config)
                suite_results["target_results"][target] = target_results
                suite_results["total_vulnerabilities"] += len(target_results.get("vulnerabilities", []))
            except Exception as e:
                self.logger.error(f"Error scanning target {target}: {e}")
                suite_results["target_results"][target] = {"error": str(e)}
        
        # Generate summary
        suite_results["summary"] = {
            "high_vulnerabilities": sum(1 for result in suite_results["target_results"].values() 
                                      for vuln in result.get("vulnerabilities", []) 
                                      if vuln.get("severity") == "High"),
            "medium_vulnerabilities": sum(1 for result in suite_results["target_results"].values() 
                                        for vuln in result.get("vulnerabilities", []) 
                                        if vuln.get("severity") == "Medium"),
            "low_vulnerabilities": sum(1 for result in suite_results["target_results"].values() 
                                     for vuln in result.get("vulnerabilities", []) 
                                     if vuln.get("severity") == "Low")
        }
        
        self.logger.info(f"Test suite completed. Total vulnerabilities: {suite_results['total_vulnerabilities']}")
        return suite_results


def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Burp Suite Automation Tool (no REST API required)")
    parser.add_argument("--target", "-t", required=True, help="Target URL to scan")
    parser.add_argument("--config", "-c", default="config/burp_config.yaml", help="Configuration file")
    parser.add_argument("--report-format", "-r", default="html", choices=["html", "json", "pdf"], help="Report format")
    parser.add_argument("--output", "-o", help="Output directory for reports")
    
    args = parser.parse_args()
    
    # Initialize automation
    automation = BurpAutomation(args.config)
    
    try:
        # Run security scan
        scan_results = automation.run_security_scan(args.target)
        
        # Generate report
        report_path = automation.generate_report(scan_results, args.report_format)
        
        print(f"Scan completed successfully!")
        print(f"Found {len(scan_results['vulnerabilities'])} vulnerabilities")
        print(f"Report generated: {report_path}")
        
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 