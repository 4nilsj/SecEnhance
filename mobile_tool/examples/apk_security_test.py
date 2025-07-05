#!/usr/bin/env python3
"""
APK Security Testing Tool
Specialized tool for comprehensive Android APK security analysis.
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from analyzers.static_analyzer import StaticAnalyzer
from analyzers.code_analyzer import CodeAnalyzer
from analyzers.storage_analyzer import StorageAnalyzer
from analyzers.network_analyzer import NetworkAnalyzer
from analyzers.dynamic_analyzer import DynamicAnalyzer
from reporting.report_generator import ReportGenerator
from utils.debug_utils import setup_debug_logging, debug_print

def setup_logging(debug: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(f'apk_security_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        ]
    )

def analyze_apk_comprehensive(apk_path: str, debug: bool = False) -> dict:
    """Perform comprehensive APK security analysis."""
    debug_print(f"Starting comprehensive APK analysis: {apk_path}", debug)
    
    results = {
        "apk_info": {},
        "static_analysis": {},
        "code_analysis": {},
        "storage_analysis": {},
        "network_analysis": {},
        "dynamic_analysis": {},
        "security_summary": {},
        "recommendations": [],
        "timestamp": datetime.now().isoformat()
    }
    
    try:
        # Initialize analyzers
        static_analyzer = StaticAnalyzer(debug=debug)
        code_analyzer = CodeAnalyzer(debug=debug)
        storage_analyzer = StorageAnalyzer(debug=debug)
        network_analyzer = NetworkAnalyzer(debug=debug)
        dynamic_analyzer = DynamicAnalyzer(debug=debug)
        
        debug_print("Analyzers initialized successfully", debug)
        
        # 1. Static Analysis
        debug_print("Starting static analysis...", debug)
        results["static_analysis"] = static_analyzer.analyze_apk(apk_path)
        
        # 2. Code Analysis
        debug_print("Starting code analysis...", debug)
        results["code_analysis"] = code_analyzer.analyze_apk(apk_path)
        
        # 3. Storage Analysis
        debug_print("Starting storage analysis...", debug)
        results["storage_analysis"] = storage_analyzer.analyze_apk(apk_path)
        
        # 4. Network Analysis
        debug_print("Starting network analysis...", debug)
        results["network_analysis"] = network_analyzer.analyze_apk(apk_path)
        
        # 5. Dynamic Analysis (if device connected)
        debug_print("Starting dynamic analysis...", debug)
        results["dynamic_analysis"] = dynamic_analyzer.analyze_apk(apk_path)
        
        # Generate security summary
        results["security_summary"] = generate_security_summary(results)
        
        # Generate recommendations
        results["recommendations"] = generate_recommendations(results)
        
        debug_print("Comprehensive analysis completed successfully", debug)
        
    except Exception as e:
        debug_print(f"Error during comprehensive analysis: {str(e)}", debug)
        results["error"] = str(e)
    
    return results

def generate_security_summary(results: dict) -> dict:
    """Generate a comprehensive security summary."""
    summary = {
        "total_vulnerabilities": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0,
        "info_severity": 0,
        "critical_issues": [],
        "high_issues": [],
        "medium_issues": [],
        "low_issues": [],
        "info_issues": [],
        "risk_score": 0,
        "overall_security_status": "Unknown"
    }
    
    try:
        # Collect all vulnerabilities from different analyzers
        all_vulnerabilities = []
        
        # Static analysis vulnerabilities
        static_vulns = results.get("static_analysis", {}).get("vulnerabilities", [])
        all_vulnerabilities.extend(static_vulns)
        
        # Code analysis vulnerabilities
        code_vulns = results.get("code_analysis", {}).get("vulnerabilities", [])
        all_vulnerabilities.extend(code_vulns)
        
        # Storage analysis vulnerabilities
        storage_vulns = results.get("storage_analysis", {}).get("vulnerabilities", [])
        all_vulnerabilities.extend(storage_vulns)
        
        # Network analysis vulnerabilities
        network_vulns = results.get("network_analysis", {}).get("vulnerabilities", [])
        all_vulnerabilities.extend(network_vulns)
        
        # Dynamic analysis vulnerabilities
        dynamic_vulns = results.get("dynamic_analysis", {}).get("vulnerabilities", [])
        all_vulnerabilities.extend(dynamic_vulns)
        
        # Categorize vulnerabilities by severity
        for vuln in all_vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            summary["total_vulnerabilities"] += 1
            
            if severity == "critical":
                summary["critical_issues"].append(vuln)
            elif severity == "high":
                summary["high_severity"] += 1
                summary["high_issues"].append(vuln)
            elif severity == "medium":
                summary["medium_severity"] += 1
                summary["medium_issues"].append(vuln)
            elif severity == "low":
                summary["low_severity"] += 1
                summary["low_issues"].append(vuln)
            elif severity == "info":
                summary["info_severity"] += 1
                summary["info_issues"].append(vuln)
        
        # Calculate risk score (0-100)
        risk_score = (
            len(summary["critical_issues"]) * 25 +
            summary["high_severity"] * 15 +
            summary["medium_severity"] * 8 +
            summary["low_severity"] * 3 +
            summary["info_severity"] * 1
        )
        summary["risk_score"] = min(risk_score, 100)
        
        # Determine overall security status
        if summary["risk_score"] >= 80:
            summary["overall_security_status"] = "Critical"
        elif summary["risk_score"] >= 60:
            summary["overall_security_status"] = "High"
        elif summary["risk_score"] >= 40:
            summary["overall_security_status"] = "Medium"
        elif summary["risk_score"] >= 20:
            summary["overall_security_status"] = "Low"
        else:
            summary["overall_security_status"] = "Good"
        
    except Exception as e:
        summary["error"] = str(e)
    
    return summary

def generate_recommendations(results: dict) -> list:
    """Generate comprehensive security recommendations."""
    recommendations = []
    
    try:
        # Static analysis recommendations
        static_recs = results.get("static_analysis", {}).get("recommendations", [])
        recommendations.extend(static_recs)
        
        # Code analysis recommendations
        code_recs = results.get("code_analysis", {}).get("recommendations", [])
        recommendations.extend(code_recs)
        
        # Storage analysis recommendations
        storage_recs = results.get("storage_analysis", {}).get("recommendations", [])
        recommendations.extend(storage_recs)
        
        # Network analysis recommendations
        network_recs = results.get("network_analysis", {}).get("recommendations", [])
        recommendations.extend(network_recs)
        
        # Dynamic analysis recommendations
        dynamic_recs = results.get("dynamic_analysis", {}).get("recommendations", [])
        recommendations.extend(dynamic_recs)
        
        # Add general recommendations based on findings
        summary = results.get("security_summary", {})
        
        if summary.get("high_severity", 0) > 0:
            recommendations.append("Prioritize fixing high severity vulnerabilities immediately")
        
        if summary.get("critical_issues"):
            recommendations.append("Address critical security issues before production deployment")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        recommendations = unique_recommendations
        
    except Exception as e:
        recommendations.append(f"Error generating recommendations: {str(e)}")
    
    return recommendations

def save_results(results: dict, output_file: str):
    """Save analysis results to file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"Results saved to: {output_file}")
    except Exception as e:
        print(f"Error saving results: {str(e)}")

def print_summary(results: dict):
    """Print a summary of the analysis results."""
    summary = results.get("security_summary", {})
    
    print("\n" + "="*60)
    print("APK SECURITY ANALYSIS SUMMARY")
    print("="*60)
    
    print(f"Overall Security Status: {summary.get('overall_security_status', 'Unknown')}")
    print(f"Risk Score: {summary.get('risk_score', 0)}/100")
    print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    
    print(f"\nVulnerabilities by Severity:")
    print(f"  Critical: {len(summary.get('critical_issues', []))}")
    print(f"  High: {summary.get('high_severity', 0)}")
    print(f"  Medium: {summary.get('medium_severity', 0)}")
    print(f"  Low: {summary.get('low_severity', 0)}")
    print(f"  Info: {summary.get('info_severity', 0)}")
    
    # Print critical issues
    critical_issues = summary.get('critical_issues', [])
    if critical_issues:
        print(f"\nCritical Issues:")
        for i, issue in enumerate(critical_issues, 1):
            print(f"  {i}. {issue.get('description', 'Unknown issue')}")
    
    # Print high severity issues
    high_issues = summary.get('high_issues', [])
    if high_issues:
        print(f"\nHigh Severity Issues:")
        for i, issue in enumerate(high_issues[:5], 1):  # Show first 5
            print(f"  {i}. {issue.get('description', 'Unknown issue')}")
        if len(high_issues) > 5:
            print(f"  ... and {len(high_issues) - 5} more")
    
    print("\n" + "="*60)

def main():
    """Main function for APK security testing."""
    parser = argparse.ArgumentParser(description="APK Security Testing Tool")
    parser.add_argument("apk_path", help="Path to the APK file to analyze")
    parser.add_argument("-o", "--output", help="Output file for results (JSON)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--no-summary", action="store_true", help="Skip printing summary")
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.debug)
    
    # Check if APK file exists
    if not os.path.exists(args.apk_path):
        print(f"Error: APK file not found: {args.apk_path}")
        sys.exit(1)
    
    if not args.apk_path.endswith('.apk'):
        print(f"Warning: File does not have .apk extension: {args.apk_path}")
    
    print(f"Starting APK security analysis: {args.apk_path}")
    print(f"Debug mode: {'Enabled' if args.debug else 'Disabled'}")
    
    # Perform comprehensive analysis
    results = analyze_apk_comprehensive(args.apk_path, args.debug)
    
    # Print summary
    if not args.no_summary:
        print_summary(results)
    
    # Save results
    if args.output:
        save_results(results, args.output)
    else:
        # Generate default output filename
        apk_name = Path(args.apk_path).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_output = f"apk_analysis_{apk_name}_{timestamp}.json"
        save_results(results, default_output)
    
    print("\nAnalysis completed successfully!")

if __name__ == "__main__":
    main() 