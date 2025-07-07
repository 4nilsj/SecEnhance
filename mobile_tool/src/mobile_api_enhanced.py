#!/usr/bin/env python3
"""
Enhanced Mobile Security Testing API
Provides RESTful API endpoints for mobile security testing with scan ID management.
"""

import os
import json
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify, send_file, abort
from flask_cors import CORS
import threading
import time

# Import our modules
from .mobile_security_tester import MobileSecurityTester
from .utils.config_manager import ConfigManager
from .utils.debug_utils import setup_debug_logging, debug_print

class MobileSecurityAPI:
    """Enhanced Mobile Security Testing API with scan ID management."""
    
    def __init__(self, debug: bool = False, port: int = 5001):
        """Initialize the API server."""
        self.app = Flask(__name__)
        CORS(self.app)
        self.debug = debug
        self.port = port
        
        # Scan sessions storage
        self.scan_sessions = {}
        self.scan_lock = threading.Lock()
        
        # Configuration
        self.config = ConfigManager()
        
        # Setup logging
        if debug:
            setup_debug_logging()
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Create report directories
        self._setup_directories()
        
        # Register routes
        self._register_routes()
        
    def _setup_directories(self):
        """Setup necessary directories for reports."""
        directories = [
            "reports/api",
            "reports/cli",
            "uploads",
            "logs"
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def _register_routes(self):
        """Register API routes."""
        
        @self.app.route('/api/v1/health', methods=['GET'])
        def health_check():
            """Health check endpoint."""
            return jsonify({
                "status": "healthy",
                "service": "Mobile Security Testing API",
                "version": "2.0.0",
                "timestamp": datetime.now().isoformat()
            })
        
        @self.app.route('/api/v1/scan', methods=['POST'])
        def start_scan():
            """Start a new mobile security scan."""
            try:
                data = request.get_json() or {}
                
                # Validate required fields
                if 'file_path' not in data and 'device_type' not in data:
                    return jsonify({
                        "error": "Missing required field: file_path or device_type"
                    }), 400
                
                # Generate scan ID
                scan_id = str(uuid.uuid4())
                
                # Create scan session
                scan_session = {
                    "scan_id": scan_id,
                    "status": "queued",
                    "created_at": datetime.now().isoformat(),
                    "request_data": data,
                    "results": None,
                    "report_path": None,
                    "error": None
                }
                
                with self.scan_lock:
                    self.scan_sessions[scan_id] = scan_session
                
                # Start scan in background thread
                threading.Thread(
                    target=self._run_scan,
                    args=(scan_id, data),
                    daemon=True
                ).start()
                
                return jsonify({
                    "scan_id": scan_id,
                    "status": "queued",
                    "message": "Scan started successfully"
                }), 202
                
            except Exception as e:
                debug_print(f"Error starting scan: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/v1/scan/<scan_id>/status', methods=['GET'])
        def get_scan_status(scan_id):
            """Get scan status and results."""
            try:
                with self.scan_lock:
                    if scan_id not in self.scan_sessions:
                        return jsonify({"error": "Scan not found"}), 404
                    
                    session = self.scan_sessions[scan_id]
                    
                    response = {
                        "scan_id": scan_id,
                        "status": session["status"],
                        "created_at": session["created_at"],
                        "request_data": session["request_data"]
                    }
                    
                    if session["status"] == "completed":
                        response["results"] = session["results"]
                        response["report_path"] = session["report_path"]
                    elif session["status"] == "failed":
                        response["error"] = session["error"]
                    
                    return jsonify(response)
                    
            except Exception as e:
                debug_print(f"Error getting scan status: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/v1/scan/<scan_id>/report', methods=['GET'])
        def get_scan_report(scan_id):
            """Get scan report file."""
            try:
                with self.scan_lock:
                    if scan_id not in self.scan_sessions:
                        return jsonify({"error": "Scan not found"}), 404
                    
                    session = self.scan_sessions[scan_id]
                    
                    if session["status"] != "completed":
                        return jsonify({"error": "Scan not completed"}), 400
                    
                    if not session["report_path"] or not os.path.exists(session["report_path"]):
                        return jsonify({"error": "Report file not found"}), 404
                    
                    return send_file(
                        session["report_path"],
                        as_attachment=True,
                        download_name=f"mobile_scan_report_{scan_id}.html"
                    )
                    
            except Exception as e:
                debug_print(f"Error getting scan report: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/v1/scans', methods=['GET'])
        def list_scans():
            """List all scans."""
            try:
                with self.scan_lock:
                    scans = []
                    for scan_id, session in self.scan_sessions.items():
                        scans.append({
                            "scan_id": scan_id,
                            "status": session["status"],
                            "created_at": session["created_at"],
                            "file_path": session["request_data"].get("file_path"),
                            "device_type": session["request_data"].get("device_type")
                        })
                    
                    return jsonify({
                        "scans": scans,
                        "total": len(scans)
                    })
                    
            except Exception as e:
                debug_print(f"Error listing scans: {str(e)}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/v1/scan/<scan_id>/dashboard', methods=['GET'])
        def get_scan_dashboard(scan_id):
            """Get interactive dashboard report for a scan."""
            try:
                with self.scan_lock:
                    if scan_id not in self.scan_sessions:
                        return jsonify({"error": "Scan not found"}), 404
                    
                    session = self.scan_sessions[scan_id]
                    
                    if session["status"] != "completed":
                        return jsonify({"error": "Scan not completed"}), 400
                    
                    if not session["results"]:
                        return jsonify({"error": "No results available"}), 404
                    
                    # Generate dashboard report
                    dashboard_path = f"reports/api/dashboard_{scan_id}.html"
                    tester = MobileSecurityTester(debug=self.debug)
                    tester.results = session["results"]
                    dashboard_file = tester.generate_report(
                        output_file=dashboard_path,
                        format="dashboard"
                    )
                    
                    return send_file(
                        dashboard_file,
                        as_attachment=True,
                        download_name=f"dashboard_report_{scan_id}.html"
                    )
                    
            except Exception as e:
                debug_print(f"Error generating dashboard: {str(e)}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/v1/batch-scan', methods=['POST'])
        def start_batch_scan():
            """Start batch scan for multiple files."""
            try:
                data = request.get_json() or {}
                
                if 'files' not in data or not isinstance(data['files'], list):
                    return jsonify({
                        "error": "Missing or invalid 'files' array"
                    }), 400
                
                batch_id = str(uuid.uuid4())
                batch_results = {
                    "batch_id": batch_id,
                    "status": "processing",
                    "created_at": datetime.now().isoformat(),
                    "total_files": len(data['files']),
                    "completed_files": 0,
                    "failed_files": 0,
                    "results": {},
                    "summary": {
                        "total_vulnerabilities": 0,
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0
                    }
                }
                
                with self.scan_lock:
                    self.scan_sessions[batch_id] = batch_results
                
                # Start batch processing in background
                threading.Thread(
                    target=self._run_batch_scan,
                    args=(batch_id, data['files'], data.get('tests', ['static', 'network', 'storage', 'code'])),
                    daemon=True
                ).start()
                
                return jsonify({
                    "batch_id": batch_id,
                    "status": "processing",
                    "total_files": len(data['files']),
                    "message": "Batch scan started successfully"
                }), 202
                
            except Exception as e:
                debug_print(f"Error starting batch scan: {str(e)}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/v1/ai-analysis', methods=['POST'])
        def ai_analysis():
            """Perform AI-powered analysis on existing scan results."""
            try:
                data = request.get_json() or {}
                
                if 'scan_id' not in data:
                    return jsonify({
                        "error": "Missing required field: scan_id"
                    }), 400
                
                scan_id = data['scan_id']
                
                with self.scan_lock:
                    if scan_id not in self.scan_sessions:
                        return jsonify({"error": "Scan not found"}), 404
                    
                    session = self.scan_sessions[scan_id]
                    
                    if session["status"] != "completed":
                        return jsonify({"error": "Scan not completed"}), 400
                
                # Perform AI analysis
                from .ai.vulnerability_detector import AIVulnerabilityDetector
                ai_detector = AIVulnerabilityDetector()
                ai_results = ai_detector.analyze(session["results"])
                
                return jsonify({
                    "scan_id": scan_id,
                    "ai_analysis": ai_results,
                    "timestamp": datetime.now().isoformat()
                })
                
            except Exception as e:
                debug_print(f"Error performing AI analysis: {str(e)}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/v1/stats', methods=['GET'])
        def get_stats():
            """Get API statistics and summary."""
            try:
                with self.scan_lock:
                    total_scans = len(self.scan_sessions)
                    completed_scans = sum(1 for s in self.scan_sessions.values() 
                                        if s.get("status") == "completed")
                    failed_scans = sum(1 for s in self.scan_sessions.values() 
                                     if s.get("status") == "failed")
                    processing_scans = sum(1 for s in self.scan_sessions.values() 
                                         if s.get("status") in ["queued", "processing"])
                    
                    # Calculate vulnerability statistics
                    total_vulns = 0
                    critical_vulns = 0
                    high_vulns = 0
                    medium_vulns = 0
                    low_vulns = 0
                    
                    for session in self.scan_sessions.values():
                        if session.get("results") and "vulnerabilities" in session["results"]:
                            vulns = session["results"]["vulnerabilities"]
                            total_vulns += len(vulns)
                            for vuln in vulns:
                                severity = vuln.get("severity", "low").lower()
                                if severity == "critical":
                                    critical_vulns += 1
                                elif severity == "high":
                                    high_vulns += 1
                                elif severity == "medium":
                                    medium_vulns += 1
                                else:
                                    low_vulns += 1
                    
                    return jsonify({
                        "api_stats": {
                            "total_scans": total_scans,
                            "completed_scans": completed_scans,
                            "failed_scans": failed_scans,
                            "processing_scans": processing_scans,
                            "success_rate": (completed_scans / total_scans * 100) if total_scans > 0 else 0
                        },
                        "vulnerability_stats": {
                            "total_vulnerabilities": total_vulns,
                            "critical": critical_vulns,
                            "high": high_vulns,
                            "medium": medium_vulns,
                            "low": low_vulns
                        },
                        "timestamp": datetime.now().isoformat()
                    })
                    
            except Exception as e:
                debug_print(f"Error getting stats: {str(e)}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/v1/scan/<scan_id>', methods=['DELETE'])
        def delete_scan(scan_id):
            """Delete a scan and its results."""
            try:
                with self.scan_lock:
                    if scan_id not in self.scan_sessions:
                        return jsonify({"error": "Scan not found"}), 404
                    
                    # Clean up report files
                    session = self.scan_sessions[scan_id]
                    if session.get("report_path") and os.path.exists(session["report_path"]):
                        os.remove(session["report_path"])
                    
                    # Remove session
                    del self.scan_sessions[scan_id]
                    
                    return jsonify({
                        "message": "Scan deleted successfully",
                        "scan_id": scan_id
                    })
                    
            except Exception as e:
                debug_print(f"Error deleting scan: {str(e)}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/v1/clear', methods=['POST'])
        def clear_scans():
            """Clear all scans and results."""
            try:
                with self.scan_lock:
                    # Clean up all report files
                    for session in self.scan_sessions.values():
                        if session.get("report_path") and os.path.exists(session["report_path"]):
                            os.remove(session["report_path"])
                    
                    # Clear all sessions
                    self.scan_sessions.clear()
                    
                    return jsonify({
                        "message": "All scans cleared successfully",
                        "cleared_count": len(self.scan_sessions)
                    })
                    
            except Exception as e:
                debug_print(f"Error clearing scans: {str(e)}")
                return jsonify({"error": str(e)}), 500
    
    def _run_scan(self, scan_id: str, data: Dict[str, Any]):
        """Run scan in background thread."""
        try:
            with self.scan_lock:
                self.scan_sessions[scan_id]["status"] = "running"
            
            debug_print(f"Starting scan {scan_id} with data: {data}")
            
            # Initialize tester
            tester = MobileSecurityTester(debug=self.debug)
            
            # Determine scan type and parameters
            file_path = data.get("file_path")
            device_type = data.get("device_type")
            tests = data.get("tests", ["static", "network", "storage", "code"])
            package_name = data.get("package_name")
            
            # Run appropriate analysis
            if file_path:
                if file_path.lower().endswith('.apk'):
                    results = tester.analyze_apk(file_path, tests)
                elif file_path.lower().endswith('.ipa'):
                    results = tester.analyze_ipa(file_path, tests)
                else:
                    raise ValueError(f"Unsupported file type: {file_path}")
            elif device_type:
                results = tester.analyze_device(device_type, package_name)
            else:
                raise ValueError("Either file_path or device_type must be provided")
            
            # Generate report with API naming convention
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"api_scan_{scan_id}_{timestamp}.html"
            report_path = f"reports/api/{report_filename}"
            
            report_file = tester.generate_report(report_path, "html")
            
            # Update session
            with self.scan_lock:
                self.scan_sessions[scan_id]["status"] = "completed"
                self.scan_sessions[scan_id]["results"] = results
                self.scan_sessions[scan_id]["report_path"] = report_file
            
            debug_print(f"Scan {scan_id} completed successfully")
            
        except Exception as e:
            debug_print(f"Error in scan {scan_id}: {str(e)}")
            with self.scan_lock:
                self.scan_sessions[scan_id]["status"] = "failed"
                self.scan_sessions[scan_id]["error"] = str(e)
    
    def _run_batch_scan(self, batch_id: str, files: List[str], tests: List[str]):
        """Run batch scan in background thread."""
        try:
            with self.scan_lock:
                self.scan_sessions[batch_id]["status"] = "processing"
            
            debug_print(f"Starting batch scan {batch_id} with {len(files)} files")
            
            # Initialize tester
            tester = MobileSecurityTester(debug=self.debug)
            batch_results = {}
            total_vulns = 0
            critical_vulns = 0
            high_vulns = 0
            medium_vulns = 0
            low_vulns = 0
            
            for i, file_path in enumerate(files):
                try:
                    debug_print(f"Processing file {i+1}/{len(files)}: {file_path}")
                    
                    # Update progress
                    with self.scan_lock:
                        self.scan_sessions[batch_id]["completed_files"] = i
                    
                    # Run analysis
                    if file_path.lower().endswith('.apk'):
                        results = tester.analyze_apk(file_path, tests)
                    elif file_path.lower().endswith('.ipa'):
                        results = tester.analyze_ipa(file_path, tests)
                    else:
                        debug_print(f"Skipping unsupported file: {file_path}")
                        continue
                    
                    # Store results
                    batch_results[file_path] = results
                    
                    # Update vulnerability counts
                    vulns = results.get("vulnerabilities", [])
                    total_vulns += len(vulns)
                    for vuln in vulns:
                        severity = vuln.get("severity", "low").lower()
                        if severity == "critical":
                            critical_vulns += 1
                        elif severity == "high":
                            high_vulns += 1
                        elif severity == "medium":
                            medium_vulns += 1
                        else:
                            low_vulns += 1
                    
                    # Update progress
                    with self.scan_lock:
                        self.scan_sessions[batch_id]["completed_files"] = i + 1
                    
                except Exception as e:
                    debug_print(f"Error processing file {file_path}: {str(e)}")
                    with self.scan_lock:
                        self.scan_sessions[batch_id]["failed_files"] += 1
            
            # Generate batch report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            batch_report_filename = f"batch_scan_{batch_id}_{timestamp}.html"
            batch_report_path = f"reports/api/{batch_report_filename}"
            
            # Create batch summary
            batch_summary = {
                "batch_id": batch_id,
                "total_files": len(files),
                "completed_files": len(batch_results),
                "failed_files": len(files) - len(batch_results),
                "vulnerability_summary": {
                    "total_vulnerabilities": total_vulns,
                    "critical": critical_vulns,
                    "high": high_vulns,
                    "medium": medium_vulns,
                    "low": low_vulns
                },
                "results": batch_results,
                "timestamp": datetime.now().isoformat()
            }
            
            # Save batch report
            with open(batch_report_path, 'w', encoding='utf-8') as f:
                json.dump(batch_summary, f, indent=2, ensure_ascii=False)
            
            # Update session
            with self.scan_lock:
                self.scan_sessions[batch_id]["status"] = "completed"
                self.scan_sessions[batch_id]["results"] = batch_summary
                self.scan_sessions[batch_id]["report_path"] = batch_report_path
                self.scan_sessions[batch_id]["summary"] = batch_summary["vulnerability_summary"]
            
            debug_print(f"Batch scan {batch_id} completed successfully")
            
        except Exception as e:
            debug_print(f"Error in batch scan {batch_id}: {str(e)}")
            with self.scan_lock:
                self.scan_sessions[batch_id]["status"] = "failed"
                self.scan_sessions[batch_id]["error"] = str(e)
    
    def run(self, host: str = '0.0.0.0', port: int = None, debug: bool = None):
        """Run the API server."""
        if port is None:
            port = self.port
        if debug is None:
            debug = self.debug
            
        print(f"🚀 Starting Mobile Security Testing API on {host}:{port}")
        print(f"📚 API Documentation: http://{host}:{port}/api/v1/health")
        print(f"🔍 Debug mode: {'enabled' if debug else 'disabled'}")
        
        self.app.run(host=host, port=port, debug=debug)

def main():
    """Main function to run the API server."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Mobile Security Testing API")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5001, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    # Check for environment variable
    port = int(os.getenv('MOBILE_API_PORT', args.port))
    
    api = MobileSecurityAPI(debug=args.debug, port=port)
    api.run(host=args.host, port=port, debug=args.debug)

if __name__ == "__main__":
    main() 