#!/usr/bin/env python3
"""
API Security Scanner - Web UI
A web-based interface for running API security scans independently
"""

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
import sys
import os
# Fix the path to properly import from the project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
import json
import tempfile
import time
from datetime import datetime
import threading
import queue

# Only import ReportLab for PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("⚠ ReportLab not available. PDF generation will be disabled.")

# Remove problematic import and create fallbacks
# from debug_utils import get_debug_summary, export_debug_data
def get_debug_summary():
    """Get comprehensive debug and diagnostic summary"""
    import psutil
    import threading
    from datetime import datetime
    
    try:
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Process metrics
        process = psutil.Process()
        process_memory = process.memory_info()
        process_cpu = process.cpu_percent()
        
        # Thread information
        active_threads = threading.active_count()
        
        # Application metrics
        app_metrics = {
            'current_cpu': cpu_percent,
            'current_memory': memory.percent,
            'current_threads': active_threads,
            'monitoring_duration': f"{int(time.time())} seconds"
        }
        
        # Debug stats
        debug_stats = {
            'request_count': len(scan_results),
            'error_count': 0,  # Could be enhanced to track actual errors
            'active_scans': len([s for s in scan_results.values() if s.get('status') == 'running']),
            'completed_scans': len([s for s in scan_results.values() if s.get('status') == 'completed']),
            'failed_scans': len([s for s in scan_results.values() if s.get('status') == 'failed'])
        }
        
        # System diagnostics
        system_diagnostics = {
            'platform': psutil.sys.platform,
            'python_version': sys.version,
            'process_id': process.pid,
            'process_uptime': time.time() - process.create_time(),
            'memory_usage_mb': process_memory.rss / 1024 / 1024,
            'cpu_usage_percent': process_cpu
        }
        
        return {
            'metrics_summary': app_metrics,
            'debug_stats': debug_stats,
            'diagnostics': {
                'summary': system_diagnostics,
                'timestamp': datetime.now().isoformat(),
                'scan_manager_status': 'active' if 'scan_manager' in globals() else 'inactive',
                'scan_queue_size': scan_queue.qsize() if 'scan_queue' in globals() else 0,
                'scan_progress_count': len(scan_progress) if 'scan_progress' in globals() else 0
            }
        }
    except Exception as e:
        return {
            'error': f'Failed to get diagnostics: {str(e)}',
            'metrics_summary': {'current_cpu': 'N/A', 'current_memory': 'N/A', 'current_threads': 'N/A'},
            'debug_stats': {'request_count': 0, 'error_count': 0, 'active_scans': 0, 'completed_scans': 0, 'failed_scans': 0},
            'diagnostics': {'summary': {'error': str(e)}, 'timestamp': datetime.now().isoformat()}
        }

def export_debug_data():
    """Export debug data to a file"""
    try:
        # Get project root directory (2 levels up from src/web/)
        project_root = Path(__file__).parent.parent.parent
        debug_file = project_root / 'logs' / f'debug_export_{int(time.time())}.json'
        
        debug_data = get_debug_summary()
        debug_data['export_timestamp'] = datetime.now().isoformat()
        
        with open(debug_file, 'w', encoding='utf-8') as f:
            json.dump(debug_data, f, indent=2, default=str)
        
        return {'success': True, 'file': str(debug_file)}
    except Exception as e:
        return {'success': False, 'error': str(e)}

from werkzeug.utils import secure_filename
import requests
import yaml
from pathlib import Path

# Import debugging framework
try:
    from debug_config import (
        debug_logger, debug_decorator, debug_method, DebugContext,
        track_request, track_scan, track_auth, track_api,
        debug_log, info_log, error_log
    )
except ImportError:
    try:
        from src.config.debug_config import (
            debug_logger, debug_decorator, debug_method, DebugContext,
            track_request, track_scan, track_auth, track_api,
            debug_log, info_log, error_log
        )
    except ImportError:
        # Fallback debug functions
        def debug_logger(func):
            return func
        def debug_decorator(func):
            return func
        def debug_method(func):
            return func
        class DebugContext:
            def __init__(self, name, **kwargs):
                self.name = name
                self.kwargs = kwargs
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc_val, exc_tb):
                pass
        def track_request(*args, **kwargs):
            pass
        def track_scan(*args, **kwargs):
            pass
        def track_auth(*args, **kwargs):
            pass
        def track_api(*args, **kwargs):
            pass
        def debug_log(*args, **kwargs):
            pass
        def info_log(*args, **kwargs):
            pass
        def error_log(*args, **kwargs):
            pass

# Import API Security Scanner
try:
    from src.core.api_security_scanner import APISecurityScanner
    print("✓ Successfully imported APISecurityScanner from src.core.api_security_scanner")
except ImportError as e:
    print(f"✗ Failed to import from src.core.api_security_scanner: {e}")
    try:
        from src.core.api_security_scanner import APISecurityScanner
        print("✓ Successfully imported APISecurityScanner from src.core.api_security_scanner")
    except ImportError as e2:
        print(f"✗ Failed to import from src.core.api_security_scanner: {e2}")
        # Fallback class if scanner is not available
        class APISecurityScanner:
            def __init__(self, **kwargs):
                pass
            def scan_api_endpoints(self, endpoints):
                return {"status": "scanner_not_available"}
            def generate_api_security_report(self, results):
                return "report_not_available"
            def generate_owasp_report(self, results, format='html'):
                return "owasp_report_not_available"
            def set_auth_config(self, auth_config):
                pass
            def upload_and_scan_collection(self, file_path, base_url=None, auth_config=None):
                return {"status": "scanner_not_available", "error": "Scanner not available"}
            def scan_from_swagger_url(self, swagger_url, base_url=None, auth_config=None):
                return {"status": "scanner_not_available", "error": "Scanner not available"}
            def scan_from_json_file(self, json_file_path, base_url, auth_config=None):
                return {"status": "scanner_not_available", "error": "Scanner not available"}
        print("⚠ Using fallback APISecurityScanner class")

app = Flask(__name__)

# Global variables for scan management
scan_queue = queue.Queue()
scan_results = {}
scan_progress = {}  # Track progress for each scan
current_scan = None

def load_existing_scans():
    """Load existing scan results from reports directory - Enhanced for script-generated reports"""
    global scan_results
    
    try:
        # Get project root directory (2 levels up from src/web/)
        project_root = Path(__file__).parent.parent.parent
        reports_dir = project_root / 'reports'
        
        if not reports_dir.exists():
            return
        
        # Look for JSON reports in multiple locations
        json_report_patterns = [
            reports_dir.glob('api_security_scan_*.json'),
            reports_dir.glob('vulnerable_api_scan_*.json'),
            (reports_dir / 'json').glob('api_security_scan_*.json') if (reports_dir / 'json').exists() else []
        ]
        
        for pattern in json_report_patterns:
            for json_file in pattern:
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                    
                    # Extract scan ID from filename - handle both single and double "scan" patterns
                    filename = json_file.stem
                    if filename.startswith('api_security_scan_scan_'):
                        # Handle double "scan" pattern: api_security_scan_scan_1750596638
                        scan_id = filename.replace('api_security_scan_scan_', '')
                    elif filename.startswith('api_security_scan_'):
                        # Handle single "scan" pattern: api_security_scan_1750596638
                        scan_id = filename.replace('api_security_scan_', '')
                    elif filename.startswith('vulnerable_api_scan_'):
                        # Handle vulnerable API pattern
                        scan_id = filename.replace('vulnerable_api_scan_', '')
                    else:
                        # Skip files that don't match expected patterns
                        continue
                    
                    # Skip if already loaded
                    if scan_id in scan_results:
                        continue
                    
                    # Find corresponding HTML report
                    html_report = None
                    html_patterns = [
                        reports_dir / f'owasp_api_scan_{scan_id}.html',
                        reports_dir / f'vulnerable_api_owasp_{scan_id}.html',
                        (reports_dir / 'html') / f'owasp_api_report_{scan_id}.html' if (reports_dir / 'html').exists() else None
                    ]
                    
                    for html_pattern in html_patterns:
                        if html_pattern and html_pattern.exists():
                            html_report = str(html_pattern)
                            break
                    
                    # Create scan result entry
                    scan_results[scan_id] = {
                        'id': scan_id,
                        'status': 'completed',
                        'scan_type': report_data.get('scan_type', 'unknown'),
                        'start_time': report_data.get('scan_start_time', ''),
                        'end_time': report_data.get('scan_end_time', ''),
                        'endpoints_scanned': report_data.get('endpoints_scanned', report_data.get('endpoints_found', 0)),
                        'vulnerabilities_found': len(report_data.get('vulnerabilities_found', [])),
                        'reports': {
                            'standard_report': str(json_file),
                            'owasp_report': html_report or str(reports_dir / f'owasp_api_scan_{scan_id}.html')
                        },
                        'results': report_data
                    }
                    
                    debug_log("Loaded existing scan", scan_id=scan_id, file=str(json_file))
                    
                except Exception as e:
                    error_log("Failed to load scan report", file=str(json_file), error=str(e))
                    continue
        
        debug_log("Loaded existing scans", count=len(scan_results))
        
    except Exception as e:
        error_log("Error loading existing scans", error=str(e))

class ScanManager:
    """Manages API security scans with debugging support"""
    
    def __init__(self):
        debug_log("Initializing ScanManager")
        self.scanner = APISecurityScanner()
        self.scan_history = []
        debug_log("ScanManager initialized successfully")
    
    def _progress_callback(self, scan_id, progress_data):
        """Callback function to update scan progress"""
        scan_progress[scan_id] = progress_data
        debug_log("Progress update", scan_id=scan_id, progress=progress_data)
    
    @debug_method
    def run_scan(self, scan_config):
        """Run a security scan with the given configuration"""
        scan_id = scan_config.get('id', f"scan_{int(time.time())}")
        track_scan(scan_id, scan_config.get('scan_type', 'unknown'), "started")
        
        with DebugContext("run_scan", scan_id=scan_id, scan_type=scan_config.get('scan_type')):
            try:
                debug_log("Starting scan", scan_id=scan_id, scan_type=scan_config.get('scan_type'))
                
                scan_config['id'] = scan_id
                scan_config['status'] = 'running'
                scan_config['start_time'] = datetime.now().isoformat()
                
                # Initialize progress tracking
                scan_progress[scan_id] = {
                    'current': 0,
                    'total': 0,
                    'percentage': 0,
                    'current_endpoint': '',
                    'current_method': '',
                    'status': 'initializing'
                }
                
                # Set authentication if provided
                if scan_config.get('auth_type'):
                    auth_config = self._build_auth_config(scan_config)
                    self.scanner.set_auth_config(auth_config)
                    track_auth(scan_config['auth_type'], True)
                
                # Create scanner with progress callback
                progress_scanner = APISecurityScanner(
                    auth_config=auth_config if scan_config.get('auth_type') else None,
                    progress_callback=lambda progress: self._progress_callback(scan_id, progress)
                )
                
                # Run scan based on type
                scan_type = scan_config['scan_type']
                if scan_type == 'swagger_url':
                    results = progress_scanner.scan_from_swagger_url(
                        scan_config['swagger_url'],
                        scan_config.get('base_url'),
                        auth_config if scan_config.get('auth_type') else None
                    )
                elif scan_type == 'json_file':
                    results = progress_scanner.scan_from_json_file(
                        scan_config['json_file'],
                        scan_config.get('base_url'),
                        auth_config if scan_config.get('auth_type') else None
                    )
                elif scan_type == 'collection':
                    results = progress_scanner.upload_and_scan_collection(
                        scan_config['collection_file'],
                        scan_config.get('base_url'),
                        auth_config if scan_config.get('auth_type') else None
                    )
                else:
                    error_msg = f"Unsupported scan type: {scan_type}"
                    debug_log("Unsupported scan type", scan_type=scan_type)
                    scan_config['status'] = 'failed'
                    scan_config['error'] = error_msg
                    track_scan(scan_id, scan_type, "failed", error=error_msg)
                    return scan_config
                
                # Process scan results
                if 'error' not in results:
                    debug_log("Processing scan results", scan_id=scan_id)
                    
                    # Extract the actual scan results
                    if 'scan_results' in results:
                        actual_scan_results = results['scan_results']
                    else:
                        actual_scan_results = results
                    
                    # Generate reports
                    debug_log("Generating reports", scan_id=scan_id)
                    try:
                        report_file = progress_scanner.generate_api_security_report(actual_scan_results)
                        owasp_report = progress_scanner.generate_owasp_report(actual_scan_results, 'html')
                        
                        scan_config['status'] = 'completed'
                        scan_config['results'] = actual_scan_results
                        scan_config['reports'] = {
                            'standard_report': report_file,
                            'owasp_report': owasp_report
                        }
                        
                        # Update final progress
                        scan_progress[scan_id] = {
                            'current': actual_scan_results.get('endpoints_scanned', 0),
                            'total': actual_scan_results.get('endpoints_found', 0),
                            'percentage': 100,
                            'current_endpoint': '',
                            'current_method': '',
                            'status': 'completed'
                        }
                        
                        track_scan(scan_id, scan_type, "completed", 
                                 endpoint_count=actual_scan_results.get('endpoints_found', 0),
                                 vulnerability_count=len(actual_scan_results.get('vulnerabilities_found', [])))
                        
                        debug_log("Scan completed successfully", 
                                scan_id=scan_id, 
                                endpoints_scanned=actual_scan_results.get('endpoints_scanned', 0),
                                vulnerabilities_found=len(actual_scan_results.get('vulnerabilities_found', [])))
                        
                    except Exception as report_error:
                        error_log("Error generating reports", exception=report_error, scan_id=scan_id)
                        scan_config['status'] = 'completed_with_errors'
                        scan_config['error'] = f"Scan completed but report generation failed: {str(report_error)}"
                        scan_config['results'] = actual_scan_results
                        
                else:
                    scan_config['status'] = 'failed'
                    scan_config['error'] = results['error']
                    track_scan(scan_id, scan_type, "failed", error=results['error'])
                    error_log("Scan failed", error=results['error'], scan_id=scan_id)
                
                scan_config['end_time'] = datetime.now().isoformat()
                self.scan_history.append(scan_config)
                
                return scan_config
                
            except Exception as e:
                error_log("Error in run_scan", exception=e, scan_id=scan_id)
                scan_config['status'] = 'failed'
                scan_config['error'] = str(e)
                track_scan(scan_id, scan_config.get('scan_type', 'unknown'), "failed", error=str(e))
                return scan_config
    
    @debug_method
    def _build_auth_config(self, scan_config):
        """Build authentication configuration from scan config"""
        auth_type = scan_config['auth_type']
        debug_log("Building auth config", auth_type=auth_type)
        
        if auth_type == 'bearer':
            return {
                'type': 'bearer',
                'token': scan_config['bearer_token']
            }
        elif auth_type == 'apikey':
            return {
                'type': 'apikey',
                'key': scan_config['api_key_name'],
                'value': scan_config['api_key_value'],
                'location': scan_config.get('api_key_location', 'header')
            }
        elif auth_type == 'basic':
            return {
                'type': 'basic',
                'username': scan_config['basic_username'],
                'password': scan_config['basic_password']
            }
        elif auth_type == 'oauth2':
            return {
                'type': 'oauth2',
                'access_token': scan_config['oauth2_token']
            }
        elif auth_type == 'custom':
            headers = {}
            for i in range(5):  # Support up to 5 custom headers
                header_key = scan_config.get(f'custom_header_key_{i}')
                header_value = scan_config.get(f'custom_header_value_{i}')
                if header_key and header_value:
                    headers[header_key] = header_value
            
            return {
                'type': 'custom',
                'headers': headers
            }
        
        return {}

scan_manager = ScanManager()

@app.route('/')
def index():
    """Main page"""
    track_api('/', 'GET', 200)
    return render_template('index.html')

@app.route('/test')
def test_page():
    """Simple test page"""
    return send_file('simple_test.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    start_time = time.time()
    
    try:
        # Debug: Log the raw request data
        print("Raw request data:", request.get_data(as_text=True))
        print("Content-Type:", request.content_type)
        
        try:
            scan_config = request.json
        except Exception as json_error:
            print("JSON parsing error:", str(json_error))
            return jsonify({'error': f'Invalid JSON: {str(json_error)}'}), 400
        
        debug_log("Received scan request", scan_type=scan_config.get('scan_type'))
        
        # Generate unique scan ID
        scan_config['id'] = f"scan_{int(time.time())}"
        
        # Validate required fields
        if scan_config['scan_type'] == 'swagger_url':
            if not scan_config.get('swagger_url'):
                error_msg = 'Swagger URL is required'
                debug_log("Validation failed", error=error_msg)
                track_api('/api/scan', 'POST', 400)
                return jsonify({'error': error_msg}), 400
        elif scan_config['scan_type'] == 'json_file':
            if not scan_config.get('json_file'):
                error_msg = 'JSON file is required'
                debug_log("Validation failed", error=error_msg)
                track_api('/api/scan', 'POST', 400)
                return jsonify({'error': error_msg}), 400
        elif scan_config['scan_type'] == 'collection':
            if not scan_config.get('collection_file'):
                error_msg = 'Collection file is required'
                debug_log("Validation failed", error=error_msg)
                track_api('/api/scan', 'POST', 400)
                return jsonify({'error': error_msg}), 400
        
        # Run scan in background
        def run_scan_async():
            with DebugContext("async_scan", scan_id=scan_config['id']):
                result = scan_manager.run_scan(scan_config)
                # Ensure we store with the correct scan ID that was generated
                scan_id = scan_config['id']
                scan_results[scan_id] = result
                
                # Also add to scan history for consistency
                scan_history_entry = {
                    'id': scan_id,
                    'scan_type': result.get('scan_type', 'unknown'),
                    'status': result.get('scan_status', 'unknown'),
                    'start_time': result.get('scan_start_time', ''),
                    'end_time': result.get('scan_end_time', ''),
                    'endpoints_scanned': result.get('endpoints_scanned', 0),
                    'vulnerabilities_found': len(result.get('vulnerabilities_found', [])),
                    'scan_duration': result.get('scan_duration', 0)
                }
                scan_manager.scan_history.append(scan_history_entry)
        
        thread = threading.Thread(target=run_scan_async)
        thread.start()
        
        duration = time.time() - start_time
        track_request("POST", "/api/scan", 200, duration)
        
        return jsonify({
            'scan_id': scan_config['id'],
            'status': 'started',
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        duration = time.time() - start_time
        error_log("Error in start_scan", exception=e)
        track_request("POST", "/api/scan", 500, duration)
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>')
def get_scan_status(scan_id):
    """Get scan status and results"""
    start_time = time.time()
    
    try:
        if scan_id in scan_results:
            duration = time.time() - start_time
            track_request("GET", f"/api/scan/{scan_id}", 200, duration)
            return jsonify(scan_results[scan_id])
        else:
            # Provide more helpful error message with available scan IDs
            available_scans = list(scan_results.keys())
            error_response = {
                'error': 'Scan not found',
                'scan_id': scan_id,
                'available_scans': available_scans,
                'total_available_scans': len(available_scans),
                'message': f'Scan {scan_id} not found. Available scans: {available_scans[:5]}...' if len(available_scans) > 5 else f'Available scans: {available_scans}',
                'debug_info': {
                    'scan_results_keys': list(scan_results.keys()),
                    'scan_progress_keys': list(scan_progress.keys()),
                    'scan_history_count': len(scan_manager.scan_history)
                }
            }
            
            duration = time.time() - start_time
            track_request("GET", f"/api/scan/{scan_id}", 404, duration)
            return jsonify(error_response), 404
    except Exception as e:
        duration = time.time() - start_time
        error_log("Error in get_scan_status", exception=e, scan_id=scan_id)
        track_request("GET", f"/api/scan/{scan_id}", 500, duration)
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/progress')
def get_scan_progress(scan_id):
    """Get real-time scan progress"""
    start_time = time.time()
    
    try:
        if scan_id in scan_progress:
            duration = time.time() - start_time
            track_request("GET", f"/api/scan/{scan_id}/progress", 200, duration)
            return jsonify(scan_progress[scan_id])
        else:
            duration = time.time() - start_time
            track_request("GET", f"/api/scan/{scan_id}/progress", 404, duration)
            return jsonify({'error': 'Progress not found'}), 404
    except Exception as e:
        duration = time.time() - start_time
        error_log("Error in get_scan_progress", exception=e, scan_id=scan_id)
        track_request("GET", f"/api/scan/{scan_id}/progress", 500, duration)
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans')
def get_scan_history():
    """Get scan history"""
    start_time = time.time()
    
    try:
        # Combine data from both sources for better compatibility
        combined_history = []
        
        # Add scans from scan_results (current active scans)
        for scan_id, scan_data in scan_results.items():
            vulnerabilities_found = scan_data.get('vulnerabilities_found', [])
            if isinstance(vulnerabilities_found, list):
                vuln_count = len(vulnerabilities_found)
            else:
                vuln_count = int(vulnerabilities_found) if vulnerabilities_found else 0

            # Try to get fields from top-level, then from 'results', then fallback
            results = scan_data.get('results', {})
            combined_history.append({
                'id': scan_id,
                'scan_type': scan_data.get('scan_type') or results.get('scan_type', 'unknown'),
                'status': scan_data.get('scan_status') or scan_data.get('status') or results.get('scan_status', 'unknown'),
                'start_time': scan_data.get('scan_start_time') or scan_data.get('start_time') or results.get('scan_start_time', ''),
                'end_time': scan_data.get('scan_end_time') or scan_data.get('end_time') or results.get('scan_end_time', ''),
                'endpoints_scanned': scan_data.get('endpoints_scanned') or results.get('endpoints_scanned', 0),
                'vulnerabilities_found': vuln_count,
                'scan_duration': scan_data.get('scan_duration') or results.get('scan_duration', 0)
            })
        
        # Add scans from scan_manager.scan_history (historical scans)
        for scan_entry in scan_manager.scan_history:
            # Avoid duplicates
            if not any(entry['id'] == scan_entry['id'] for entry in combined_history):
                combined_history.append(scan_entry)
        
        # Sort by start time (newest first)
        combined_history.sort(key=lambda x: x.get('start_time', ''), reverse=True)
        
        duration = time.time() - start_time
        track_request("GET", "/api/scans", 200, duration)
        return jsonify(combined_history)
    except Exception as e:
        duration = time.time() - start_time
        error_log("Error in get_scan_history", exception=e)
        track_request("GET", "/api/scans", 500, duration)
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/scans')
def debug_scans():
    """Debug endpoint to show all available scans"""
    try:
        return jsonify({
            'scan_results_keys': list(scan_results.keys()),
            'scan_results_count': len(scan_results),
            'scan_progress_keys': list(scan_progress.keys()),
            'scan_progress_count': len(scan_progress),
            'scan_history_count': len(scan_manager.scan_history),
            'available_scans': [
                {
                    'id': scan_id,
                    'status': scan_data.get('status', 'unknown'),
                    'scan_type': scan_data.get('scan_type', 'unknown'),
                    'start_time': scan_data.get('start_time', ''),
                    'endpoints_scanned': scan_data.get('endpoints_scanned', 0),
                    'vulnerabilities_found': scan_data.get('vulnerabilities_found', 0)
                }
                for scan_id, scan_data in scan_results.items()
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<scan_id>/<report_type>')
def download_report(scan_id, report_type):
    """Download scan report - Enhanced to handle script-generated reports"""
    start_time = time.time()
    
    try:
        # Get project root directory (2 levels up from src/web/)
        project_root = Path(__file__).parent.parent.parent
        reports_dir = project_root / 'reports'
        
        # Define possible report file locations and patterns
        report_file = None
        
        if report_type == 'standard':
            # Look for JSON reports in multiple locations with both single and double "scan" patterns
            possible_locations = [
                reports_dir / f"api_security_scan_{scan_id}.json",
                reports_dir / f"api_security_scan_scan_{scan_id}.json",  # Handle double "scan" pattern
                reports_dir / "json" / f"api_security_scan_{scan_id}.json",
                reports_dir / "json" / f"api_security_scan_scan_{scan_id}.json",  # Handle double "scan" pattern
                reports_dir / f"vulnerable_api_scan_{scan_id}.json"
            ]
            
            for location in possible_locations:
                if os.path.exists(location):
                    report_file = location
                    break
                    
        elif report_type == 'owasp':
            # Look for HTML reports in multiple locations
            possible_locations = [
                reports_dir / f"owasp_api_scan_{scan_id}.html",
                reports_dir / "html" / f"owasp_api_report_{scan_id}.html",
                reports_dir / f"vulnerable_api_owasp_{scan_id}.html"
            ]
            
            for location in possible_locations:
                if os.path.exists(location):
                    report_file = location
                    break
        
        # If not found by scan_id, try to find by timestamp pattern
        if not report_file and report_type == 'standard':
            # Look for any JSON report files
            json_files = list(reports_dir.glob("**/*.json"))
            for json_file in json_files:
                if "api_security_scan" in json_file.name or "vulnerable_api_scan" in json_file.name:
                    report_file = json_file
                    break
                    
        elif not report_file and report_type == 'owasp':
            # Look for any HTML report files
            html_files = list(reports_dir.glob("**/*.html"))
            for html_file in html_files:
                if "owasp" in html_file.name:
                    report_file = html_file
                    break
        
        if report_file and os.path.exists(report_file):
            duration = time.time() - start_time
            track_request("GET", f"/api/report/{scan_id}/{report_type}", 200, duration)
            return send_file(str(report_file), as_attachment=True)
        else:
            duration = time.time() - start_time
            track_request("GET", f"/api/report/{scan_id}/{report_type}", 404, duration)
            return jsonify({'error': 'Report file not found'}), 404
            
    except Exception as e:
        duration = time.time() - start_time
        error_log("Error in download_report", exception=e, scan_id=scan_id, report_type=report_type)
        track_request("GET", f"/api/report/{scan_id}/{report_type}", 500, duration)
        return jsonify({'error': str(e)}), 500

def generate_pdf_from_json(json_data, scan_id):
    """Generate PDF from JSON data using ReportLab"""
    if not REPORTLAB_AVAILABLE:
        return None, "ReportLab not available"
    try:
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_pdf:
            temp_pdf_path = temp_pdf.name
        doc = SimpleDocTemplate(temp_pdf_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1
        )
        story.append(Paragraph(f"API Security Scan Report - {scan_id}", title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph("Scan Information", styles['Heading2']))
        story.append(Spacer(1, 12))
        scan_info_data = [
            ['Field', 'Value'],
            ['Scan ID', scan_id],
            ['Scan Type', json_data.get('scan_type', 'Unknown')],
            ['Start Time', json_data.get('scan_start_time', 'Unknown')],
            ['End Time', json_data.get('scan_end_time', 'Unknown')],
            ['Endpoints Scanned', str(json_data.get('endpoints_scanned', json_data.get('endpoints_found', 0)))],
            ['Vulnerabilities Found', str(len(json_data.get('vulnerabilities_found', [])))]
        ]
        scan_info_table = Table(scan_info_data, colWidths=[2*inch, 4*inch])
        scan_info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(scan_info_table)
        story.append(Spacer(1, 20))
        
        # Add endpoints list section
        endpoint_results = json_data.get('endpoint_results', [])
        if endpoint_results:
            story.append(Paragraph("Endpoints Scanned", styles['Heading2']))
            story.append(Spacer(1, 12))
            
            # Create endpoints table
            endpoints_data = [['#', 'Method', 'URL', 'Name', 'Status', 'Issues']]
            for i, endpoint_result in enumerate(endpoint_results, 1):
                endpoint = endpoint_result.get('endpoint', {})
                url = endpoint.get('url', 'N/A')
                method = endpoint.get('method', 'GET')
                name = endpoint.get('name', 'N/A')
                scan_status = endpoint_result.get('scan_status', 'unknown')
                
                # Count total issues for this endpoint
                total_issues = 0
                if 'vulnerabilities' in endpoint_result:
                    total_issues += len(endpoint_result['vulnerabilities'])
                if 'warnings' in endpoint_result:
                    total_issues += len(endpoint_result['warnings'])
                if 'performance_issues' in endpoint_result:
                    total_issues += len(endpoint_result['performance_issues'])
                if 'configuration_issues' in endpoint_result:
                    total_issues += len(endpoint_result['configuration_issues'])
                if 'connectivity_issues' in endpoint_result:
                    total_issues += len(endpoint_result['connectivity_issues'])
                if 'errors' in endpoint_result:
                    total_issues += len(endpoint_result['errors'])
                
                # Truncate URL if too long
                if len(url) > 50:
                    url = url[:47] + "..."
                
                endpoints_data.append([
                    str(i),
                    method,
                    url,
                    name[:30] + "..." if len(name) > 30 else name,
                    scan_status.upper(),
                    str(total_issues)
                ])
            
            # Create table with appropriate column widths
            endpoints_table = Table(endpoints_data, colWidths=[0.3*inch, 0.8*inch, 3*inch, 1.5*inch, 0.8*inch, 0.6*inch])
            endpoints_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(endpoints_table)
            story.append(Spacer(1, 20))
        
        vulnerabilities = json_data.get('vulnerabilities_found', [])
        if vulnerabilities:
            story.append(Paragraph("Vulnerabilities Found", styles['Heading2']))
            story.append(Spacer(1, 12))
            for i, vuln in enumerate(vulnerabilities[:10], 1):
                # Use 'type' field for vulnerability name (matches actual data structure)
                vuln_title = f"{i}. {vuln.get('type', 'Unknown Vulnerability')}"
                story.append(Paragraph(vuln_title, styles['Heading3']))
                story.append(Spacer(1, 6))
                vuln_desc = vuln.get('description', 'No description available')
                story.append(Paragraph(vuln_desc, styles['Normal']))
                story.append(Spacer(1, 6))
                severity = vuln.get('severity', 'Unknown')
                severity_color = colors.red if severity.lower() == 'high' else colors.orange if severity.lower() == 'medium' else colors.yellow
                story.append(Paragraph(f"Severity: {severity}", ParagraphStyle('Severity', textColor=severity_color)))
                story.append(Spacer(1, 6))
                # Add URL and method information
                url = vuln.get('url', 'N/A')
                method = vuln.get('method', 'N/A')
                story.append(Paragraph(f"Endpoint: {method} {url}", styles['Normal']))
                story.append(Spacer(1, 6))
                
                # Enhanced evidence section with request/response details
                story.append(Paragraph("Evidence:", styles['Heading4']))
                story.append(Spacer(1, 3))
                
                # Basic evidence
                evidence = vuln.get('evidence', 'No evidence available')
                story.append(Paragraph(f"Summary: {evidence}", styles['Normal']))
                story.append(Spacer(1, 6))
                
                # Request details
                request_data = vuln.get('request_data')
                if request_data:
                    story.append(Paragraph("Request Details:", styles['Heading4']))
                    story.append(Spacer(1, 3))
                    
                    # Request method and URL
                    req_method = request_data.get('method', 'N/A')
                    req_url = request_data.get('url', 'N/A')
                    story.append(Paragraph(f"Method: {req_method}", styles['Normal']))
                    story.append(Paragraph(f"URL: {req_url}", styles['Normal']))
                    
                    # Request headers
                    req_headers = request_data.get('headers', {})
                    if req_headers:
                        story.append(Paragraph("Headers:", styles['Normal']))
                        for header, value in list(req_headers.items())[:5]:  # Show first 5 headers
                            story.append(Paragraph(f"  {header}: {value}", styles['Normal']))
                        if len(req_headers) > 5:
                            story.append(Paragraph(f"  ... and {len(req_headers) - 5} more headers", styles['Normal']))
                    
                    # Request parameters/body
                    req_params = request_data.get('params')
                    if req_params:
                        story.append(Paragraph("Parameters:", styles['Normal']))
                        for param, value in req_params.items():
                            story.append(Paragraph(f"  {param}: {value}", styles['Normal']))
                    
                    req_json = request_data.get('json')
                    if req_json:
                        story.append(Paragraph("JSON Body:", styles['Normal']))
                        story.append(Paragraph(f"  {json.dumps(req_json, indent=2)}", styles['Normal']))
                    
                    story.append(Spacer(1, 6))
                
                # Response details
                response_data = vuln.get('response_data')
                if response_data:
                    story.append(Paragraph("Response Details:", styles['Heading4']))
                    story.append(Spacer(1, 3))
                    
                    # Response status
                    resp_status = response_data.get('status_code', 'N/A')
                    story.append(Paragraph(f"Status Code: {resp_status}", styles['Normal']))
                    
                    # Response headers
                    resp_headers = response_data.get('headers', {})
                    if resp_headers:
                        story.append(Paragraph("Response Headers:", styles['Normal']))
                        for header, value in list(resp_headers.items())[:5]:  # Show first 5 headers
                            story.append(Paragraph(f"  {header}: {value}", styles['Normal']))
                        if len(resp_headers) > 5:
                            story.append(Paragraph(f"  ... and {len(resp_headers) - 5} more headers", styles['Normal']))
                    
                    # Response content
                    resp_content = response_data.get('content', '')
                    if resp_content:
                        story.append(Paragraph("Response Content:", styles['Normal']))
                        # Truncate content if too long
                        if len(resp_content) > 500:
                            content_preview = resp_content[:500] + "... (truncated)"
                        else:
                            content_preview = resp_content
                        story.append(Paragraph(f"  {content_preview}", styles['Normal']))
                    
                    # Special handling for rate limiting tests
                    if 'responses' in response_data:
                        story.append(Paragraph("Rate Limiting Test Results:", styles['Normal']))
                        responses = response_data.get('responses', [])
                        for j, resp in enumerate(responses[:3]):  # Show first 3 responses
                            status = resp.get('status_code', 'N/A')
                            story.append(Paragraph(f"  Request {j+1}: Status {status}", styles['Normal']))
                        if len(responses) > 3:
                            story.append(Paragraph(f"  ... and {len(responses) - 3} more responses", styles['Normal']))
                    
                    # Special handling for HTTP methods tests
                    if 'method_results' in response_data:
                        story.append(Paragraph("HTTP Methods Test Results:", styles['Normal']))
                        method_results = response_data.get('method_results', [])
                        for method_result in method_results:
                            method_name = method_result.get('method', 'N/A')
                            status = method_result.get('status_code', 'N/A')
                            allowed = method_result.get('allowed', False)
                            story.append(Paragraph(f"  {method_name}: Status {status} ({'Allowed' if allowed else 'Blocked'})", styles['Normal']))
                    
                    story.append(Spacer(1, 6))
                
                # If no detailed request/response data, show basic evidence
                if not request_data and not response_data:
                    story.append(Paragraph(f"Evidence: {evidence}", styles['Normal']))
                
                story.append(Spacer(1, 12))
        doc.build(story)
        return temp_pdf_path, None
    except Exception as e:
        return None, str(e)

@app.route('/api/report/<scan_id>/view')
def view_report(scan_id):
    """View scan report in PDF format (ReportLab only)"""
    start_time = time.time()
    try:
        from pathlib import Path
        project_root = Path(__file__).parent.parent.parent
        reports_dir = project_root / 'reports'
        json_report = None
        json_patterns = [
            reports_dir / f"api_security_scan_{scan_id}.json",
            reports_dir / f"api_security_scan_scan_{scan_id}.json",
            reports_dir / "json" / f"api_security_scan_{scan_id}.json",
            reports_dir / "json" / f"api_security_scan_scan_{scan_id}.json",
            reports_dir / f"vulnerable_api_scan_{scan_id}.json"
        ]
        for json_pattern in json_patterns:
            if json_pattern and json_pattern.exists():
                json_report = json_pattern
                break
        if json_report:
            try:
                with open(json_report, 'r', encoding='utf-8') as f:
                    json_data = json.load(f)
                pdf_path, error = generate_pdf_from_json(json_data, scan_id)
                if pdf_path and not error:
                    duration = time.time() - start_time
                    response = send_file(pdf_path, as_attachment=False, download_name=f"api_security_report_{scan_id}.pdf")
                    def cleanup():
                        try:
                            os.unlink(pdf_path)
                        except:
                            pass
                    response.call_on_close(cleanup)
                    return response
                else:
                    return jsonify({'error': f'Failed to generate PDF: {error}'}), 500
            except Exception as e:
                return jsonify({'error': f'Error reading JSON report: {str(e)}'}), 500
        return jsonify({'error': 'Report not found or PDF generation failed'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload a collection file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file:
            filename = secure_filename(file.filename)
            timestamp = int(time.time())
            filename = f"upload_{timestamp}_{filename}"
            
            # Get project root directory (2 levels up from src/web/)
            project_root = Path(__file__).parent.parent.parent
            uploads_dir = project_root / 'uploads'
            uploads_dir.mkdir(exist_ok=True)
        
            file_path = uploads_dir / filename
            file.save(str(file_path))
        
        return jsonify({
                'success': True,
            'filename': filename,
                'filepath': str(file_path)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/test', methods=['POST'])
def test_authentication():
    """Test authentication configuration"""
    start_time = time.time()
    
    try:
        auth_config = request.json
        debug_log("Testing authentication", auth_type=auth_config.get('type'))
        
        # Create temporary scanner for testing
        test_scanner = APISecurityScanner()
        
        # Use the correct set_auth_config method
        test_scanner.set_auth_config(auth_config)
        
        # Test with a simple request
        test_url = "https://httpbin.org/get"
        try:
            response = test_scanner.session.get(test_url, timeout=10)
            if response.status_code == 200:
                duration = time.time() - start_time
                track_request("POST", "/api/auth/test", 200, duration)
                return jsonify({
                    'success': True,
                    'message': 'Authentication test successful'
                })
            else:
                duration = time.time() - start_time
                track_request("POST", "/api/auth/test", 400, duration)
                return jsonify({
                    'success': False,
                    'error': f'Request failed with status {response.status_code}'
                })
        except Exception as req_error:
            duration = time.time() - start_time
            track_request("POST", "/api/auth/test", 400, duration)
            return jsonify({
                'success': False,
                'error': f'Request failed: {str(req_error)}'
            })
        
    except Exception as e:
        duration = time.time() - start_time
        error_log("Error in test_authentication", exception=e)
        track_request("POST", "/api/auth/test", 500, duration)
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def get_logs():
    """Get the latest log lines (tail) or search logs"""
    # Get project root directory (2 levels up from src/web/)
    project_root = Path(__file__).parent.parent.parent
    log_file = project_root / 'logs' / 'api_scanner.log'
    lines = int(request.args.get('lines', 200))
    search = request.args.get('search', '').strip()
    result = []
    try:
        if not os.path.exists(log_file):
            return jsonify({'error': 'Log file not found'}), 404
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            all_lines = f.readlines()
            if search:
                filtered = [line for line in all_lines if search.lower() in line.lower()]
                result = filtered[-lines:] if lines > 0 else filtered
            else:
                result = all_lines[-lines:] if lines > 0 else all_lines
        return jsonify({'lines': result[::-1]})  # newest first
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/download')
def download_logs():
    """Download the full log file"""
    # Get project root directory (2 levels up from src/web/)
    project_root = Path(__file__).parent.parent.parent
    log_file = project_root / 'logs' / 'api_scanner.log'
    if not os.path.exists(log_file):
        return jsonify({'error': 'Log file not found'}), 404
    return send_file(log_file, as_attachment=True)

@app.route('/api/diagnostics')
def diagnostics_summary():
    """Get a summary of debug/diagnostic stats"""
    try:
        summary = get_debug_summary()
        return jsonify(summary)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/diagnostics/export', methods=['POST'])
def export_diagnostics():
    """Export all debug data and diagnostics"""
    try:
        export_debug_data()
        return jsonify({'success': True, 'message': 'Debug data exported to logs/'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/logs/clear', methods=['DELETE'])
def clear_logs():
    """Clear all log files"""
    try:
        # Get project root directory (2 levels up from src/web/)
        project_root = Path(__file__).parent.parent.parent
        logs_dir = project_root / 'logs'
        
        cleared_files = []
        if logs_dir.exists():
            # Clear main log file
            log_file = logs_dir / 'api_scanner.log'
            if log_file.exists():
                # Clear the file content but keep the file
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write(f"# Log cleared at {datetime.now().isoformat()}\n")
                cleared_files.append(str(log_file))
            
            # Clear debug export files
            for debug_file in logs_dir.glob('debug_export_*.json'):
                try:
                    os.remove(debug_file)
                    cleared_files.append(str(debug_file))
                except Exception as e:
                    error_log(f"Failed to delete debug file: {debug_file}", error=str(e))
        
        return jsonify({
            'success': True,
            'message': f'Cleared {len(cleared_files)} log files',
            'cleared_files': cleared_files
        })
    except Exception as e:
        error_log("Error clearing logs", exception=e)
        return jsonify({'error': str(e)}), 500

@app.route('/api/diagnostics/clear', methods=['DELETE'])
def clear_diagnostics():
    """Clear diagnostics data and reset counters"""
    try:
        # Reset global counters and data
        global scan_results, scan_progress, scan_queue
        
        # Clear scan progress
        scan_progress.clear()
        
        # Reset scan results (keep the structure but clear progress data)
        for scan_id in scan_results:
            if scan_results[scan_id].get('status') == 'running':
                scan_results[scan_id]['status'] = 'failed'
                scan_results[scan_id]['end_time'] = datetime.now().isoformat()
        
        # Clear debug export files
        project_root = Path(__file__).parent.parent.parent
        logs_dir = project_root / 'logs'
        cleared_files = []
        
        if logs_dir.exists():
            for debug_file in logs_dir.glob('debug_export_*.json'):
                try:
                    os.remove(debug_file)
                    cleared_files.append(str(debug_file))
                except Exception as e:
                    error_log(f"Failed to delete debug file: {debug_file}", error=str(e))
        
        return jsonify({
            'success': True,
            'message': 'Diagnostics data cleared and counters reset',
            'cleared_files': cleared_files,
            'reset_scans': len([s for s in scan_results.values() if s.get('status') == 'failed'])
        })
    except Exception as e:
        error_log("Error clearing diagnostics", exception=e)
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/delete', methods=['DELETE'])
def delete_logs():
    """Delete log files completely"""
    try:
        # Get project root directory (2 levels up from src/web/)
        project_root = Path(__file__).parent.parent.parent
        logs_dir = project_root / 'logs'
        
        deleted_files = []
        if logs_dir.exists():
            # Delete main log file
            log_file = logs_dir / 'api_scanner.log'
            if log_file.exists():
                os.remove(log_file)
                deleted_files.append(str(log_file))
            
            # Delete debug export files
            for debug_file in logs_dir.glob('debug_export_*.json'):
                try:
                    os.remove(debug_file)
                    deleted_files.append(str(debug_file))
                except Exception as e:
                    error_log(f"Failed to delete debug file: {debug_file}", error=str(e))
        
        return jsonify({
            'success': True,
            'message': f'Deleted {len(deleted_files)} log files',
            'deleted_files': deleted_files
        })
    except Exception as e:
        error_log("Error deleting logs", exception=e)
        return jsonify({'error': str(e)}), 500

def extract_all_endpoints_from_spec(spec, base_url=None):
    """Helper to extract all endpoints from a Swagger/OpenAPI spec, including nested/foldered ones."""
    # Try OpenAPI 3.0/3.1 or Swagger 2.0
    endpoints = []
    if 'paths' in spec:
        for path, methods in spec['paths'].items():
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                    endpoints.append({
                        'method': method.upper(),
                        'path': path,
                        'summary': details.get('summary', ''),
                        'description': details.get('description', ''),
                        'operationId': details.get('operationId', ''),
                        'tags': details.get('tags', []),
                        'base_url': base_url
                    })
    return endpoints

def extract_all_endpoints_from_postman(collection, parent_folder=""):
    """Recursively extract all endpoints from a Postman collection, including folders."""
    endpoints = []
    items = collection.get('item', [])
    for item in items:
        if 'item' in item:  # Folder
            folder_name = item.get('name', '')
            endpoints += extract_all_endpoints_from_postman(item, parent_folder + '/' + folder_name)
        else:
            request = item.get('request', {})
            method = request.get('method', 'GET')
            url = request.get('url', {})
            if isinstance(url, dict):
                path = url.get('raw', '')
            else:
                path = url
            endpoints.append({
                'method': method.upper(),
                'path': path,
                'summary': item.get('name', ''),
                'description': request.get('description', ''),
                'folder': parent_folder.strip('/'),
            })
    return endpoints

@app.route('/api/parse_endpoints', methods=['POST'])
def parse_endpoints():
    """Parse all endpoints from uploaded file or URL and return a flat list."""
    try:
        if 'file' in request.files:
            file = request.files['file']
            filename = secure_filename(file.filename)
            ext = filename.split('.')[-1].lower()
            content = file.read().decode('utf-8', errors='ignore')
            if ext == 'json':
                data = json.loads(content)
                # Detect Postman or OpenAPI
                if 'info' in data and 'item' in data:
                    endpoints = extract_all_endpoints_from_postman(data)
                else:
                    endpoints = extract_all_endpoints_from_spec(data)
            elif ext in ['yaml', 'yml']:
                data = yaml.safe_load(content)
                endpoints = extract_all_endpoints_from_spec(data)
            else:
                return jsonify({'error': 'Unsupported file type'}), 400
            return jsonify({'endpoints': endpoints})
        elif request.json and 'url' in request.json:
            url = request.json['url']
            resp = requests.get(url, timeout=30)
            if resp.status_code != 200:
                return jsonify({'error': f'Failed to fetch URL: {resp.status_code}'}), 400
            try:
                data = resp.json()
            except Exception:
                data = yaml.safe_load(resp.text)
            # Detect Postman or OpenAPI
            if 'info' in data and 'item' in data:
                endpoints = extract_all_endpoints_from_postman(data)
            else:
                endpoints = extract_all_endpoints_from_spec(data)
            return jsonify({'endpoints': endpoints})
        else:
            return jsonify({'error': 'No file or URL provided'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/delete', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan and its reports"""
    try:
        # Remove from scan_results
        scan = scan_results.pop(scan_id, None)
        # Remove from scan_manager.scan_history
        scan_manager.scan_history = [entry for entry in scan_manager.scan_history if entry.get('id') != scan_id]
        # Remove from scan_progress
        scan_progress.pop(scan_id, None)
        
        deleted_files = []
        if scan:
            # Delete associated report files
            reports = scan.get('reports', {})
            for report_path in reports.values():
                try:
                    if report_path and os.path.exists(report_path):
                        os.remove(report_path)
                        deleted_files.append(report_path)
                except Exception as e:
                    error_log(f"Failed to delete report file: {report_path}", error=str(e))
        return jsonify({
            'success': True,
            'deleted_scan_id': scan_id,
            'deleted_files': deleted_files
        })
    except Exception as e:
        error_log("Error deleting scan", exception=e, scan_id=scan_id)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Get project root directory (2 levels up from src/web/)
    project_root = Path(__file__).parent.parent.parent
    
    # Create necessary directories
    (project_root / 'uploads').mkdir(exist_ok=True)
    (project_root / 'templates').mkdir(exist_ok=True)
    (project_root / 'static').mkdir(exist_ok=True)
    (project_root / 'logs').mkdir(exist_ok=True)
    
    # Initialize scan manager and load existing scans
    scan_manager = ScanManager()
    load_existing_scans()
    
    debug_log("Starting API Security Scanner Web UI")
    print("🌐 Starting API Security Scanner Web UI...")
    print("📱 Open your browser and go to: http://localhost:5000")
    print("🔧 Press Ctrl+C to stop the server")
    
    app.run(debug=True, host='0.0.0.0', port=5000) 