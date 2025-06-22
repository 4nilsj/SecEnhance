#!/usr/bin/env python3
"""
API Security Scanner - Web UI
A web-based interface for running API security scans independently
"""

from flask import Flask, render_template, request, jsonify, send_file
from api_security_scanner import APISecurityScanner
import os
import json
import tempfile
import time
from datetime import datetime
import threading
import queue
from debug_utils import get_debug_summary, export_debug_data
from werkzeug.utils import secure_filename
import requests
import yaml

# Import debugging framework
from debug_config import (
    debug_logger, debug_decorator, debug_method, DebugContext,
    track_request, track_scan, track_auth, track_api,
    debug_log, info_log, error_log
)

app = Flask(__name__)

# Global variables for scan management
scan_queue = queue.Queue()
scan_results = {}
current_scan = None

class ScanManager:
    """Manages API security scans with debugging support"""
    
    def __init__(self):
        debug_log("Initializing ScanManager")
        self.scanner = APISecurityScanner()
        self.scan_history = []
        debug_log("ScanManager initialized successfully")
    
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
                
                # Set authentication if provided
                if scan_config.get('auth_type'):
                    auth_config = self._build_auth_config(scan_config)
                    self.scanner.set_auth_config(auth_config)
                    track_auth(scan_config['auth_type'], True)
                
                # Run scan based on type
                scan_type = scan_config['scan_type']
                if scan_type == 'swagger_url':
                    results = self.scanner.scan_from_swagger_url(
                        scan_config['swagger_url'],
                        scan_config.get('base_url'),
                        auth_config if scan_config.get('auth_type') else None
                    )
                elif scan_type == 'json_file':
                    results = self.scanner.scan_from_json_file(
                        scan_config['json_file'],
                        scan_config.get('base_url'),
                        auth_config if scan_config.get('auth_type') else None
                    )
                elif scan_type == 'collection':
                    results = self.scanner.upload_and_scan_collection(
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
                
                # Generate reports
                if 'error' not in results:
                    debug_log("Generating reports", scan_id=scan_id)
                    report_file = self.scanner.generate_api_security_report(results)
                    owasp_report = self.scanner.generate_owasp_report(results, 'html')
                    
                    scan_config['status'] = 'completed'
                    scan_config['results'] = results
                    scan_config['reports'] = {
                        'standard_report': report_file,
                        'owasp_report': owasp_report
                    }
                    
                    track_scan(scan_id, scan_type, "completed", 
                             endpoint_count=results.get('endpoints_found', 0),
                             vulnerability_count=len(results.get('vulnerabilities', [])))
                else:
                    scan_config['status'] = 'failed'
                    scan_config['error'] = results['error']
                    track_scan(scan_id, scan_type, "failed", error=results['error'])
                
                scan_config['end_time'] = datetime.now().isoformat()
                self.scan_history.append(scan_config)
                
                return scan_config
                
            except Exception as e:
                error_log("Error in run_scan", exception=e, scan_id=scan_id)
                scan_config['status'] = 'failed'
                scan_config['error'] = str(e)
                scan_config['end_time'] = datetime.now().isoformat()
                self.scan_history.append(scan_config)
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
                scan_results[result['id']] = result
        
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
            duration = time.time() - start_time
            track_request("GET", f"/api/scan/{scan_id}", 404, duration)
            return jsonify({'error': 'Scan not found'}), 404
    except Exception as e:
        duration = time.time() - start_time
        error_log("Error in get_scan_status", exception=e, scan_id=scan_id)
        track_request("GET", f"/api/scan/{scan_id}", 500, duration)
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans')
def get_scan_history():
    """Get scan history"""
    start_time = time.time()
    
    try:
        duration = time.time() - start_time
        track_request("GET", "/api/scans", 200, duration)
        return jsonify(scan_manager.scan_history)
    except Exception as e:
        duration = time.time() - start_time
        error_log("Error in get_scan_history", exception=e)
        track_request("GET", "/api/scans", 500, duration)
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<scan_id>/<report_type>')
def download_report(scan_id, report_type):
    """Download scan report"""
    start_time = time.time()
    
    try:
        if scan_id not in scan_results:
            duration = time.time() - start_time
            track_request("GET", f"/api/report/{scan_id}/{report_type}", 404, duration)
            return jsonify({'error': 'Scan not found'}), 404
        
        scan = scan_results[scan_id]
        if scan['status'] != 'completed':
            duration = time.time() - start_time
            track_request("GET", f"/api/report/{scan_id}/{report_type}", 400, duration)
            return jsonify({'error': 'Scan not completed'}), 400
        
        if report_type == 'standard':
            report_file = scan['reports']['standard_report']
        elif report_type == 'owasp':
            report_file = scan['reports']['owasp_report']
        else:
            duration = time.time() - start_time
            track_request("GET", f"/api/report/{scan_id}/{report_type}", 400, duration)
            return jsonify({'error': 'Invalid report type'}), 400
        
        if os.path.exists(report_file):
            duration = time.time() - start_time
            track_request("GET", f"/api/report/{scan_id}/{report_type}", 200, duration)
            return send_file(report_file, as_attachment=True)
        else:
            duration = time.time() - start_time
            track_request("GET", f"/api/report/{scan_id}/{report_type}", 404, duration)
            return jsonify({'error': 'Report file not found'}), 404
            
    except Exception as e:
        duration = time.time() - start_time
        error_log("Error in download_report", exception=e, scan_id=scan_id, report_type=report_type)
        track_request("GET", f"/api/report/{scan_id}/{report_type}", 500, duration)
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file uploads"""
    start_time = time.time()
    
    try:
        if 'file' not in request.files:
            duration = time.time() - start_time
            track_request("POST", "/api/upload", 400, duration)
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            duration = time.time() - start_time
            track_request("POST", "/api/upload", 400, duration)
            return jsonify({'error': 'No file selected'}), 400
        
        # Save uploaded file
        filename = f"upload_{int(time.time())}_{file.filename}"
        filepath = os.path.join('uploads', filename)
        
        # Create uploads directory if it doesn't exist
        os.makedirs('uploads', exist_ok=True)
        
        file.save(filepath)
        debug_log("File uploaded successfully", filename=filename, filepath=filepath)
        
        duration = time.time() - start_time
        track_request("POST", "/api/upload", 200, duration)
        
        return jsonify({
            'filename': filename,
            'filepath': filepath,
            'message': 'File uploaded successfully'
        })
        
    except Exception as e:
        duration = time.time() - start_time
        error_log("Error in upload_file", exception=e)
        track_request("POST", "/api/upload", 500, duration)
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
        
        if auth_config.get('type') == 'bearer':
            test_scanner.set_bearer_token(auth_config['token'])
        elif auth_config.get('type') == 'apikey':
            test_scanner.set_api_key(
                auth_config['key'],
                auth_config['value'],
                auth_config.get('location', 'header')
            )
        elif auth_config.get('type') == 'basic':
            test_scanner.set_basic_auth(
                auth_config['username'],
                auth_config['password']
            )
        
        # Test with a simple request
        response = requests.get(
            "https://httpbin.org/headers",
            headers=test_scanner.session.headers,
            auth=test_scanner.session.auth,
            timeout=10
        )
        
        success = response.status_code == 200
        track_auth(auth_config.get('type', 'unknown'), success)
        
        duration = time.time() - start_time
        track_request("POST", "/api/auth/test", 200, duration)
        
        return jsonify({
            'success': True,
            'status_code': response.status_code,
            'headers': dict(test_scanner.session.headers),
            'message': 'Authentication test successful'
        })
        
    except Exception as e:
        duration = time.time() - start_time
        error_log("Error in test_authentication", exception=e)
        track_auth(auth_config.get('type', 'unknown') if 'auth_config' in locals() else 'unknown', False)
        track_request("POST", "/api/auth/test", 500, duration)
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Authentication test failed'
        }), 500

@app.route('/api/logs')
def get_logs():
    """Get the latest log lines (tail) or search logs"""
    log_file = 'logs/api_scanner.log'
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
    log_file = 'logs/api_scanner.log'
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

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    debug_log("Starting API Security Scanner Web UI")
    print("🌐 Starting API Security Scanner Web UI...")
    print("📱 Open your browser and go to: http://localhost:5000")
    print("🔧 Press Ctrl+C to stop the server")
    
    app.run(debug=True, host='0.0.0.0', port=5000) 