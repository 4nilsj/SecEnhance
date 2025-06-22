#!/usr/bin/env python3
"""
API Security Scanner - Updated Web UI
A web-based interface for running API security scans with performance optimization
"""

from flask import Flask, render_template, request, jsonify, send_file
from api_security_scanner_updated import APISecurityScanner
import os
import json
import tempfile
import time
from datetime import datetime
import threading
import queue
from werkzeug.utils import secure_filename
import requests
import yaml
import logging
import glob
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Global variables for scan management
scan_queue = queue.Queue()
scan_results = {}
current_scan = None

class ScanManager:
    """Manages API security scans with performance optimization"""
    
    def __init__(self):
        logger.info("Initializing ScanManager")
        self.scanner = APISecurityScanner(enable_optimization=True, max_workers=8)
        self.scan_history = []
        logger.info("ScanManager initialized successfully")
    
    def run_scan(self, scan_config):
        """Run a security scan with the given configuration"""
        scan_id = scan_config.get('id', f"scan_{int(time.time())}")
        logger.info(f"Starting scan {scan_id}")
        
        try:
            scan_config['id'] = scan_id
            scan_config['status'] = 'running'
            scan_config['start_time'] = datetime.now().isoformat()
            
            # Initialize progress tracking
            self.scanner.reset_scan_progress()
            
            # Set authentication if provided
            if scan_config.get('auth_type'):
                auth_config = self._build_auth_config(scan_config)
                self.scanner.set_auth_config(auth_config)
                logger.info(f"Authentication configured: {scan_config['auth_type']}")
            
            # Run scan based on type
            scan_type = scan_config['scan_type']
            results = None
            
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
            elif scan_type == 'endpoints':
                # Direct endpoint scanning with progress tracking
                endpoints = scan_config.get('endpoints', [])
                if endpoints:
                    # Calculate total tests for progress tracking
                    total_tests = len(endpoints) * len(self.scanner.api_tests)
                    self.scanner.update_scan_progress(0, total_tests, 'initializing')
                    
                    results = self.scanner.scan_api_endpoints_optimized(endpoints)
                else:
                    raise ValueError("No endpoints provided for scanning")
            else:
                error_msg = f"Unsupported scan type: {scan_type}"
                logger.error(error_msg)
                scan_config['status'] = 'failed'
                scan_config['error'] = error_msg
                return scan_config
            
            # Process results
            if results and 'error' not in results:
                logger.info(f"Scan completed successfully for {scan_id}")
                
                # Get final progress
                progress = self.scanner.get_scan_progress()
                scan_config['progress'] = progress
                
                # Generate reports
                try:
                    report_file = self.scanner.generate_api_security_report(results)
                    owasp_report = self.scanner.generate_owasp_report(results, 'html')
                    
                    scan_config['status'] = 'completed'
                    scan_config['results'] = results
                    scan_config['reports'] = {
                        'standard_report': report_file,
                        'owasp_report': owasp_report
                    }
                    
                    # Add performance metrics
                    if 'performance_metrics' in results:
                        scan_config['performance'] = results['performance_metrics']
                    
                    logger.info(f"Reports generated for scan {scan_id}")
                    
                except Exception as report_error:
                    logger.error(f"Error generating reports: {report_error}")
                    scan_config['status'] = 'completed'
                    scan_config['results'] = results
                    scan_config['error'] = f"Scan completed but report generation failed: {str(report_error)}"
            else:
                scan_config['status'] = 'failed'
                scan_config['error'] = results.get('error', 'Unknown error occurred') if results else 'No results returned'
                logger.error(f"Scan failed for {scan_id}: {scan_config['error']}")
            
            scan_config['end_time'] = datetime.now().isoformat()
            self.scan_history.append(scan_config)
            
            return scan_config
            
        except Exception as e:
            logger.error(f"Error in run_scan for {scan_id}: {e}")
            scan_config['status'] = 'failed'
            scan_config['error'] = str(e)
            scan_config['end_time'] = datetime.now().isoformat()
            self.scan_history.append(scan_config)
            return scan_config
    
    def _build_auth_config(self, scan_config):
        """Build authentication configuration from scan config"""
        auth_type = scan_config['auth_type']
        logger.info(f"Building auth config for type: {auth_type}")
        
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
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    try:
        scan_config = request.json
        if not scan_config:
            return jsonify({'error': 'No scan configuration provided'}), 400
        
        logger.info(f"Received scan request: {scan_config.get('scan_type', 'unknown')}")
        
        # Generate unique scan ID
        scan_config['id'] = f"scan_{int(time.time())}"
        
        # Validate required fields
        scan_type = scan_config.get('scan_type')
        if not scan_type:
            return jsonify({'error': 'Scan type is required'}), 400
        
        # Validate scan type specific fields
        if scan_type == 'swagger_url' and not scan_config.get('swagger_url'):
            return jsonify({'error': 'Swagger URL is required'}), 400
        elif scan_type == 'json_file' and not scan_config.get('json_file'):
            return jsonify({'error': 'JSON file path is required'}), 400
        elif scan_type == 'collection' and not scan_config.get('collection_file'):
            return jsonify({'error': 'Collection file is required'}), 400
        elif scan_type == 'endpoints' and not scan_config.get('endpoints'):
            return jsonify({'error': 'Endpoints list is required'}), 400
        
        # Store scan config
        scan_results[scan_config['id']] = scan_config
        
        # Run scan in background thread
        def run_scan_async():
            try:
                result = scan_manager.run_scan(scan_config)
                scan_results[scan_config['id']] = result
                logger.info(f"Background scan completed for {scan_config['id']}")
            except Exception as e:
                logger.error(f"Background scan error for {scan_config['id']}: {e}")
                scan_results[scan_config['id']]['status'] = 'failed'
                scan_results[scan_config['id']]['error'] = str(e)
        
        thread = threading.Thread(target=run_scan_async)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_config['id'],
            'status': 'started',
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>')
def get_scan_status(scan_id):
    """Get the status of a scan"""
    try:
        scan_result = scan_results.get(scan_id)
        if not scan_result:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Return basic status info
        response = {
            'id': scan_result['id'],
            'status': scan_result['status'],
            'scan_type': scan_result.get('scan_type'),
            'start_time': scan_result.get('start_time'),
            'end_time': scan_result.get('end_time')
        }
        
        # Add error if failed
        if scan_result['status'] == 'failed':
            response['error'] = scan_result.get('error')
        
        # Add summary if completed
        if scan_result['status'] == 'completed':
            results = scan_result.get('results', {})
            response['summary'] = {
                'endpoints_scanned': results.get('scanned_endpoints', 0),
                'vulnerabilities_found': len(results.get('vulnerabilities', [])),
                'scan_duration': results.get('scan_info', {}).get('duration', 0)
            }
            
            # Add performance metrics if available
            if 'performance' in scan_result:
                response['performance'] = scan_result['performance']
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans')
def get_scan_history():
    """Get scan history"""
    try:
        history = []
        
        # Add scans from scan_manager.scan_history
        for scan in scan_manager.scan_history[-10:]:  # Last 10 scans
            history.append({
                'id': scan['id'],
                'scan_type': scan.get('scan_type'),
                'status': scan['status'],
                'start_time': scan.get('start_time'),
                'end_time': scan.get('end_time'),
                'error': scan.get('error')
            })
        
        # Add scans from scan_results (loaded from existing reports)
        for scan_id, scan_result in scan_results.items():
            # Check if this scan is already in history
            if not any(h['id'] == scan_id for h in history):
                history.append({
                    'id': scan_result['id'],
                    'scan_type': scan_result.get('scan_type'),
                    'status': scan_result['status'],
                    'start_time': scan_result.get('start_time'),
                    'end_time': scan_result.get('end_time'),
                    'error': scan_result.get('error')
                })
        
        # Sort by start time (newest first)
        history.sort(key=lambda x: x.get('start_time', ''), reverse=True)
        
        # Return last 10 scans
        return jsonify({'scans': history[:10]})
        
    except Exception as e:
        logger.error(f"Error getting scan history: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<scan_id>/<report_type>')
def download_report(scan_id, report_type):
    """Download a scan report"""
    try:
        scan_result = scan_results.get(scan_id)
        if not scan_result:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan_result['status'] != 'completed':
            return jsonify({'error': 'Scan not completed'}), 400
        
        reports = scan_result.get('reports', {})
        
        if report_type == 'json':
            # Return JSON report
            results = scan_result.get('results', {})
            return jsonify(results)
        
        elif report_type == 'standard':
            # Return standard HTML report
            report_file = reports.get('standard_report')
            if report_file and os.path.exists(report_file):
                return send_file(report_file, as_attachment=True, 
                               download_name=f"security_report_{scan_id}.html")
            else:
                return jsonify({'error': 'Standard report not found'}), 404
        
        elif report_type == 'owasp':
            # Return OWASP HTML report
            report_file = reports.get('owasp_report')
            if report_file and os.path.exists(report_file):
                return send_file(report_file, as_attachment=True, 
                               download_name=f"owasp_report_{scan_id}.html")
            else:
                return jsonify({'error': 'OWASP report not found'}), 404
        
        else:
            return jsonify({'error': 'Invalid report type'}), 400
        
    except Exception as e:
        logger.error(f"Error downloading report: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<scan_id>/<report_type>/view')
def view_report(scan_id, report_type):
    """View a scan report directly in the browser"""
    try:
        scan_result = scan_results.get(scan_id)
        if not scan_result:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan_result['status'] != 'completed':
            return jsonify({'error': 'Scan not completed'}), 400
        
        # Look for report files based on scan timestamp
        scan_start = scan_result.get('start_time', '')
        if scan_start:
            # Extract timestamp from scan start time
            try:
                dt = datetime.fromisoformat(scan_start.replace('Z', '+00:00'))
                timestamp = dt.strftime('%Y%m%d_%H%M%S')
                
                if report_type == 'json':
                    report_file = f"api_security_report_{timestamp}.json"
                elif report_type == 'owasp':
                    report_file = f"owasp_api_report_{timestamp}.html"
                else:
                    return jsonify({'error': 'Invalid report type'}), 400
                
                if os.path.exists(report_file):
                    if report_type == 'json':
                        with open(report_file, 'r', encoding='utf-8') as f:
                            return jsonify(json.load(f))
                    else:
                        return send_file(report_file, mimetype='text/html')
                else:
                    return jsonify({'error': f'Report file not found: {report_file}'}), 404
                    
            except Exception as e:
                logger.error(f"Error parsing scan timestamp: {e}")
                return jsonify({'error': 'Invalid scan timestamp'}), 400
        
        return jsonify({'error': 'No scan timestamp found'}), 400
        
    except Exception as e:
        logger.error(f"Error viewing report: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<scan_id>/list')
def list_reports(scan_id):
    """List available reports for a scan"""
    try:
        scan_result = scan_results.get(scan_id)
        if not scan_result:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan_result['status'] != 'completed':
            return jsonify({'error': 'Scan not completed'}), 400
        
        # Look for report files based on scan timestamp
        scan_start = scan_result.get('start_time', '')
        reports = []
        
        if scan_start:
            try:
                dt = datetime.fromisoformat(scan_start.replace('Z', '+00:00'))
                timestamp = dt.strftime('%Y%m%d_%H%M%S')
                
                # Check for JSON report
                json_report = f"api_security_report_{timestamp}.json"
                if os.path.exists(json_report):
                    reports.append({
                        'type': 'json',
                        'name': 'API Security Report (JSON)',
                        'file': json_report,
                        'size': os.path.getsize(json_report),
                        'view_url': f'/api/report/{scan_id}/json/view',
                        'download_url': f'/api/report/{scan_id}/json'
                    })
                
                # Check for OWASP HTML report
                owasp_report = f"owasp_api_report_{timestamp}.html"
                if os.path.exists(owasp_report):
                    reports.append({
                        'type': 'owasp',
                        'name': 'OWASP API Security Report (HTML)',
                        'file': owasp_report,
                        'size': os.path.getsize(owasp_report),
                        'view_url': f'/api/report/{scan_id}/owasp/view',
                        'download_url': f'/api/report/{scan_id}/owasp'
                    })
                
            except Exception as e:
                logger.error(f"Error parsing scan timestamp: {e}")
        
        return jsonify({'reports': reports})
        
    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file uploads"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file:
            filename = secure_filename(file.filename)
            upload_dir = 'uploads'
            os.makedirs(upload_dir, exist_ok=True)
            
            # Save file with timestamp
            timestamp = int(time.time())
            filename = f"upload_{timestamp}_{filename}"
            filepath = os.path.join(upload_dir, filename)
            file.save(filepath)
            
            logger.info(f"File uploaded: {filepath}")
            
            return jsonify({
                'filename': filename,
                'filepath': filepath,
                'size': os.path.getsize(filepath)
            })
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/test', methods=['POST'])
def test_authentication():
    """Test authentication configuration"""
    try:
        auth_config = request.json
        if not auth_config:
            return jsonify({'error': 'No authentication configuration provided'}), 400
        
        # Create temporary scanner for testing
        test_scanner = APISecurityScanner(enable_optimization=False)
        test_scanner.set_auth_config(auth_config)
        
        # Test with a simple request
        test_url = auth_config.get('test_url', 'http://localhost:5001/api/users')
        
        try:
            response = test_scanner.session.get(test_url, timeout=10)
            
            return jsonify({
                'success': True,
                'status_code': response.status_code,
                'message': 'Authentication test successful'
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e),
                'message': 'Authentication test failed'
            })
        
    except Exception as e:
        logger.error(f"Error testing authentication: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/performance/report')
def get_performance_report():
    """Get performance report from scanner"""
    try:
        report = scan_manager.scanner.get_performance_report()
        return jsonify(report)
        
    except Exception as e:
        logger.error(f"Error getting performance report: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/optimize/config', methods=['POST'])
def optimize_configuration():
    """Optimize scanner configuration"""
    try:
        data = request.json
        endpoints = data.get('endpoints', [])
        
        if not endpoints:
            return jsonify({'error': 'No endpoints provided'}), 400
        
        opt_config = scan_manager.scanner.optimize_configuration(endpoints)
        return jsonify(opt_config)
        
    except Exception as e:
        logger.error(f"Error optimizing configuration: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'scanner_ready': True
    })

@app.route('/api/scan/<scan_id>/progress')
def get_scan_progress(scan_id):
    """Get real-time scan progress with percentage completion"""
    try:
        scan_result = scan_results.get(scan_id)
        if not scan_result:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Get current progress from scanner
        progress = scan_manager.scanner.get_scan_progress()
        
        response = {
            'scan_id': scan_id,
            'status': scan_result['status'],
            'progress': progress
        }
        
        # Add scan-specific progress if available
        if 'progress' in scan_result:
            response['scan_progress'] = scan_result['progress']
        
        # Add estimated time remaining
        if progress.get('status') == 'running' and progress.get('current', 0) > 0:
            elapsed_time = time.time() - datetime.fromisoformat(scan_result['start_time'].replace('Z', '+00:00')).timestamp()
            if progress.get('progress', 0) > 0:
                estimated_total = elapsed_time / (progress.get('progress', 1) / 100)
                estimated_remaining = estimated_total - elapsed_time
                response['estimated_remaining'] = round(estimated_remaining, 1)
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error getting scan progress: {e}")
        return jsonify({'error': str(e)}), 500

def extract_endpoints_from_spec(spec, base_url=None):
    """Extract endpoints from OpenAPI/Swagger specification"""
    endpoints = []
    
    try:
        if isinstance(spec, str):
            spec = json.loads(spec)
        
        # Handle OpenAPI 3.x
        if 'openapi' in spec:
            paths = spec.get('paths', {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        endpoint = {
                            'path': path,
                            'method': method.upper(),
                            'base_url': base_url or spec.get('servers', [{}])[0].get('url', ''),
                            'description': details.get('summary', details.get('description', ''))
                        }
                        endpoints.append(endpoint)
        
        # Handle Swagger 2.x
        elif 'swagger' in spec:
            paths = spec.get('paths', {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        endpoint = {
                            'path': path,
                            'method': method.upper(),
                            'base_url': base_url or spec.get('host', ''),
                            'description': details.get('summary', details.get('description', ''))
                        }
                        endpoints.append(endpoint)
        
        return endpoints
        
    except Exception as e:
        logger.error(f"Error extracting endpoints: {e}")
        return []

@app.route('/api/parse_endpoints', methods=['POST'])
def parse_endpoints():
    """Parse endpoints from uploaded file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file content
        content = file.read().decode('utf-8')
        
        # Try to parse as JSON/YAML
        try:
            if file.filename.endswith('.json'):
                spec = json.loads(content)
            elif file.filename.endswith(('.yaml', '.yml')):
                spec = yaml.safe_load(content)
            else:
                return jsonify({'error': 'Unsupported file format'}), 400
        except Exception as parse_error:
            return jsonify({'error': f'Failed to parse file: {str(parse_error)}'}), 400
        
        # Extract endpoints
        base_url = request.form.get('base_url', '')
        endpoints = extract_endpoints_from_spec(spec, base_url)
        
        return jsonify({
            'endpoints': endpoints,
            'count': len(endpoints)
        })
        
    except Exception as e:
        logger.error(f"Error parsing endpoints: {e}")
        return jsonify({'error': str(e)}), 500

def load_existing_scans():
    """Load existing scan results from generated report files"""
    try:
        # Find JSON report files
        json_reports = glob.glob("api_security_report_*.json")
        
        for report_file in json_reports:
            # Extract timestamp from filename
            match = re.search(r'api_security_report_(\d{8}_\d{6})\.json', report_file)
            if match:
                timestamp = match.group(1)
                scan_id = f"scan_{timestamp}"
                
                # Check if scan already exists
                if scan_id not in scan_results:
                    try:
                        # Parse timestamp
                        dt = datetime.strptime(timestamp, '%Y%m%d_%H%M%S')
                        
                        # Create scan result entry
                        scan_result = {
                            'id': scan_id,
                            'status': 'completed',
                            'scan_type': 'collection',
                            'start_time': dt.isoformat(),
                            'end_time': dt.isoformat(),  # Approximate
                            'reports': {
                                'json_report': report_file,
                                'owasp_report': f"owasp_api_report_{timestamp}.html"
                            }
                        }
                        
                        # Load scan results from JSON file
                        try:
                            with open(report_file, 'r', encoding='utf-8') as f:
                                results_data = json.load(f)
                                scan_result['results'] = results_data
                                
                                # Add performance metrics
                                if 'performance_metrics' in results_data:
                                    scan_result['performance'] = results_data['performance_metrics']['metrics']
                        except Exception as e:
                            logger.warning(f"Could not load results from {report_file}: {e}")
                        
                        scan_results[scan_id] = scan_result
                        logger.info(f"Loaded existing scan: {scan_id}")
                        
                    except Exception as e:
                        logger.warning(f"Could not parse scan from {report_file}: {e}")
        
        logger.info(f"Loaded {len(scan_results)} existing scans")
        
    except Exception as e:
        logger.error(f"Error loading existing scans: {e}")

# Load existing scans on startup
load_existing_scans()

if __name__ == '__main__':
    # Create uploads directory
    os.makedirs('uploads', exist_ok=True)
    
    # Create templates directory and basic template if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create basic index.html template if it doesn't exist
    if not os.path.exists('templates/index.html'):
        with open('templates/index.html', 'w') as f:
            f.write('''<!DOCTYPE html>
<html>
<head>
    <title>API Security Scanner</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .form-section { margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, select, textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .status { padding: 10px; margin: 10px 0; border-radius: 3px; }
        .status.success { background: #d4edda; color: #155724; }
        .status.error { background: #f8d7da; color: #721c24; }
        .status.info { background: #d1ecf1; color: #0c5460; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 API Security Scanner</h1>
            <p>Comprehensive API security testing with performance optimization</p>
        </div>
        
        <div class="form-section">
            <h2>🔍 Start New Scan</h2>
            <form id="scanForm">
                <div class="form-group">
                    <label for="scanType">Scan Type:</label>
                    <select id="scanType" name="scanType" required>
                        <option value="">Select scan type...</option>
                        <option value="swagger_url">Swagger/OpenAPI URL</option>
                        <option value="json_file">JSON Specification File</option>
                        <option value="collection">Postman Collection</option>
                        <option value="endpoints">Direct Endpoints</option>
                    </select>
                </div>
                
                <div id="scanConfig"></div>
                
                <button type="submit">Start Scan</button>
            </form>
        </div>
        
        <div class="form-section">
            <h2>📊 Scan Status</h2>
            <div id="scanStatus"></div>
        </div>
        
        <div class="form-section">
            <h2>📋 Scan History</h2>
            <div id="scanHistory"></div>
        </div>
    </div>
    
    <script>
        // Basic JavaScript for form handling
        document.getElementById('scanType').addEventListener('change', function() {
            const configDiv = document.getElementById('scanConfig');
            const scanType = this.value;
            
            let configHTML = '';
            
            switch(scanType) {
                case 'swagger_url':
                    configHTML = `
                        <div class="form-group">
                            <label for="swaggerUrl">Swagger URL:</label>
                            <input type="url" id="swaggerUrl" name="swaggerUrl" required>
                        </div>
                        <div class="form-group">
                            <label for="baseUrl">Base URL (optional):</label>
                            <input type="url" id="baseUrl" name="baseUrl">
                        </div>
                    `;
                    break;
                case 'endpoints':
                    configHTML = `
                        <div class="form-group">
                            <label for="endpoints">Endpoints (JSON):</label>
                            <textarea id="endpoints" name="endpoints" rows="5" required placeholder='[{"path": "/api/users", "method": "GET", "base_url": "http://localhost:5001"}]'></textarea>
                        </div>
                    `;
                    break;
            }
            
            configHTML += `
                <div class="form-group">
                    <label for="authType">Authentication Type:</label>
                    <select id="authType" name="authType">
                        <option value="">None</option>
                        <option value="bearer">Bearer Token</option>
                        <option value="apikey">API Key</option>
                        <option value="basic">Basic Auth</option>
                    </select>
                </div>
            `;
            
            configDiv.innerHTML = configHTML;
        });
        
        document.getElementById('scanForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const scanType = formData.get('scanType');
            
            let scanConfig = {
                scan_type: scanType
            };
            
            switch(scanType) {
                case 'swagger_url':
                    scanConfig.swagger_url = formData.get('swaggerUrl');
                    scanConfig.base_url = formData.get('baseUrl');
                    break;
                case 'endpoints':
                    try {
                        scanConfig.endpoints = JSON.parse(formData.get('endpoints'));
                    } catch(e) {
                        alert('Invalid JSON format for endpoints');
                        return;
                    }
                    break;
            }
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(scanConfig)
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    showStatus('Scan started successfully!', 'success');
                    if (result.scan_id) {
                        monitorScan(result.scan_id);
                    }
                } else {
                    showStatus('Error: ' + result.error, 'error');
                }
            } catch(e) {
                showStatus('Error: ' + e.message, 'error');
            }
        });
        
        function showStatus(message, type) {
            const statusDiv = document.getElementById('scanStatus');
            statusDiv.innerHTML = `<div class="status ${type}">${message}</div>`;
        }
        
        async function monitorScan(scanId) {
            const checkStatus = async () => {
                try {
                    const response = await fetch(`/api/scan/${scanId}`);
                    const result = await response.json();
                    
                    if (response.ok) {
                        let statusMessage = `Scan ${scanId}: ${result.status}`;
                        
                        if (result.status === 'completed') {
                            statusMessage += ` - ${result.summary.vulnerabilities_found} vulnerabilities found`;
                            showStatus(statusMessage, 'success');
                            return;
                        } else if (result.status === 'failed') {
                            statusMessage += ` - ${result.error}`;
                            showStatus(statusMessage, 'error');
                            return;
                        } else {
                            showStatus(statusMessage, 'info');
                            setTimeout(checkStatus, 2000); // Check again in 2 seconds
                        }
                    }
                } catch(e) {
                    showStatus('Error monitoring scan: ' + e.message, 'error');
                }
            };
            
            checkStatus();
        }
        
        // Load scan history on page load
        window.addEventListener('load', async function() {
            try {
                const response = await fetch('/api/scans');
                const result = await response.json();
                
                if (response.ok) {
                    const historyDiv = document.getElementById('scanHistory');
                    let historyHTML = '<ul>';
                    
                    result.scans.forEach(scan => {
                        historyHTML += `<li>${scan.id} - ${scan.scan_type} - ${scan.status}</li>`;
                    });
                    
                    historyHTML += '</ul>';
                    historyDiv.innerHTML = historyHTML;
                }
            } catch(e) {
                console.error('Error loading scan history:', e);
            }
        });
    </script>
</body>
</html>''')
    
    logger.info("Starting API Security Scanner Web UI...")
    logger.info("Web UI will be available at: http://localhost:5000")
    
    app.run(host='0.0.0.0', port=5000, debug=True) 