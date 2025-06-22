#!/usr/bin/env python3
"""
API Security Scanner - Enhanced Web UI
A web-based interface for running API security scans with improved scan history and reports
"""

import os
import json
import time
import glob
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from werkzeug.utils import secure_filename
import threading
import queue

# Import the scanner
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from core.scanner import APISecurityScanner

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Global variables
scan_queue = queue.Queue()
scan_results = {}
scan_history = []

class ScanManager:
    """Manages API security scans"""
    
    def __init__(self):
        self.scanner = APISecurityScanner()
        self.load_scan_history()
    
    def load_scan_history(self):
        """Load scan history from reports directory"""
        global scan_history
        try:
            # Load from reports/json directory
            json_reports = glob.glob('reports/json/*.json')
            for report_file in json_reports:
                try:
                    with open(report_file, 'r') as f:
                        report_data = json.load(f)
                    
                    # Extract scan info from filename
                    filename = os.path.basename(report_file)
                    if filename.startswith('api_security_report_'):
                        scan_id = filename.replace('api_security_report_', '').replace('.json', '')
                        
                        scan_info = {
                            'id': scan_id,
                            'scan_type': 'collection',
                            'status': 'completed',
                            'start_time': report_data.get('scan_start_time', ''),
                            'end_time': report_data.get('scan_end_time', ''),
                            'endpoints_found': report_data.get('endpoints_found', 0),
                            'vulnerabilities_found': len(report_data.get('vulnerabilities', [])),
                            'report_file': report_file,
                            'html_report': report_file.replace('json', 'html').replace('.json', '.html'),
                            'summary': {
                                'total_endpoints': report_data.get('endpoints_found', 0),
                                'total_vulnerabilities': len(report_data.get('vulnerabilities', [])),
                                'high_vulnerabilities': len([v for v in report_data.get('vulnerabilities', []) if v.get('severity') == 'High']),
                                'medium_vulnerabilities': len([v for v in report_data.get('vulnerabilities', []) if v.get('severity') == 'Medium']),
                                'low_vulnerabilities': len([v for v in report_data.get('vulnerabilities', []) if v.get('severity') == 'Low'])
                            }
                        }
                        
                        # Check if scan already exists
                        existing_scan = next((s for s in scan_history if s['id'] == scan_id), None)
                        if not existing_scan:
                            scan_history.append(scan_info)
                
                except Exception as e:
                    print(f"Error loading report {report_file}: {e}")
            
            # Sort by start time (newest first)
            scan_history.sort(key=lambda x: x.get('start_time', ''), reverse=True)
            
        except Exception as e:
            print(f"Error loading scan history: {e}")
    
    def run_scan(self, scan_config):
        """Run a security scan"""
        scan_id = scan_config.get('id', f"scan_{int(time.time())}")
        
        try:
            scan_config['id'] = scan_id
            scan_config['status'] = 'running'
            scan_config['start_time'] = datetime.now().isoformat()
            
            # Add to scan history
            scan_history.insert(0, scan_config)
            
            # Run the scan
            if scan_config['scan_type'] == 'collection':
                results = self.scanner.upload_and_scan_collection(
                    scan_config['collection_file'],
                    scan_config.get('base_url')
                )
            else:
                results = {'error': 'Unsupported scan type'}
            
            if 'error' not in results:
                # Generate reports
                report_file = self.scanner.generate_api_security_report(results)
                owasp_report = self.scanner.generate_owasp_report(results, 'html')
                
                scan_config['status'] = 'completed'
                scan_config['results'] = results
                scan_config['reports'] = {
                    'standard_report': report_file,
                    'owasp_report': owasp_report
                }
                scan_config['end_time'] = datetime.now().isoformat()
                scan_config['endpoints_found'] = results.get('endpoints_found', 0)
                scan_config['vulnerabilities_found'] = len(results.get('vulnerabilities', []))
                
                # Update scan history
                self.update_scan_in_history(scan_config)
            else:
                scan_config['status'] = 'failed'
                scan_config['error'] = results['error']
                scan_config['end_time'] = datetime.now().isoformat()
                self.update_scan_in_history(scan_config)
            
            return scan_config
            
        except Exception as e:
            scan_config['status'] = 'failed'
            scan_config['error'] = str(e)
            scan_config['end_time'] = datetime.now().isoformat()
            self.update_scan_in_history(scan_config)
            return scan_config
    
    def update_scan_in_history(self, scan_config):
        """Update scan in history"""
        for i, scan in enumerate(scan_history):
            if scan['id'] == scan_config['id']:
                scan_history[i] = scan_config
                break

scan_manager = ScanManager()

@app.route('/')
def index():
    """Main page"""
    return render_template('enhanced_index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    try:
        scan_config = request.json
        
        # Generate unique scan ID
        scan_config['id'] = f"scan_{int(time.time())}"
        
        # Validate required fields
        if not scan_config.get('scan_type'):
            return jsonify({'error': 'Scan type is required'}), 400
        
        if scan_config['scan_type'] == 'collection' and not scan_config.get('collection_file'):
            return jsonify({'error': 'Collection file is required'}), 400
        
        # Run scan in background
        def run_scan_async():
            scan_manager.run_scan(scan_config)
        
        thread = threading.Thread(target=run_scan_async)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'scan_id': scan_config['id'],
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>')
def get_scan_status(scan_id):
    """Get scan status"""
    try:
        scan = next((s for s in scan_history if s['id'] == scan_id), None)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify(scan)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans')
def get_scan_history():
    """Get scan history"""
    try:
        # Reload scan history to get latest reports
        scan_manager.load_scan_history()
        return jsonify(scan_history)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<scan_id>/<report_type>')
def download_report(scan_id, report_type):
    """Download scan report"""
    try:
        scan = next((s for s in scan_history if s['id'] == scan_id), None)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan['status'] != 'completed':
            return jsonify({'error': 'Scan not completed'}), 400
        
        if report_type == 'standard':
            report_file = scan.get('reports', {}).get('standard_report')
        elif report_type == 'owasp':
            report_file = scan.get('reports', {}).get('owasp_report')
        else:
            return jsonify({'error': 'Invalid report type'}), 400
        
        if not report_file or not os.path.exists(report_file):
            return jsonify({'error': 'Report file not found'}), 404
        
        return send_file(report_file, as_attachment=True)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<scan_id>/view')
def view_report(scan_id):
    """View scan report in browser"""
    try:
        scan = next((s for s in scan_history if s['id'] == scan_id), None)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan['status'] != 'completed':
            return jsonify({'error': 'Scan not completed'}), 400
        
        # Try to find HTML report
        html_report = scan.get('reports', {}).get('owasp_report')
        if html_report and os.path.exists(html_report):
            return send_file(html_report)
        
        # Fallback to JSON report
        json_report = scan.get('reports', {}).get('standard_report')
        if json_report and os.path.exists(json_report):
            with open(json_report, 'r') as f:
                report_data = json.load(f)
            return jsonify(report_data)
        
        return jsonify({'error': 'No report available'}), 404
        
    except Exception as e:
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
        
        # Save uploaded file
        filename = secure_filename(f"upload_{int(time.time())}_{file.filename}")
        filepath = os.path.join('data/uploads', filename)
        
        # Create uploads directory if it doesn't exist
        os.makedirs('data/uploads', exist_ok=True)
        
        file.save(filepath)
        
        return jsonify({
            'filename': filename,
            'filepath': filepath,
            'message': 'File uploaded successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """Get scan statistics"""
    try:
        total_scans = len(scan_history)
        completed_scans = len([s for s in scan_history if s.get('status') == 'completed'])
        failed_scans = len([s for s in scan_history if s.get('status') == 'failed'])
        running_scans = len([s for s in scan_history if s.get('status') == 'running'])
        
        total_vulnerabilities = sum(s.get('vulnerabilities_found', 0) for s in scan_history if s.get('status') == 'completed')
        total_endpoints = sum(s.get('endpoints_found', 0) for s in scan_history if s.get('status') == 'completed')
        
        return jsonify({
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'failed_scans': failed_scans,
            'running_scans': running_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'total_endpoints': total_endpoints
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 