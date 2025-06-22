#!/usr/bin/env python3
"""
API Security Scanner - Enhanced Web UI
A web-based interface for running API security scans with improved scan history and reports
"""

import os
import json
import time
import glob
import sys
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from werkzeug.utils import secure_filename
import threading
import queue

# Add src directory to Python path
src_path = Path(__file__).parent.parent
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Import the scanner with error handling
try:
    from src.core.api_security_scanner import APISecurityScanner
except ImportError as e:
    print(f"Warning: Could not import APISecurityScanner: {e}")
    APISecurityScanner = None

# Flask app configuration
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Get configuration from environment variables
HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
PORT = int(os.environ.get('FLASK_PORT', 5000))
DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'

# Global variables
scan_queue = queue.Queue()
scan_results = {}
scan_history = []

class ScanManager:
    """Manages API security scans with improved error handling"""
    
    def __init__(self):
        if APISecurityScanner is None:
            raise RuntimeError("APISecurityScanner not available")
        
        self.scanner = APISecurityScanner()
        self.load_scan_history()
    
    def load_scan_history(self):
        """Load scan history from reports directory with error handling"""
        global scan_history
        try:
            # Ensure reports directory exists
            reports_dir = Path('reports')
            json_reports_dir = reports_dir / 'json'
            
            if not json_reports_dir.exists():
                print(f"📁 Creating reports directory: {json_reports_dir}")
                json_reports_dir.mkdir(parents=True, exist_ok=True)
                return
            
            # Load from reports/json directory
            json_reports = list(json_reports_dir.glob('*.json'))
            
            for report_file in json_reports:
                try:
                    with open(report_file, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                    
                    # Extract scan info from filename
                    filename = report_file.name
                    if filename.startswith('api_security_report_'):
                        scan_id = filename.replace('api_security_report_', '').replace('.json', '')
                        
                        # Extract scan info from the actual structure
                        scan_info = report_data.get('scan_results', {}).get('scan_info', {})
                        report_metadata = report_data.get('report_metadata', {})
                        
                        # Calculate end time from start time and duration
                        start_time = scan_info.get('start_time', '')
                        duration = scan_info.get('duration', 0)
                        end_time = ''
                        if start_time and duration:
                            try:
                                start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                                end_dt = start_dt + timedelta(seconds=duration)
                                end_time = end_dt.isoformat()
                            except:
                                end_time = start_time
                        
                        scan_info_record = {
                            'id': scan_id,
                            'scan_type': 'collection',
                            'status': 'completed',
                            'start_time': start_time,
                            'end_time': end_time,
                            'endpoints_found': scan_info.get('endpoints_scanned', 0),
                            'vulnerabilities_found': len(report_data.get('scan_results', {}).get('vulnerabilities', [])),
                            'report_file': str(report_file),
                            'html_report': str(Path(__file__).parent.parent.parent / 'reports' / 'html' / f'api_security_report_{scan_id}.html'),
                            'summary': {
                                'total_endpoints': scan_info.get('endpoints_scanned', 0),
                                'total_vulnerabilities': len(report_data.get('scan_results', {}).get('vulnerabilities', [])),
                                'high_vulnerabilities': len([v for v in report_data.get('scan_results', {}).get('vulnerabilities', []) if v.get('severity') == 'High']),
                                'medium_vulnerabilities': len([v for v in report_data.get('scan_results', {}).get('vulnerabilities', []) if v.get('severity') == 'Medium']),
                                'low_vulnerabilities': len([v for v in report_data.get('scan_results', {}).get('vulnerabilities', []) if v.get('severity') == 'Low'])
                            }
                        }
                        
                        # Check if scan already exists
                        existing_scan = next((s for s in scan_history if s['id'] == scan_id), None)
                        if not existing_scan:
                            scan_history.append(scan_info_record)
                
                except Exception as e:
                    print(f"⚠️  Error loading report {report_file}: {e}")
            
            # Sort by start time (newest first)
            def parse_time(x):
                try:
                    return datetime.fromisoformat(x.get('start_time', ''))
                except Exception:
                    return datetime.min
            scan_history.sort(key=parse_time, reverse=True)
            print(f"📊 Loaded {len(scan_history)} scan reports")
            
        except Exception as e:
            print(f"❌ Error loading scan history: {e}")
    
    def run_scan(self, scan_config):
        """Run a security scan with comprehensive error handling"""
        scan_id = scan_config.get('id', f"scan_{int(time.time())}")
        
        try:
            scan_config['id'] = scan_id
            scan_config['status'] = 'running'
            scan_config['start_time'] = datetime.now().isoformat()
            
            # Add to scan history
            scan_history.insert(0, scan_config)
            
            print(f"🚀 Starting scan {scan_id}: {scan_config.get('scan_type', 'unknown')}")
            
            # Run the scan
            if scan_config['scan_type'] == 'collection':
                collection_file = scan_config.get('collection_file')
                base_url = scan_config.get('base_url')
                
                if not collection_file or not os.path.exists(collection_file):
                    raise FileNotFoundError(f"Collection file not found: {collection_file}")
                
                results = self.scanner.upload_and_scan_collection(
                    collection_file,
                    base_url
                )
            else:
                results = {'error': f'Unsupported scan type: {scan_config["scan_type"]}'}
            
            if 'error' not in results:
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
                    scan_config['end_time'] = datetime.now().isoformat()
                    scan_config['endpoints_found'] = results.get('endpoints_found', 0)
                    scan_config['vulnerabilities_found'] = len(results.get('vulnerabilities', []))
                    
                    print(f"✅ Scan {scan_id} completed successfully")
                    
                except Exception as e:
                    print(f"⚠️  Error generating reports for scan {scan_id}: {e}")
                    scan_config['status'] = 'completed_with_warnings'
                    scan_config['warning'] = f"Scan completed but report generation failed: {str(e)}"
                    scan_config['end_time'] = datetime.now().isoformat()
                
                # Update scan history
                self.update_scan_in_history(scan_config)
            else:
                scan_config['status'] = 'failed'
                scan_config['error'] = results['error']
                scan_config['end_time'] = datetime.now().isoformat()
                self.update_scan_in_history(scan_config)
                print(f"❌ Scan {scan_id} failed: {results['error']}")
            
            return scan_config
            
        except Exception as e:
            error_msg = f"Unexpected error during scan: {str(e)}"
            scan_config['status'] = 'failed'
            scan_config['error'] = error_msg
            scan_config['end_time'] = datetime.now().isoformat()
            self.update_scan_in_history(scan_config)
            print(f"❌ Scan {scan_id} failed with exception: {e}")
            return scan_config
    
    def update_scan_in_history(self, scan_config):
        """Update scan in history"""
        for i, scan in enumerate(scan_history):
            if scan['id'] == scan_config['id']:
                scan_history[i] = scan_config
                break

# Initialize scan manager
try:
    scan_manager = ScanManager()
    print("✅ Scan manager initialized successfully")
except Exception as e:
    print(f"❌ Failed to initialize scan manager: {e}")
    scan_manager = None

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    if scan_manager is None:
        return jsonify({'error': 'Scanner not available'}), 503
    
    try:
        scan_config = request.json
        
        if not scan_config:
            return jsonify({'error': 'No scan configuration provided'}), 400
        
        # Generate unique scan ID
        scan_config['id'] = f"scan_{int(time.time())}"
        
        # Validate required fields
        if not scan_config.get('scan_type'):
            return jsonify({'error': 'Scan type is required'}), 400
        
        if scan_config['scan_type'] == 'collection' and not scan_config.get('collection_file'):
            return jsonify({'error': 'Collection file is required'}), 400
        
        # Run scan in background
        def run_scan_async():
            try:
                scan_manager.run_scan(scan_config)
            except Exception as e:
                print(f"❌ Background scan failed: {e}")
        
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
    """Get scan history with filtering and pagination"""
    try:
        scan_manager.load_scan_history()  # Always reload from disk
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        status_filter = request.args.get('status', '')
        search_query = request.args.get('search', '')
        
        # Filter scans
        filtered_scans = scan_history
        
        if status_filter:
            filtered_scans = [s for s in filtered_scans if s.get('status') == status_filter]
        
        if search_query:
            search_lower = search_query.lower()
            filtered_scans = [s for s in filtered_scans if 
                            search_lower in s.get('id', '').lower() or
                            search_lower in s.get('scan_type', '').lower()]
        
        # Paginate
        total_scans = len(filtered_scans)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_scans = filtered_scans[start_idx:end_idx]
        
        return jsonify({
            'scans': paginated_scans,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_scans,
                'pages': (total_scans + per_page - 1) // per_page
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<scan_id>/<report_type>')
def download_report(scan_id, report_type):
    """Download a specific report"""
    try:
        scan = next((s for s in scan_history if s['id'] == scan_id), None)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if report_type == 'json':
            report_file = scan.get('report_file')
        elif report_type == 'html':
            report_file = scan.get('html_report')
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
    """View a report in the browser, generating HTML on demand if missing"""
    try:
        scan = next((s for s in scan_history if s['id'] == scan_id), None)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        report_file = scan.get('html_report')
        json_report_file = scan.get('report_file')
        
        # If HTML report does not exist, generate it from JSON
        if (not report_file or not os.path.exists(report_file)) and json_report_file and os.path.exists(json_report_file):
            try:
                with open(json_report_file, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                
                # Generate HTML report in the correct location
                html_report_path = generate_html_report_from_json(report_data, scan_id)
                scan['html_report'] = html_report_path
                report_file = html_report_path
                
            except Exception as e:
                return jsonify({'error': f'Failed to generate HTML report: {e}'}), 500
        
        if not report_file or not os.path.exists(report_file):
            return jsonify({'error': 'Report file not found'}), 404
        
        return send_file(report_file)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<scan_id>/owasp')
def download_owasp_report(scan_id):
    """Download OWASP HTML report, generating on demand if missing"""
    try:
        scan = next((s for s in scan_history if s['id'] == scan_id), None)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        report_file = scan.get('reports', {}).get('owasp_report')
        json_report_file = scan.get('report_file')
        
        # If OWASP HTML report does not exist, generate it from JSON
        if (not report_file or not os.path.exists(report_file)) and json_report_file and os.path.exists(json_report_file):
            try:
                with open(json_report_file, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                
                # Generate OWASP HTML report in the correct location
                html_report_path = generate_owasp_html_report_from_json(report_data, scan_id)
                scan['reports'] = scan.get('reports', {})
                scan['reports']['owasp_report'] = html_report_path
                report_file = html_report_path
                
            except Exception as e:
                return jsonify({'error': f'Failed to generate OWASP HTML report: {e}'}), 500
        
        if not report_file or not os.path.exists(report_file):
            return jsonify({'error': 'Report file not found'}), 404
        
        return send_file(report_file, as_attachment=True)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_html_report_from_json(report_data, scan_id):
    """Generate HTML report from JSON data"""
    try:
        # Get project root directory (2 levels up from src/web/)
        project_root = Path(__file__).parent.parent.parent
        
        # Ensure reports/html directory exists
        html_dir = project_root / 'reports' / 'html'
        html_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate HTML report filename
        html_filename = f"api_security_report_{scan_id}.html"
        html_path = html_dir / html_filename
        
        # Extract scan results
        scan_results = report_data.get('scan_results', {})
        vulnerabilities = scan_results.get('vulnerabilities', [])
        scan_info = scan_results.get('scan_info', {})
        
        # Generate HTML content
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Report - {scan_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .summary {{ background-color: #e9ecef; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .vulnerability {{ margin: 15px 0; padding: 20px; border-left: 4px solid #dc3545; background-color: #f8f9fa; border-radius: 4px; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .severity {{ font-weight: bold; padding: 5px 10px; border-radius: 4px; color: white; }}
        .severity-critical {{ background-color: #dc3545; }}
        .severity-high {{ background-color: #fd7e14; }}
        .severity-medium {{ background-color: #ffc107; color: #212529; }}
        .severity-low {{ background-color: #28a745; }}
        .endpoint {{ background-color: #f1f3f4; padding: 10px; border-radius: 4px; margin: 10px 0; }}
        .error-summary {{ background-color: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .evidence-section {{ background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 15px; margin: 10px 0; }}
        .evidence-section h4 {{ margin-top: 0; color: #495057; border-bottom: 1px solid #dee2e6; padding-bottom: 5px; }}
        .evidence-section pre {{ background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 10px; overflow-x: auto; font-size: 12px; }}
        .evidence-section code {{ background-color: #e9ecef; padding: 2px 4px; border-radius: 3px; font-family: 'Courier New', monospace; }}
        .evidence-section ul {{ margin: 10px 0; padding-left: 20px; }}
        .evidence-section li {{ margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 API Security Scan Report</h1>
        <p><strong>Scan ID:</strong> {scan_id}</p>
        <p><strong>Scan Date:</strong> {scan_info.get('start_time', 'Unknown')}</p>
        <p><strong>Duration:</strong> {scan_info.get('duration', 0):.2f} seconds</p>
    </div>
    
    <div class="summary">
        <h2>📊 Scan Summary</h2>
        <p><strong>Total Endpoints Scanned:</strong> {scan_info.get('endpoints_scanned', 0)}</p>
        <p><strong>Total Vulnerabilities Found:</strong> {len(vulnerabilities)}</p>
        <p><strong>High Severity:</strong> {len([v for v in vulnerabilities if v.get('severity') == 'High'])}</p>
        <p><strong>Medium Severity:</strong> {len([v for v in vulnerabilities if v.get('severity') == 'Medium'])}</p>
        <p><strong>Low Severity:</strong> {len([v for v in vulnerabilities if v.get('severity') == 'Low'])}</p>
    </div>
    
    <h2>🚨 Vulnerabilities Found</h2>
"""
        
        if vulnerabilities:
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Medium')
                severity_class = severity.lower()
                html_content += f"""
    <div class="vulnerability {severity_class}">
        <h3>{vuln.get('type', 'Unknown Vulnerability')}</h3>
        <p><strong>Severity:</strong> <span class="severity severity-{severity_class}">{severity}</span></p>
        <p><strong>Category:</strong> {vuln.get('category', 'Unknown')}</p>
        <p><strong>Endpoint:</strong> <span class="endpoint">{vuln.get('url', 'N/A')}</span></p>
        <p><strong>Method:</strong> {vuln.get('method', 'N/A')}</p>
        <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
"""
                
                # Enhanced evidence section with request/response details
                evidence = vuln.get('evidence', 'No evidence available')
                html_content += f"""
        <p><strong>Evidence Summary:</strong> {evidence}</p>
"""
                
                # Request details
                request_data = vuln.get('request_data')
                if request_data:
                    html_content += """
        <div class="evidence-section">
            <h4>Request Details</h4>
"""
                    
                    # Request method and URL
                    req_method = request_data.get('method', 'N/A')
                    req_url = request_data.get('url', 'N/A')
                    html_content += f"""
            <p><strong>Method:</strong> {req_method}</p>
            <p><strong>URL:</strong> <code>{req_url}</code></p>
"""
                    
                    # Request headers
                    req_headers = request_data.get('headers', {})
                    if req_headers:
                        html_content += """
            <p><strong>Headers:</strong></p>
            <pre><code>
"""
                        for header, value in list(req_headers.items())[:5]:  # Show first 5 headers
                            html_content += f"{header}: {value}\n"
                        if len(req_headers) > 5:
                            html_content += f"... and {len(req_headers) - 5} more headers\n"
                        html_content += """
            </code></pre>
"""
                    
                    # Request parameters/body
                    req_params = request_data.get('params')
                    if req_params:
                        html_content += """
            <p><strong>Parameters:</strong></p>
            <pre><code>
"""
                        for param, value in req_params.items():
                            html_content += f"{param}: {value}\n"
                        html_content += """
            </code></pre>
"""
                    
                    req_json = request_data.get('json')
                    if req_json:
                        html_content += """
            <p><strong>JSON Body:</strong></p>
            <pre><code>
"""
                        html_content += json.dumps(req_json, indent=2)
                        html_content += """
            </code></pre>
"""
                    
                    html_content += """
        </div>
"""
                
                # Response details
                response_data = vuln.get('response_data')
                if response_data:
                    html_content += """
        <div class="evidence-section">
            <h4>Response Details</h4>
"""
                    
                    # Response status
                    resp_status = response_data.get('status_code', 'N/A')
                    html_content += f"""
            <p><strong>Status Code:</strong> {resp_status}</p>
"""
                    
                    # Response headers
                    resp_headers = response_data.get('headers', {})
                    if resp_headers:
                        html_content += """
            <p><strong>Response Headers:</strong></p>
            <pre><code>
"""
                        for header, value in list(resp_headers.items())[:5]:  # Show first 5 headers
                            html_content += f"{header}: {value}\n"
                        if len(resp_headers) > 5:
                            html_content += f"... and {len(resp_headers) - 5} more headers\n"
                        html_content += """
            </code></pre>
"""
                    
                    # Response content
                    resp_content = response_data.get('content', '')
                    if resp_content:
                        html_content += """
            <p><strong>Response Content:</strong></p>
            <pre><code>
"""
                        # Truncate content if too long
                        if len(resp_content) > 1000:
                            content_preview = resp_content[:1000] + "... (truncated)"
                        else:
                            content_preview = resp_content
                        html_content += content_preview
                        html_content += """
            </code></pre>
"""
                    
                    # Special handling for rate limiting tests
                    if 'responses' in response_data:
                        html_content += """
            <p><strong>Rate Limiting Test Results:</strong></p>
            <ul>
"""
                        responses = response_data.get('responses', [])
                        for j, resp in enumerate(responses[:3]):  # Show first 3 responses
                            status = resp.get('status_code', 'N/A')
                            html_content += f"""
                <li>Request {j+1}: Status {status}</li>
"""
                        if len(responses) > 3:
                            html_content += f"""
                <li>... and {len(responses) - 3} more responses</li>
"""
                        html_content += """
            </ul>
"""
                    
                    # Special handling for HTTP methods tests
                    if 'method_results' in response_data:
                        html_content += """
            <p><strong>HTTP Methods Test Results:</strong></p>
            <ul>
"""
                        method_results = response_data.get('method_results', [])
                        for method_result in method_results:
                            method_name = method_result.get('method', 'N/A')
                            status = method_result.get('status_code', 'N/A')
                            allowed = method_result.get('allowed', False)
                            status_text = 'Allowed' if allowed else 'Blocked'
                            html_content += f"""
                <li>{method_name}: Status {status} ({status_text})</li>
"""
                        html_content += """
            </ul>
"""
                    
                    html_content += """
        </div>
"""
                
                # If no detailed request/response data, show basic evidence
                if not request_data and not response_data:
                    html_content += f"""
        <p><strong>Evidence:</strong> {evidence}</p>
"""
                
                html_content += """
    </div>
"""
        else:
            html_content += """
    <div class="vulnerability low">
        <h3>✅ No Vulnerabilities Found</h3>
        <p>Congratulations! No security vulnerabilities were detected in this scan.</p>
    </div>
"""
        
        # Add error summary if available
        error_summary = report_data.get('error_summary', [])
        if error_summary:
            html_content += """
    <h2>⚠️ Error Summary</h2>
    <div class="error-summary">
        <h3>Issues Encountered During Scan</h3>
        <ul>
"""
            for error in error_summary:
                html_content += f"            <li>{error}</li>\n"
            html_content += """
        </ul>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        # Write the HTML file
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(html_path)
        
    except Exception as e:
        print(f"Error generating HTML report: {e}")
        raise

def generate_owasp_html_report_from_json(report_data, scan_id):
    """Generate OWASP HTML report from JSON data"""
    try:
        # Get project root directory (2 levels up from src/web/)
        project_root = Path(__file__).parent.parent.parent
        
        # Ensure reports/html directory exists
        html_dir = project_root / 'reports' / 'html'
        html_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate HTML report filename
        html_filename = f"owasp_report_{scan_id}.html"
        html_path = html_dir / html_filename
        
        # Extract scan results
        scan_results = report_data.get('scan_results', {})
        vulnerabilities = scan_results.get('vulnerabilities', [])
        scan_info = scan_results.get('scan_info', {})
        
        # Group vulnerabilities by OWASP category
        owasp_vulns = {}
        for vuln in vulnerabilities:
            category = vuln.get('owasp_category', 'Other')
            if category not in owasp_vulns:
                owasp_vulns[category] = []
            owasp_vulns[category].append(vuln)
        
        # Generate HTML content
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP API Top 10 Report - {scan_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .summary {{ background-color: #e9ecef; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .vulnerability {{ margin: 15px 0; padding: 20px; border-left: 4px solid #dc3545; background-color: #f8f9fa; border-radius: 4px; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .severity {{ font-weight: bold; padding: 5px 10px; border-radius: 4px; color: white; }}
        .severity-critical {{ background-color: #dc3545; }}
        .severity-high {{ background-color: #fd7e14; }}
        .severity-medium {{ background-color: #ffc107; color: #212529; }}
        .severity-low {{ background-color: #28a745; }}
        .endpoint {{ background-color: #f1f3f4; padding: 10px; border-radius: 4px; margin: 10px 0; }}
        .category {{ background-color: #e3f2fd; padding: 15px; border-radius: 8px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 OWASP API Top 10 Security Report</h1>
        <p><strong>Scan ID:</strong> {scan_id}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Scan Summary</h2>
        <p><strong>Total Endpoints Scanned:</strong> {scan_info.get('endpoints_scanned', 0)}</p>
        <p><strong>Total Vulnerabilities Found:</strong> {len(vulnerabilities)}</p>
        <p><strong>OWASP Categories Found:</strong> {len(owasp_vulns)}</p>
        <p><strong>Scan Duration:</strong> {scan_info.get('duration', 0):.2f} seconds</p>
    </div>
    
    <h2>🚨 Vulnerabilities by OWASP Category</h2>
"""
        
        if owasp_vulns:
            for category, vulns in owasp_vulns.items():
                html_content += f"""
    <div class="category">
        <h3>{category}</h3>
        <p>Found {len(vulns)} vulnerabilities</p>
"""
                
                for vuln in vulns:
                    severity = vuln.get('severity', 'Medium')
                    severity_class = severity.lower()
                    html_content += f"""
        <div class="vulnerability {severity_class}">
            <h4>{vuln.get('type', 'Unknown Vulnerability')}</h4>
            <p><strong>Severity:</strong> <span class="severity severity-{severity_class}">{severity}</span></p>
            <p><strong>Endpoint:</strong> <span class="endpoint">{vuln.get('url', 'N/A')}</span></p>
            <p><strong>Method:</strong> {vuln.get('method', 'N/A')}</p>
            <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
            <p><strong>Evidence:</strong> {vuln.get('evidence', 'No evidence available')}</p>
        </div>
"""
                html_content += "    </div>\n"
        else:
            html_content += """
    <div class="vulnerability low">
        <h3>✅ No OWASP Vulnerabilities Found</h3>
        <p>Congratulations! No OWASP API Top 10 vulnerabilities were detected in this scan.</p>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        # Write the HTML file
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(html_path)
        
    except Exception as e:
        print(f"Error generating OWASP HTML report: {e}")
        raise

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
                'file_path': str(file_path)
            })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """Get scanning statistics"""
    try:
        total_scans = len(scan_history)
        completed_scans = len([s for s in scan_history if s.get('status') == 'completed'])
        failed_scans = len([s for s in scan_history if s.get('status') == 'failed'])
        running_scans = len([s for s in scan_history if s.get('status') == 'running'])
        
        total_vulnerabilities = sum(s.get('vulnerabilities_found', 0) for s in scan_history)
        total_endpoints = sum(s.get('endpoints_found', 0) for s in scan_history)
        
        return jsonify({
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'failed_scans': failed_scans,
            'running_scans': running_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'total_endpoints': total_endpoints,
            'success_rate': (completed_scans / total_scans * 100) if total_scans > 0 else 0
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'scanner_available': APISecurityScanner is not None,
        'scan_manager_available': scan_manager is not None,
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("🔒 API Security Scanner - Web UI")
    print("=" * 50)
    print(f"🌐 Server: {HOST}:{PORT}")
    print(f"🐛 Debug: {DEBUG}")
    print(f"📁 Working directory: {os.getcwd()}")
    print("=" * 50)
    
    try:
        app.run(
            host=HOST,
            port=PORT,
            debug=DEBUG,
            threaded=True
        )
    except Exception as e:
        print(f"❌ Failed to start web server: {e}")
        sys.exit(1) 