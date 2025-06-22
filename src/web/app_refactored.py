#!/usr/bin/env python3
"""
API Security Scanner - Refactored Web UI
A web-based interface using the refactored scanner with improved modularity
"""

import os
import json
import time
import sys
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from werkzeug.utils import secure_filename
import threading
import queue
import logging

# Add src directory to Python path
src_path = Path(__file__).parent.parent
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Import configuration and scanner with error handling
try:
    from src.config.app_config import get_config
    config = get_config()
    print("✅ Configuration loaded successfully")
except ImportError as e:
    print(f"⚠️  Warning: Could not import configuration: {e}")
    config = None

try:
    from core.scanner_refactored import APISecurityScannerRefactored, ScanError, ConfigurationError
    ScannerClass = APISecurityScannerRefactored
    print("✅ Refactored scanner imported successfully")
except ImportError as e:
    print(f"⚠️  Warning: Could not import refactored scanner: {e}")
    try:
        from src.core.api_security_scanner import APISecurityScanner
        ScannerClass = APISecurityScanner
        print("✅ Fallback scanner imported successfully")
    except ImportError as e2:
        print(f"❌ Error: Could not import any scanner: {e2}")
        ScannerClass = None

# Setup logging
if config:
    log_config = config.get_logging_config()
    logging.basicConfig(
        level=getattr(logging, log_config['level']),
        format=log_config['format'],
        handlers=[
            logging.FileHandler(log_config['file']),
            logging.StreamHandler()
        ]
    )
else:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)

if config:
    web_config = config.get_web_config()
    app.config['MAX_CONTENT_LENGTH'] = web_config['max_content_length']
    app.config['SECRET_KEY'] = web_config['secret_key']
    HOST = web_config['host']
    PORT = web_config['port']
    DEBUG = web_config['debug']
else:
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
    app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
    HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
    PORT = int(os.environ.get('FLASK_PORT', 5000))
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'

# Global variables
scan_queue = queue.Queue()
scan_results = {}
scan_history = []

class RefactoredScanManager:
    """Manages API security scans using the refactored scanner"""
    
    def __init__(self):
        if ScannerClass is None:
            raise RuntimeError("No scanner available")
        
        # Initialize scanner with configuration
        scanner_config = config.get_scanner_config() if config else {}
        self.scanner = ScannerClass(
            max_workers=scanner_config.get('max_workers', 10)
        )
        
        # Ensure directories exist
        if config:
            config.ensure_directories()
        
        self.load_scan_history()
        logger.info("Refactored scan manager initialized successfully")
    
    def load_scan_history(self):
        """Load scan history from reports directory with error handling"""
        global scan_history
        try:
            # Get reports directory from config
            if config:
                reports_dir = Path(config.get_paths_config()['reports_dir'])
            else:
                reports_dir = Path('reports')
            
            json_reports_dir = reports_dir / 'json'
            
            if not json_reports_dir.exists():
                logger.info(f"📁 Creating reports directory: {json_reports_dir}")
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
                        
                        scan_info = {
                            'id': scan_id,
                            'scan_type': 'collection',
                            'status': 'completed',
                            'start_time': report_data.get('scan_start_time', ''),
                            'end_time': report_data.get('scan_end_time', ''),
                            'endpoints_found': report_data.get('endpoints_found', 0),
                            'vulnerabilities_found': len(report_data.get('vulnerabilities', [])),
                            'report_file': str(report_file),
                            'html_report': str(report_file).replace('json', 'html').replace('.json', '.html'),
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
                    logger.warning(f"⚠️  Error loading report {report_file}: {e}")
            
            # Sort by start time (newest first)
            scan_history.sort(key=lambda x: x.get('start_time', ''), reverse=True)
            logger.info(f"📊 Loaded {len(scan_history)} scan reports")
            
        except Exception as e:
            logger.error(f"❌ Error loading scan history: {e}")
    
    def run_scan(self, scan_config):
        """Run a security scan with comprehensive error handling"""
        scan_id = scan_config.get('id', f"scan_{int(time.time())}")
        
        try:
            scan_config['id'] = scan_id
            scan_config['status'] = 'running'
            scan_config['start_time'] = datetime.now().isoformat()
            
            # Add to scan history
            scan_history.insert(0, scan_config)
            
            logger.info(f"🚀 Starting scan {scan_id}: {scan_config.get('scan_type', 'unknown')}")
            
            # Run the scan
            if scan_config['scan_type'] == 'collection':
                collection_file = scan_config.get('collection_file')
                base_url = scan_config.get('base_url')
                auth_config = scan_config.get('auth_config')
                
                if not collection_file or not os.path.exists(collection_file):
                    raise FileNotFoundError(f"Collection file not found: {collection_file}")
                
                results = self.scanner.upload_and_scan_collection(
                    collection_file,
                    base_url,
                    auth_config
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
                    scan_config['endpoints_found'] = results.get('endpoints_scanned', 0)
                    scan_config['vulnerabilities_found'] = len(results.get('vulnerabilities_found', []))
                    
                    logger.info(f"✅ Scan {scan_id} completed successfully")
                    
                except Exception as e:
                    logger.warning(f"⚠️  Error generating reports for scan {scan_id}: {e}")
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
                logger.error(f"❌ Scan {scan_id} failed: {results['error']}")
            
            return scan_config
            
        except Exception as e:
            error_msg = f"Unexpected error during scan: {str(e)}"
            scan_config['status'] = 'failed'
            scan_config['error'] = error_msg
            scan_config['end_time'] = datetime.now().isoformat()
            self.update_scan_in_history(scan_config)
            logger.error(f"❌ Scan {scan_id} failed with exception: {e}")
            return scan_config
    
    def update_scan_in_history(self, scan_config):
        """Update scan in history"""
        for i, scan in enumerate(scan_history):
            if scan['id'] == scan_config['id']:
                scan_history[i] = scan_config
                break

# Initialize scan manager
try:
    scan_manager = RefactoredScanManager()
    logger.info("✅ Refactored scan manager initialized successfully")
except Exception as e:
    logger.error(f"❌ Failed to initialize scan manager: {e}")
    scan_manager = None

@app.route('/')
def index():
    """Main page"""
    return render_template('enhanced_index.html')

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
                logger.error(f"❌ Background scan failed: {e}")
        
        thread = threading.Thread(target=run_scan_async)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'scan_id': scan_config['id'],
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
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
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans')
def get_scan_history():
    """Get scan history with filtering and pagination"""
    try:
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
        logger.error(f"Error getting scan history: {e}")
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
        logger.error(f"Error downloading report: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<scan_id>/view')
def view_report(scan_id):
    """View a report in the browser"""
    try:
        scan = next((s for s in scan_history if s['id'] == scan_id), None)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        report_file = scan.get('html_report')
        if not report_file or not os.path.exists(report_file):
            return jsonify({'error': 'Report file not found'}), 404
        
        return send_file(report_file)
        
    except Exception as e:
        logger.error(f"Error viewing report: {e}")
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
            
            # Get uploads directory from config
            if config:
                uploads_dir = Path(config.get_paths_config()['uploads_dir'])
            else:
                uploads_dir = Path('uploads')
            
            uploads_dir.mkdir(exist_ok=True)
            file_path = uploads_dir / filename
            file.save(str(file_path))
            
            return jsonify({
                'success': True,
                'filename': filename,
                'file_path': str(file_path)
            })
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
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
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'scanner_available': ScannerClass is not None,
        'scan_manager_available': scan_manager is not None,
        'config_available': config is not None,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/config')
def get_config_info():
    """Get configuration information"""
    if not config:
        return jsonify({'error': 'Configuration not available'}), 503
    
    try:
        return jsonify({
            'web_config': config.get_web_config(),
            'scanner_config': config.get_scanner_config(),
            'paths_config': config.get_paths_config(),
            'security_config': config.get_security_config(),
            'logging_config': config.get_logging_config(),
            'reports_config': config.get_reports_config()
        })
    except Exception as e:
        logger.error(f"Error getting config info: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🔒 API Security Scanner - Refactored Web UI")
    print("=" * 50)
    print(f"🌐 Server: {HOST}:{PORT}")
    print(f"🐛 Debug: {DEBUG}")
    print(f"📁 Working directory: {os.getcwd()}")
    print(f"🔧 Configuration: {'✅ Available' if config else '❌ Not available'}")
    print(f"🔍 Scanner: {'✅ Available' if ScannerClass else '❌ Not available'}")
    print("=" * 50)
    
    try:
        app.run(
            host=HOST,
            port=PORT,
            debug=DEBUG,
            threaded=True
        )
    except Exception as e:
        logger.error(f"❌ Failed to start web server: {e}")
        sys.exit(1) 