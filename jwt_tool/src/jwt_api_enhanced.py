#!/usr/bin/env python3
"""
JWT Security Testing Tool - Enhanced REST API with Scan ID Management
"""
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import tempfile
import uuid
import json
from datetime import datetime
from jwt_security_tester import JWTSecurityTester

# Create separate reports directories for CLI and API
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLI_REPORTS_DIR = os.path.join(BASE_DIR, '..', 'reports', 'cli')
API_REPORTS_DIR = os.path.join(BASE_DIR, '..', 'reports', 'api')

# Create directories if they don't exist
os.makedirs(CLI_REPORTS_DIR, exist_ok=True)
os.makedirs(API_REPORTS_DIR, exist_ok=True)

# API uses the API reports directory
REPORTS_DIR = API_REPORTS_DIR

app = Flask(__name__)
CORS(app)

# Global storage for scan sessions (in production, use a database)
scan_sessions = {}
tester = JWTSecurityTester(debug=False)

def generate_scan_id():
    """Generate a unique scan ID."""
    return str(uuid.uuid4())

def store_scan_results(scan_id, results, scan_type="single"):
    """Store scan results with metadata."""
    scan_sessions[scan_id] = {
        "scan_id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "scan_type": scan_type,
        "results": results,
        "status": "completed"
    }
    return scan_id

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "status": "ok", 
        "message": "JWT Security Testing Tool API is running",
        "active_scans": len(scan_sessions),
        "reports_directory": REPORTS_DIR,
        "total_reports": len([f for f in os.listdir(REPORTS_DIR) if f.endswith('.html') and f.startswith('api_scan_')])
    })

@app.route('/scan/start', methods=['POST'])
def start_scan():
    """Start a new scan session."""
    data = request.get_json(force=True)
    scan_type = data.get('scan_type', 'single')  # single, batch
    description = data.get('description', '')
    
    scan_id = generate_scan_id()
    scan_sessions[scan_id] = {
        "scan_id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "scan_type": scan_type,
        "description": description,
        "status": "started",
        "results": None
    }
    
    return jsonify({
        "scan_id": scan_id,
        "status": "started",
        "message": f"Scan session {scan_id} created"
    })

@app.route('/scan/<scan_id>/analyze', methods=['POST'])
def analyze_with_scan_id(scan_id):
    """Analyze JWT with scan ID tracking."""
    if scan_id not in scan_sessions:
        return jsonify({"error": "Invalid scan ID"}), 404
    
    data = request.get_json(force=True)
    token = data.get('token')
    secret = data.get('secret')
    public_key = data.get('public_key')
    
    if not token:
        return jsonify({"error": "Missing 'token' in request"}), 400
    
    try:
        # Update scan status
        scan_sessions[scan_id]["status"] = "running"
        
        # Perform analysis
        results = tester.comprehensive_test(token, secret, public_key)
        
        # Store results
        store_scan_results(scan_id, results, "single")
        
        return jsonify({
            "scan_id": scan_id,
            "status": "completed",
            "results": results
        })
    except Exception as e:
        scan_sessions[scan_id]["status"] = "failed"
        scan_sessions[scan_id]["error"] = str(e)
        return jsonify({"error": str(e), "scan_id": scan_id}), 500

@app.route('/scan/<scan_id>/batch', methods=['POST'])
def batch_with_scan_id(scan_id):
    """Batch analysis with scan ID tracking."""
    if scan_id not in scan_sessions:
        return jsonify({"error": "Invalid scan ID"}), 404
    
    data = request.get_json(force=True)
    tokens = data.get('tokens')
    secret = data.get('secret')
    
    if not tokens or not isinstance(tokens, list):
        return jsonify({"error": "Missing or invalid 'tokens' list in request"}), 400
    
    try:
        # Update scan status
        scan_sessions[scan_id]["status"] = "running"
        
        # Perform batch analysis
        all_results = []
        for i, token in enumerate(tokens):
            try:
                result = tester.comprehensive_test(token, secret)
                result["token_index"] = i
                all_results.append(result)
            except Exception as e:
                all_results.append({
                    "error": str(e), 
                    "token_preview": token[:50],
                    "token_index": i
                })
        
        # Store results
        store_scan_results(scan_id, all_results, "batch")
        
        return jsonify({
            "scan_id": scan_id,
            "status": "completed",
            "results": all_results
        })
    except Exception as e:
        scan_sessions[scan_id]["status"] = "failed"
        scan_sessions[scan_id]["error"] = str(e)
        return jsonify({"error": str(e), "scan_id": scan_id}), 500

@app.route('/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status and metadata."""
    if scan_id not in scan_sessions:
        return jsonify({"error": "Invalid scan ID"}), 404
    
    scan = scan_sessions[scan_id]
    return jsonify({
        "scan_id": scan_id,
        "status": scan["status"],
        "timestamp": scan["timestamp"],
        "scan_type": scan["scan_type"],
        "description": scan.get("description", ""),
        "has_results": scan["results"] is not None
    })

@app.route('/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get scan results."""
    if scan_id not in scan_sessions:
        return jsonify({"error": "Invalid scan ID"}), 404
    
    scan = scan_sessions[scan_id]
    if scan["results"] is None:
        return jsonify({"error": "No results available for this scan"}), 404
    
    return jsonify({
        "scan_id": scan_id,
        "results": scan["results"]
    })

@app.route('/scan/<scan_id>/report', methods=['GET'])
def get_scan_report(scan_id):
    """Generate and download report for a scan."""
    if scan_id not in scan_sessions:
        return jsonify({"error": "Invalid scan ID"}), 404
    
    scan = scan_sessions[scan_id]
    if scan["results"] is None:
        return jsonify({"error": "No results available for this scan"}), 404
    
    output_format = request.args.get('format', 'html')
    
    try:
        if output_format == 'html':
            # Create report filename with API-specific naming convention
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"api_scan_{scan_id}_{timestamp}.html"
            filepath = os.path.join(REPORTS_DIR, filename)
            
            # Generate and save report locally
            tester.generate_html_report(scan["results"], filepath)
            
            # Store report path in scan session
            scan["report_file"] = filepath
            scan["report_generated"] = timestamp
            
            # Return the file for download
            return send_file(
                filepath, 
                mimetype='text/html', 
                as_attachment=True, 
                download_name=filename
            )
        else:
            return jsonify(scan["results"])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scans', methods=['GET'])
def list_scans():
    """List all scan sessions."""
    scans = []
    for scan_id, scan in scan_sessions.items():
        scan_info = {
            "scan_id": scan_id,
            "timestamp": scan["timestamp"],
            "scan_type": scan["scan_type"],
            "status": scan["status"],
            "description": scan.get("description", "")
        }
        
        # Add report information if available
        if "report_file" in scan:
            scan_info["has_report"] = True
            scan_info["report_file"] = os.path.basename(scan["report_file"])
            scan_info["report_generated"] = scan.get("report_generated", "")
        else:
            scan_info["has_report"] = False
        
        scans.append(scan_info)
    
    return jsonify({
        "total_scans": len(scans),
        "scans": scans
    })

@app.route('/reports', methods=['GET'])
def list_reports():
    """List all available reports."""
    try:
        reports = []
        for filename in os.listdir(REPORTS_DIR):
            if filename.endswith('.html') and filename.startswith('api_scan_'):
                filepath = os.path.join(REPORTS_DIR, filename)
                file_stat = os.stat(filepath)
                
                # Extract scan ID from filename
                parts = filename.replace('.html', '').split('_')
                scan_id = parts[2] if len(parts) >= 3 else "unknown"
                
                reports.append({
                    "filename": filename,
                    "scan_id": scan_id,
                    "file_size": file_stat.st_size,
                    "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                    "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                })
        
        # Sort by creation time (newest first)
        reports.sort(key=lambda x: x["created"], reverse=True)
        
        return jsonify({
            "total_reports": len(reports),
            "reports_directory": REPORTS_DIR,
            "reports": reports
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/reports/<filename>', methods=['GET'])
def download_report(filename):
    """Download a specific report file."""
    try:
        filepath = os.path.join(REPORTS_DIR, filename)
        if not os.path.exists(filepath):
            return jsonify({"error": "Report file not found"}), 404
        
        return send_file(
            filepath,
            mimetype='text/html',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scan/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan session."""
    if scan_id not in scan_sessions:
        return jsonify({"error": "Invalid scan ID"}), 404
    
    del scan_sessions[scan_id]
    return jsonify({"message": f"Scan {scan_id} deleted successfully"})

# Legacy endpoints (for backward compatibility)
@app.route('/analyze', methods=['POST'])
def analyze():
    """Legacy analyze endpoint - creates a scan ID automatically."""
    scan_id = generate_scan_id()
    return analyze_with_scan_id(scan_id)

@app.route('/batch', methods=['POST'])
def batch():
    """Legacy batch endpoint - creates a scan ID automatically."""
    scan_id = generate_scan_id()
    return batch_with_scan_id(scan_id)

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('JWT_API_PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 