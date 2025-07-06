#!/usr/bin/env python3
"""
JWT Security Testing Tool - REST API
"""
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import tempfile
from jwt_security_tester import JWTSecurityTester

app = Flask(__name__)
CORS(app)

tester = JWTSecurityTester(debug=False)

@app.route('/status', methods=['GET'])
def status():
    return jsonify({"status": "ok", "message": "JWT Security Testing Tool API is running"})

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json(force=True)
    token = data.get('token')
    secret = data.get('secret')
    public_key = data.get('public_key')
    if not token:
        return jsonify({"error": "Missing 'token' in request"}), 400
    try:
        results = tester.comprehensive_test(token, secret, public_key)
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/batch', methods=['POST'])
def batch():
    data = request.get_json(force=True)
    tokens = data.get('tokens')
    secret = data.get('secret')
    if not tokens or not isinstance(tokens, list):
        return jsonify({"error": "Missing or invalid 'tokens' list in request"}), 400
    all_results = []
    for token in tokens:
        try:
            result = tester.comprehensive_test(token, secret)
            all_results.append(result)
        except Exception as e:
            all_results.append({"error": str(e), "token_preview": token[:50]})
    return jsonify({"results": all_results})

@app.route('/report', methods=['POST'])
def report():
    data = request.get_json(force=True)
    results = data.get('results')
    output_format = data.get('format', 'html')
    if not results:
        return jsonify({"error": "Missing 'results' in request"}), 400
    try:
        if output_format == 'html':
            with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as tmp:
                tester.generate_html_report(results, tmp.name)
                tmp.flush()
                return send_file(tmp.name, mimetype='text/html', as_attachment=True, download_name='jwt_report.html')
        else:
            return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('JWT_API_PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 