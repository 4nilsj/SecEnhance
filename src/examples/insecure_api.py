#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple Insecure API for Testing Security Scanner
This API intentionally contains security vulnerabilities for testing purposes.
DO NOT USE IN PRODUCTION!
"""

from flask import Flask, request, jsonify
import sqlite3
import os
import subprocess
import json

app = Flask(__name__)

# Create a simple database for testing
def init_db():
    """Initialize test database"""
    conn = sqlite3.connect('test_api.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            title TEXT,
            content TEXT,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Insert some test data
    cursor.execute("INSERT OR IGNORE INTO users (username, email, password) VALUES (?, ?, ?)", 
                   ('admin', 'admin@test.com', 'admin123'))
    cursor.execute("INSERT OR IGNORE INTO users (username, email, password) VALUES (?, ?, ?)", 
                   ('user1', 'user1@test.com', 'password123'))
    cursor.execute("INSERT OR IGNORE INTO posts (title, content, user_id) VALUES (?, ?, ?)", 
                   ('Test Post', 'This is a test post content', 1))
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

@app.route('/')
def index():
    """Home page with API documentation"""
    return '''
    <h1>Insecure Test API</h1>
    <p>This API contains intentional security vulnerabilities for testing.</p>
    
    <h2>Available Endpoints:</h2>
    <ul>
        <li><strong>GET /api/users</strong> - Get all users (SQL Injection vulnerable)</li>
        <li><strong>GET /api/users/{id}</strong> - Get user by ID (SQL Injection vulnerable)</li>
        <li><strong>POST /api/users</strong> - Create user (XSS vulnerable)</li>
        <li><strong>GET /api/posts</strong> - Get all posts (SQL Injection vulnerable)</li>
        <li><strong>POST /api/posts</strong> - Create post (XSS vulnerable)</li>
        <li><strong>GET /api/search</strong> - Search endpoint (Command Injection vulnerable)</li>
        <li><strong>GET /api/file</strong> - File access (Path Traversal vulnerable)</li>
        <li><strong>POST /api/upload</strong> - File upload (Unrestricted upload vulnerable)</li>
        <li><strong>GET /api/redirect</strong> - Redirect endpoint (Open Redirect vulnerable)</li>
        <li><strong>GET /api/admin</strong> - Admin endpoint (Missing authentication)</li>
    </ul>
    
    <h2>Test Payloads:</h2>
    <ul>
        <li>SQL Injection: <code>1' OR '1'='1</code></li>
        <li>XSS: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
        <li>Command Injection: <code>; ls -la</code></li>
        <li>Path Traversal: <code>../../../etc/passwd</code></li>
    </ul>
    '''

@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all users - vulnerable to SQL injection"""
    search = request.args.get('search', '')
    
    conn = sqlite3.connect('test_api.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username LIKE '%{search}%'"
    cursor.execute(query)
    
    users = []
    for row in cursor.fetchall():
        users.append({
            'id': row[0],
            'username': row[1],
            'email': row[2],
            'password': row[3]  # VULNERABLE: Exposing passwords
        })
    
    conn.close()
    return jsonify(users)

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """Get user by ID - vulnerable to SQL injection"""
    conn = sqlite3.connect('test_api.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return jsonify({
            'id': row[0],
            'username': row[1],
            'email': row[2],
            'password': row[3]  # VULNERABLE: Exposing passwords
        })
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/api/users', methods=['POST'])
def create_user():
    """Create user - vulnerable to XSS"""
    data = request.get_json()
    
    # VULNERABLE: No input validation or sanitization
    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')
    
    conn = sqlite3.connect('test_api.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                      (username, email, password))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        # VULNERABLE: Reflected XSS
        return jsonify({
            'id': user_id,
            'username': username,
            'email': email,
            'message': f'User {username} created successfully'
        })
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Username already exists'}), 400

@app.route('/api/posts', methods=['GET'])
def get_posts():
    """Get all posts - vulnerable to SQL injection"""
    search = request.args.get('search', '')
    
    conn = sqlite3.connect('test_api.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id = u.id WHERE p.title LIKE '%{search}%'"
    cursor.execute(query)
    
    posts = []
    for row in cursor.fetchall():
        posts.append({
            'id': row[0],
            'title': row[1],
            'content': row[2],
            'user_id': row[3],
            'username': row[4]
        })
    
    conn.close()
    return jsonify(posts)

@app.route('/api/posts', methods=['POST'])
def create_post():
    """Create post - vulnerable to XSS"""
    data = request.get_json()
    
    # VULNERABLE: No input validation or sanitization
    title = data.get('title', '')
    content = data.get('content', '')
    user_id = data.get('user_id', 1)
    
    conn = sqlite3.connect('test_api.db')
    cursor = conn.cursor()
    
    cursor.execute("INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)", 
                  (title, content, user_id))
    conn.commit()
    post_id = cursor.lastrowid
    conn.close()
    
    # VULNERABLE: Reflected XSS
    return jsonify({
        'id': post_id,
        'title': title,
        'content': content,
        'user_id': user_id,
        'message': f'Post "{title}" created successfully'
    })

@app.route('/api/search', methods=['GET'])
def search():
    """Search endpoint - vulnerable to command injection"""
    query = request.args.get('q', '')
    
    # VULNERABLE: Command injection
    try:
        # Simulate a search command
        result = subprocess.check_output(f'echo "Searching for: {query}"', shell=True, text=True)
        return jsonify({
            'query': query,
            'result': result.strip()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file', methods=['GET'])
def read_file():
    """File access endpoint - vulnerable to path traversal"""
    filename = request.args.get('file', '')
    
    # VULNERABLE: Path traversal
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return jsonify({
            'filename': filename,
            'content': content
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """File upload endpoint - vulnerable to unrestricted upload"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # VULNERABLE: No file type validation
    filename = file.filename
    file.save(f'uploads/{filename}')
    
    return jsonify({
        'message': 'File uploaded successfully',
        'filename': filename,
        'path': f'uploads/{filename}'
    })

@app.route('/api/redirect', methods=['GET'])
def redirect():
    """Redirect endpoint - vulnerable to open redirect"""
    url = request.args.get('url', '')
    
    # VULNERABLE: Open redirect
    if url:
        return jsonify({
            'redirect_url': url,
            'message': f'Redirecting to: {url}'
        })
    else:
        return jsonify({'error': 'No URL provided'}), 400

@app.route('/api/admin', methods=['GET'])
def admin():
    """Admin endpoint - missing authentication"""
    # VULNERABLE: No authentication required
    return jsonify({
        'message': 'Welcome to admin panel',
        'users': [
            {'id': 1, 'username': 'admin', 'role': 'admin'},
            {'id': 2, 'username': 'user1', 'role': 'user'}
        ],
        'system_info': {
            'os': os.name,
            'cwd': os.getcwd(),
            'files': os.listdir('.')
        }
    })

@app.route('/api/auth', methods=['POST'])
def auth():
    """Authentication endpoint - vulnerable to weak authentication"""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    conn = sqlite3.connect('test_api.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Weak authentication (plain text comparison)
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'success': True,
            'message': 'Authentication successful',
            'user': {
                'id': user[0],
                'username': user[1],
                'email': user[2]
            }
        })
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

if __name__ == '__main__':
    # Create uploads directory
    os.makedirs('uploads', exist_ok=True)
    
    print("🚨 Starting Insecure Test API...")
    print("⚠️  WARNING: This API contains intentional security vulnerabilities!")
    print("📱 API will be available at: http://localhost:5001")
    print("🔍 Use this API to test your security scanner")
    print("🛑 DO NOT USE IN PRODUCTION!")
    
    app.run(host='0.0.0.0', port=5001, debug=True) 