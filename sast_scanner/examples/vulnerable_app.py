"""
Example vulnerable Python application for SAST testing.
This file contains intentional security vulnerabilities for demonstration purposes.
DO NOT USE IN PRODUCTION!
"""

import os
import sys
import sqlite3
import pickle
import yaml
import hashlib
import random
from flask import Flask, request, render_template_string

app = Flask(__name__)

# VULNERABILITY: Hardcoded credentials
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "my-secret-token-here"

# VULNERABILITY: Weak cryptography
def hash_password(password):
    """Hash password using weak MD5 algorithm."""
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILITY: Insecure random
def generate_token():
    """Generate random token using insecure random."""
    return str(random.randint(1000, 9999))

# VULNERABILITY: SQL Injection
def get_user_by_id(user_id):
    """Get user by ID with SQL injection vulnerability."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABILITY: SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    return user

# VULNERABILITY: Command Injection
def execute_command(command):
    """Execute system command with injection vulnerability."""
    # VULNERABILITY: Command injection
    os.system(command)

# VULNERABILITY: Path Traversal
def read_file(filename):
    """Read file with path traversal vulnerability."""
    # VULNERABILITY: Path traversal
    with open(filename, 'r') as f:
        return f.read()

# VULNERABILITY: Insecure Deserialization
def load_user_data(data):
    """Load user data with insecure deserialization."""
    # VULNERABILITY: Insecure deserialization
    return pickle.loads(data)

def load_config(config_data):
    """Load configuration with unsafe YAML loading."""
    # VULNERABILITY: Unsafe YAML loading
    return yaml.load(config_data)

# VULNERABILITY: XSS (if used in web context)
def render_user_profile(username):
    """Render user profile with XSS vulnerability."""
    # VULNERABILITY: XSS
    template = f"""
    <h1>Welcome {username}!</h1>
    <p>Your profile information:</p>
    <div>{username}</div>
    """
    return render_template_string(template)

# VULNERABILITY: Debug code in production
def debug_function():
    """Function with debug code."""
    print("Debug: This should not be in production")
    print(f"Debug: Current working directory: {os.getcwd()}")
    print(f"Debug: Python version: {sys.version}")

# VULNERABILITY: Eval usage
def evaluate_expression(expression):
    """Evaluate expression with eval vulnerability."""
    # VULNERABILITY: Eval usage
    return eval(expression)

# VULNERABILITY: Exec usage
def execute_code(code):
    """Execute code with exec vulnerability."""
    # VULNERABILITY: Exec usage
    exec(code)

# Flask routes with vulnerabilities
@app.route('/user/<user_id>')
def user_profile(user_id):
    """User profile page with multiple vulnerabilities."""
    # VULNERABILITY: SQL injection
    user = get_user_by_id(user_id)
    
    # VULNERABILITY: XSS
    return render_user_profile(user[1] if user else "Unknown")

@app.route('/upload', methods=['POST'])
def upload_file():
    """File upload with vulnerabilities."""
    file = request.files['file']
    filename = file.filename
    
    # VULNERABILITY: Path traversal
    file_path = f"uploads/{filename}"
    file.save(file_path)
    
    # VULNERABILITY: Command injection
    if filename.endswith('.sh'):
        execute_command(f"chmod +x {file_path}")
    
    return "File uploaded successfully"

@app.route('/config', methods=['POST'])
def update_config():
    """Update configuration with vulnerabilities."""
    config_data = request.get_json()
    
    # VULNERABILITY: Insecure deserialization
    config = load_config(config_data)
    
    # VULNERABILITY: Debug code
    debug_function()
    
    return "Configuration updated"

@app.route('/execute', methods=['POST'])
def execute_expression():
    """Execute expression with vulnerabilities."""
    expression = request.form.get('expression')
    
    # VULNERABILITY: Eval usage
    result = evaluate_expression(expression)
    
    return f"Result: {result}"

# Main function with vulnerabilities
def main():
    """Main function with various vulnerabilities."""
    # VULNERABILITY: Hardcoded credentials
    print(f"Connecting to database with password: {DATABASE_PASSWORD}")
    
    # VULNERABILITY: Weak cryptography
    password = "user123"
    hashed = hash_password(password)
    print(f"Password hash: {hashed}")
    
    # VULNERABILITY: Insecure random
    token = generate_token()
    print(f"Generated token: {token}")
    
    # VULNERABILITY: Debug code
    debug_function()
    
    # VULNERABILITY: Command injection
    user_input = input("Enter command: ")
    execute_command(user_input)
    
    # VULNERABILITY: Path traversal
    file_path = input("Enter file path: ")
    content = read_file(file_path)
    print(f"File content: {content}")

if __name__ == "__main__":
    main()
    app.run(debug=True)  # VULNERABILITY: Debug mode in production 