# Vulnerability Database

This document provides a comprehensive reference of all vulnerabilities supported by the AI-Enabled SAST Scanner.

## Table of Contents

- [Vulnerability Categories](#vulnerability-categories)
- [High Severity Vulnerabilities](#high-severity-vulnerabilities)
- [Medium Severity Vulnerabilities](#medium-severity-vulnerabilities)
- [Low Severity Vulnerabilities](#low-severity-vulnerabilities)
- [Detection Methods](#detection-methods)
- [AI Fix Capabilities](#ai-fix-capabilities)
- [Language Support](#language-support)
- [Custom Patterns](#custom-patterns)

## Vulnerability Categories

### Severity Levels

- **Critical** - Immediate action required, severe security impact
- **High** - Significant security risk, should be addressed quickly
- **Medium** - Moderate security risk, should be addressed
- **Low** - Minor security risk, consider addressing
- **Info** - Informational findings, no direct security risk

### Detection Methods

- **Pattern Matching** - Regex-based pattern detection
- **AST Analysis** - Abstract Syntax Tree analysis
- **Semantic Analysis** - AI-powered semantic understanding
- **Context Analysis** - Code context and flow analysis

## High Severity Vulnerabilities

### SQL Injection (CWE-89)

**Description:** SQL injection occurs when user input is directly concatenated into SQL queries without proper sanitization.

**Pattern Examples:**
```python
# Python - SQLite
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")

# Python - MySQL
cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")

# JavaScript - Node.js
db.query(`SELECT * FROM users WHERE id = ${userInput}`)

# PHP
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
```

**AI-Generated Fix:**
```python
# Python - Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))

# JavaScript - Parameterized query
db.query("SELECT * FROM users WHERE id = ?", [userInput]);

# PHP - Prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
```

**Impact:** Attackers can execute arbitrary SQL commands, potentially accessing, modifying, or deleting data.

**Languages Supported:** Python, JavaScript, PHP, Java, C#, Ruby, Go

### Cross-Site Scripting (XSS) (CWE-79)

**Description:** XSS occurs when user input is rendered as HTML/JavaScript without proper sanitization.

**Pattern Examples:**
```javascript
// JavaScript - DOM manipulation
element.innerHTML = userInput;
document.write(userInput);

// Python - Flask/Jinja2
return render_template('page.html', user_input=user_input)

// PHP
echo $_GET['user_input'];
```

**AI-Generated Fix:**
```javascript
// JavaScript - Safe DOM manipulation
element.textContent = userInput;
element.setAttribute('data-content', userInput);

// Python - Safe template rendering
return render_template('page.html', user_input=escape(user_input))

// PHP - Safe output
echo htmlspecialchars($_GET['user_input']);
```

**Impact:** Attackers can execute arbitrary JavaScript in users' browsers, potentially stealing cookies, session tokens, or performing actions on behalf of users.

**Languages Supported:** JavaScript, Python, PHP, Java, C#, Ruby

### Command Injection (CWE-78)

**Description:** Command injection occurs when user input is passed to system commands without proper validation.

**Pattern Examples:**
```python
# Python
os.system(f"ping {user_input}")
subprocess.run(f"ls {user_input}", shell=True)

# JavaScript - Node.js
exec(`ping ${userInput}`);

# PHP
system("ping " . $_GET['host']);
```

**AI-Generated Fix:**
```python
# Python - Safe command execution
subprocess.run(["ping", user_input], shell=False)

# JavaScript - Safe command execution
execFile('ping', [userInput], (error, stdout, stderr) => {});

# PHP - Safe command execution
escapeshellarg($_GET['host'])
```

**Impact:** Attackers can execute arbitrary system commands, potentially gaining full system access.

**Languages Supported:** Python, JavaScript, PHP, Java, C#, Ruby, Go

### Path Traversal (CWE-22)

**Description:** Path traversal occurs when user input is used to construct file paths without proper validation.

**Pattern Examples:**
```python
# Python
with open(f"/var/www/files/{user_input}", "r") as f:
    content = f.read()

# JavaScript - Node.js
fs.readFileSync(`./files/${userInput}`);

# PHP
include($_GET['file']);
```

**AI-Generated Fix:**
```python
# Python - Safe path handling
import os
safe_path = os.path.join("/var/www/files", os.path.basename(user_input))
if os.path.commonpath([safe_path, "/var/www/files"]) == "/var/www/files":
    with open(safe_path, "r") as f:
        content = f.read()

# JavaScript - Safe path handling
const path = require('path');
const safePath = path.join('./files', path.basename(userInput));

# PHP - Safe path handling
realpath($_GET['file'])
```

**Impact:** Attackers can access files outside the intended directory, potentially reading sensitive system files.

**Languages Supported:** Python, JavaScript, PHP, Java, C#, Ruby, Go

### Insecure Deserialization (CWE-502)

**Description:** Insecure deserialization occurs when untrusted data is deserialized without proper validation.

**Pattern Examples:**
```python
# Python - Pickle
import pickle
data = pickle.loads(user_input)

# PHP - Unserialize
$data = unserialize($_POST['data']);

# Java
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(userInput.getBytes()));
Object obj = ois.readObject();
```

**AI-Generated Fix:**
```python
# Python - Safe deserialization
import json
data = json.loads(user_input)

# PHP - Safe deserialization
$data = json_decode($_POST['data'], true);

# Java - Safe deserialization
// Use JSON or XML parsers instead of ObjectInputStream
```

**Impact:** Attackers can execute arbitrary code during deserialization, potentially gaining system access.

**Languages Supported:** Python, PHP, Java, C#, Ruby

## Medium Severity Vulnerabilities

### Hardcoded Credentials (CWE-259)

**Description:** Hardcoded credentials in source code pose a security risk as they can be easily discovered.

**Pattern Examples:**
```python
# Python
password = "super_secret_password_123"
api_key = "sk-1234567890abcdef"

# JavaScript
const password = "admin123";
const apiKey = "sk-abcdef123456";

# PHP
$password = "secret123";
$api_key = "sk-1234567890abcdef";
```

**AI-Generated Fix:**
```python
# Python - Environment variables
import os
password = os.environ.get('DB_PASSWORD')
api_key = os.environ.get('API_KEY')

# JavaScript - Environment variables
const password = process.env.DB_PASSWORD;
const apiKey = process.env.API_KEY;

# PHP - Environment variables
$password = getenv('DB_PASSWORD');
$api_key = getenv('API_KEY');
```

**Impact:** Credentials can be easily discovered by anyone with access to the source code.

**Languages Supported:** Python, JavaScript, PHP, Java, C#, Ruby, Go

### Weak Cryptography (CWE-327)

**Description:** Use of weak cryptographic algorithms or improper implementation.

**Pattern Examples:**
```python
# Python - Weak hashing
import hashlib
hash = hashlib.md5(password).hexdigest()

# JavaScript - Weak encryption
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');

# PHP - Weak hashing
$hash = md5($password);
```

**AI-Generated Fix:**
```python
# Python - Strong hashing
import hashlib
import os
salt = os.urandom(32)
hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

# JavaScript - Strong hashing
const crypto = require('crypto');
const salt = crypto.randomBytes(32);
const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256');

# PHP - Strong hashing
$hash = password_hash($password, PASSWORD_ARGON2ID);
```

**Impact:** Weak cryptography can be easily broken, compromising data security.

**Languages Supported:** Python, JavaScript, PHP, Java, C#, Ruby, Go

### Insecure Random (CWE-338)

**Description:** Use of cryptographically weak random number generators.

**Pattern Examples:**
```python
# Python - Weak random
import random
token = random.randint(1, 1000000)

# JavaScript - Weak random
const token = Math.floor(Math.random() * 1000000);

# PHP - Weak random
$token = rand(1, 1000000);
```

**AI-Generated Fix:**
```python
# Python - Secure random
import secrets
token = secrets.randbelow(1000000)

# JavaScript - Secure random
const crypto = require('crypto');
const token = crypto.randomInt(1, 1000000);

# PHP - Secure random
$token = random_int(1, 1000000);
```

**Impact:** Predictable random numbers can be exploited for session hijacking or other attacks.

**Languages Supported:** Python, JavaScript, PHP, Java, C#, Ruby, Go

### Missing Input Validation (CWE-20)

**Description:** Lack of proper input validation can lead to various security issues.

**Pattern Examples:**
```python
# Python - No validation
def process_user_data(data):
    return data.upper()

# JavaScript - No validation
function processUserData(data) {
    return data.toUpperCase();
}

# PHP - No validation
function processUserData($data) {
    return strtoupper($data);
}
```

**AI-Generated Fix:**
```python
# Python - Input validation
import re
def process_user_data(data):
    if not isinstance(data, str):
        raise ValueError("Data must be a string")
    if len(data) > 1000:
        raise ValueError("Data too long")
    if not re.match(r'^[a-zA-Z0-9\s]+$', data):
        raise ValueError("Invalid characters")
    return data.upper()

# JavaScript - Input validation
function processUserData(data) {
    if (typeof data !== 'string') {
        throw new Error('Data must be a string');
    }
    if (data.length > 1000) {
        throw new Error('Data too long');
    }
    if (!/^[a-zA-Z0-9\s]+$/.test(data)) {
        throw new Error('Invalid characters');
    }
    return data.toUpperCase();
}
```

**Impact:** Unvalidated input can lead to injection attacks, buffer overflows, or other security issues.

**Languages Supported:** Python, JavaScript, PHP, Java, C#, Ruby, Go

## Low Severity Vulnerabilities

### Debug Code (CWE-489)

**Description:** Debug code left in production can expose sensitive information.

**Pattern Examples:**
```python
# Python - Debug prints
print(f"DEBUG: User data = {user_data}")
import pdb; pdb.set_trace()

# JavaScript - Console logs
console.log("DEBUG: User data =", userData);
debugger;

# PHP - Debug output
var_dump($user_data);
error_log("DEBUG: " . $user_data);
```

**AI-Generated Fix:**
```python
# Python - Proper logging
import logging
logger = logging.getLogger(__name__)
logger.debug(f"User data processed: {user_data[:10]}...")

# JavaScript - Proper logging
const logger = require('./logger');
logger.debug('User data processed:', userData.substring(0, 10) + '...');

# PHP - Proper logging
error_log("User data processed: " . substr($user_data, 0, 10) . "...");
```

**Impact:** Debug information can expose sensitive data or system internals.

**Languages Supported:** Python, JavaScript, PHP, Java, C#, Ruby, Go

### Information Disclosure (CWE-200)

**Description:** Unintentional disclosure of sensitive information through error messages or logs.

**Pattern Examples:**
```python
# Python - Detailed error messages
try:
    connect_database()
except Exception as e:
    print(f"Database connection failed: {e}")

# JavaScript - Detailed error messages
try {
    connectDatabase();
} catch (error) {
    console.error("Database connection failed:", error);
}

# PHP - Detailed error messages
try {
    connectDatabase();
} catch (Exception $e) {
    echo "Database connection failed: " . $e->getMessage();
}
```

**AI-Generated Fix:**
```python
# Python - Generic error messages
try:
    connect_database()
except Exception as e:
    logger.error("Database connection failed")
    print("An error occurred. Please try again later.")

# JavaScript - Generic error messages
try {
    connectDatabase();
} catch (error) {
    logger.error("Database connection failed");
    console.error("An error occurred. Please try again later.");
}

# PHP - Generic error messages
try {
    connectDatabase();
} catch (Exception $e) {
    error_log("Database connection failed");
    echo "An error occurred. Please try again later.";
}
```

**Impact:** Detailed error messages can reveal system architecture, database schemas, or other sensitive information.

**Languages Supported:** Python, JavaScript, PHP, Java, C#, Ruby, Go

### Code Quality Issues

**Description:** Code quality issues that may not directly cause security vulnerabilities but indicate potential problems.

**Pattern Examples:**
```python
# Python - Complex functions
def process_data(data):
    # 200+ lines of complex logic
    pass

# JavaScript - Deep nesting
function processData(data) {
    if (condition1) {
        if (condition2) {
            if (condition3) {
                // Deep nested logic
            }
        }
    }
}

# PHP - Magic numbers
$timeout = 30;  // Magic number
$max_retries = 3;  // Magic number
```

**AI-Generated Fix:**
```python
# Python - Refactored function
def process_data(data):
    return DataProcessor(data).process()

class DataProcessor:
    def __init__(self, data):
        self.data = data
    
    def process(self):
        # Break down into smaller methods
        pass

# JavaScript - Reduced nesting
function processData(data) {
    if (!condition1) return;
    if (!condition2) return;
    if (!condition3) return;
    // Process logic
}

# PHP - Constants
const TIMEOUT_SECONDS = 30;
const MAX_RETRIES = 3;
```

**Impact:** Poor code quality can lead to maintenance issues and potential security vulnerabilities.

**Languages Supported:** Python, JavaScript, PHP, Java, C#, Ruby, Go

## Detection Methods

### Pattern Matching

Pattern matching uses regular expressions to identify vulnerable code patterns.

**Example Pattern:**
```json
{
  "name": "sql_injection",
  "pattern": "execute\\s*\\(\\s*[f]?[\"'][^\"']*\\{\\s*\\w+\\s*\\}[^\"']*[\"']",
  "severity": "high",
  "languages": ["python", "javascript", "php"]
}
```

### AST Analysis

Abstract Syntax Tree analysis examines code structure for vulnerabilities.

**Example AST Pattern:**
```python
# Look for function calls with string concatenation
def analyze_function_call(node):
    if isinstance(node, ast.Call):
        if has_string_concatenation(node.args):
            return Vulnerability(...)
```

### Semantic Analysis

AI-powered semantic analysis understands code context and meaning.

**Example Semantic Analysis:**
```python
# Analyze code context for SQL injection
def analyze_sql_context(code, context):
    if "SELECT" in code and has_user_input(context):
        return Vulnerability(...)
```

## AI Fix Capabilities

### Supported Fix Types

| Vulnerability | Python | JavaScript | PHP | Java | C# | Ruby | Go |
|---------------|--------|------------|-----|------|----|------|----|
| SQL Injection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| XSS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Command Injection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Path Traversal | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Hardcoded Credentials | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Weak Crypto | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Insecure Random | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Debug Code | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Fix Confidence Levels

- **90-100%** - High confidence, recommended fix
- **70-89%** - Medium confidence, review recommended
- **50-69%** - Low confidence, manual review required
- **<50%** - Very low confidence, manual fix required

## Language Support

### Python

**Supported Frameworks:**
- Flask
- Django
- FastAPI
- SQLAlchemy
- Requests

**Common Patterns:**
- SQL injection with f-strings
- Command injection with os.system
- XSS with template rendering
- Hardcoded credentials

### JavaScript

**Supported Frameworks:**
- Node.js
- Express
- React
- Angular
- Vue.js

**Common Patterns:**
- SQL injection with template literals
- XSS with innerHTML
- Command injection with exec
- Hardcoded API keys

### PHP

**Supported Frameworks:**
- Laravel
- Symfony
- CodeIgniter
- WordPress

**Common Patterns:**
- SQL injection with string concatenation
- XSS with echo
- File inclusion vulnerabilities
- Hardcoded passwords

### Java

**Supported Frameworks:**
- Spring Boot
- Hibernate
- JSP
- Servlets

**Common Patterns:**
- SQL injection with string concatenation
- XSS with JSP expressions
- Deserialization vulnerabilities
- Hardcoded credentials

## Custom Patterns

### Adding Custom Patterns

```json
{
  "custom_patterns": {
    "my_custom_vuln": {
      "pattern": "dangerous_function\\(.*\\)",
      "severity": "high",
      "description": "Custom vulnerability description",
      "languages": ["python", "javascript"],
      "cwe": "CWE-XXX",
      "impact": "Description of potential impact",
      "mitigation": "How to fix this vulnerability"
    }
  }
}
```

### Pattern Syntax

**Basic Patterns:**
```regex
# Simple string match
dangerous_function

# Case insensitive
(?i)dangerous_function

# Word boundary
\bdangerous_function\b

# Optional whitespace
dangerous_function\s*\(
```

**Advanced Patterns:**
```regex
# Capture groups
(dangerous_function)\s*\(([^)]+)\)

# Lookahead/lookbehind
(?<=import\s)dangerous_module
(?=.*vulnerable_pattern)

# Quantifiers
dangerous_pattern{1,3}
```

### Testing Custom Patterns

```python
from sast_scanner.patterns import PatternManager

# Test pattern
pattern_manager = PatternManager()
pattern = {
    "name": "test_pattern",
    "pattern": "dangerous_function\\(.*\\)",
    "severity": "high"
}

# Test with sample code
test_code = "dangerous_function(user_input)"
result = pattern_manager.test_pattern(pattern, test_code)
print(f"Pattern matched: {result}")
```

## Next Steps

After reviewing this vulnerability database:

1. **Try the [Usage Guide](USAGE.md)** for practical scanning examples
2. **Check the [API Reference](API_REFERENCE.md)** for advanced customization
3. **Create custom patterns** for your specific needs
4. **Contribute new patterns** to the community 