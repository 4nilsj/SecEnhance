/**
 * Example vulnerable JavaScript application for SAST testing.
 * This file contains intentional security vulnerabilities for demonstration purposes.
 * DO NOT USE IN PRODUCTION!
 */

const express = require('express');
const mysql = require('mysql');
const fs = require('fs');
const { exec } = require('child_process');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// VULNERABILITY: Hardcoded credentials
const DATABASE_PASSWORD = "admin123";
const API_KEY = "sk-1234567890abcdef";
const SECRET_TOKEN = "my-secret-token-here";

// VULNERABILITY: Weak cryptography
function hashPassword(password) {
    // VULNERABILITY: Weak MD5 hashing
    return crypto.createHash('md5').update(password).digest('hex');
}

// VULNERABILITY: Insecure random
function generateToken() {
    // VULNERABILITY: Insecure random generation
    return Math.random().toString(36).substring(2);
}

// VULNERABILITY: SQL Injection
function getUserById(userId) {
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: DATABASE_PASSWORD,
        database: 'users'
    });

    // VULNERABILITY: SQL injection
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    
    connection.query(query, (error, results) => {
        if (error) {
            console.log('Error:', error);
        } else {
            console.log('Results:', results);
        }
    });
    
    connection.end();
}

// VULNERABILITY: Command Injection
function executeCommand(command) {
    // VULNERABILITY: Command injection
    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.log('Error:', error);
        } else {
            console.log('Output:', stdout);
        }
    });
}

// VULNERABILITY: Path Traversal
function readFile(filename) {
    // VULNERABILITY: Path traversal
    return fs.readFileSync(filename, 'utf8');
}

// VULNERABILITY: XSS
function renderUserProfile(username) {
    // VULNERABILITY: XSS through innerHTML
    const template = `
        <h1>Welcome ${username}!</h1>
        <p>Your profile information:</p>
        <div id="profile">${username}</div>
    `;
    
    // VULNERABILITY: Unsafe innerHTML usage
    document.getElementById('content').innerHTML = template;
}

// VULNERABILITY: Eval usage
function evaluateExpression(expression) {
    // VULNERABILITY: Eval usage
    return eval(expression);
}

// VULNERABILITY: Debug code in production
function debugFunction() {
    console.log('Debug: This should not be in production');
    console.log('Debug: Current working directory:', process.cwd());
    console.log('Debug: Node.js version:', process.version);
}

// VULNERABILITY: Insecure object creation
function createObjectFromString(objString) {
    // VULNERABILITY: Unsafe object creation
    return new Function('return ' + objString)();
}

// VULNERABILITY: Insecure JSON parsing
function parseUserData(data) {
    // VULNERABILITY: Unsafe JSON parsing without validation
    return JSON.parse(data);
}

// Express routes with vulnerabilities
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    
    // VULNERABILITY: SQL injection
    getUserById(userId);
    
    // VULNERABILITY: XSS
    const username = req.query.name || 'Unknown';
    const profile = renderUserProfile(username);
    
    res.send(profile);
});

app.post('/upload', (req, res) => {
    const filename = req.body.filename;
    
    // VULNERABILITY: Path traversal
    const filePath = `uploads/${filename}`;
    
    // VULNERABILITY: Command injection
    if (filename.endsWith('.sh')) {
        executeCommand(`chmod +x ${filePath}`);
    }
    
    res.send('File uploaded successfully');
});

app.post('/execute', (req, res) => {
    const expression = req.body.expression;
    
    // VULNERABILITY: Eval usage
    const result = evaluateExpression(expression);
    
    res.send(`Result: ${result}`);
});

app.post('/config', (req, res) => {
    const configData = req.body.config;
    
    // VULNERABILITY: Insecure object creation
    const config = createObjectFromString(configData);
    
    // VULNERABILITY: Debug code
    debugFunction();
    
    res.send('Configuration updated');
});

app.post('/data', (req, res) => {
    const userData = req.body.data;
    
    // VULNERABILITY: Insecure JSON parsing
    const parsedData = parseUserData(userData);
    
    res.json(parsedData);
});

// VULNERABILITY: Insecure headers
app.use((req, res, next) => {
    // VULNERABILITY: Missing security headers
    res.setHeader('X-Powered-By', 'Express');
    next();
});

// VULNERABILITY: Insecure cookie settings
app.use((req, res, next) => {
    // VULNERABILITY: Insecure cookie
    res.cookie('session', 'user-session-id', {
        httpOnly: false,  // VULNERABILITY: Should be true
        secure: false,    // VULNERABILITY: Should be true in production
        sameSite: 'none'  // VULNERABILITY: Should be 'strict'
    });
    next();
});

// VULNERABILITY: Error information disclosure
app.use((err, req, res, next) => {
    // VULNERABILITY: Error information disclosure
    console.error(err.stack);
    res.status(500).send(`Error: ${err.message}`);
});

// VULNERABILITY: Insecure file serving
app.use('/files', express.static('public'));

// VULNERABILITY: Insecure CORS
app.use((req, res, next) => {
    // VULNERABILITY: Overly permissive CORS
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});

// Main function with vulnerabilities
function main() {
    // VULNERABILITY: Hardcoded credentials
    console.log(`Connecting to database with password: ${DATABASE_PASSWORD}`);
    
    // VULNERABILITY: Weak cryptography
    const password = "user123";
    const hashed = hashPassword(password);
    console.log(`Password hash: ${hashed}`);
    
    // VULNERABILITY: Insecure random
    const token = generateToken();
    console.log(`Generated token: ${token}`);
    
    // VULNERABILITY: Debug code
    debugFunction();
    
    // VULNERABILITY: Command injection
    const userInput = process.argv[2] || "ls -la";
    executeCommand(userInput);
    
    // VULNERABILITY: Path traversal
    const filePath = process.argv[3] || "../../../etc/passwd";
    try {
        const content = readFile(filePath);
        console.log(`File content: ${content}`);
    } catch (error) {
        console.log('Error reading file:', error.message);
    }
}

// VULNERABILITY: Insecure server configuration
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log('Debug mode enabled');  // VULNERABILITY: Debug information
});

// Export for testing
module.exports = {
    app,
    main,
    getUserById,
    executeCommand,
    readFile,
    renderUserProfile,
    evaluateExpression,
    hashPassword,
    generateToken
};

// Run main function if called directly
if (require.main === module) {
    main();
} 