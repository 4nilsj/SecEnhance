# AI-Enabled SAST Scanner

A comprehensive Static Application Security Testing (SAST) tool with AI-powered analysis capabilities for identifying security vulnerabilities in source code.

## Features

### 🔍 **Comprehensive Vulnerability Detection**
- **Pattern-based detection** for common security vulnerabilities
- **AI-powered analysis** using machine learning models
- **Context-aware scanning** for better accuracy
- **Multi-language support** (Python, JavaScript, Java, C/C++, PHP, Ruby, Go, Rust)

### 🤖 **AI-Powered Analysis**
- **Semantic code analysis** using transformer models
- **Context understanding** for better vulnerability identification
- **Intelligent insights** and recommendations
- **Pattern recognition** for complex security issues

### 📊 **Advanced Reporting**
- **Multiple output formats** (HTML, JSON, Markdown, PDF)
- **Detailed vulnerability reports** with mitigation strategies
- **AI-generated insights** and recommendations
- **Comprehensive statistics** and metrics

### ⚡ **Performance & Scalability**
- **Parallel scanning** with configurable worker threads
- **Single file and directory scanning** support
- **Efficient code parsing** and analysis
- **Memory-optimized** processing

## Supported Vulnerabilities

### High Severity
- **SQL Injection** - Pattern-based and AST analysis
- **Cross-Site Scripting (XSS)** - Multiple detection methods
- **Command Injection** - Comprehensive pattern matching
- **Path Traversal** - File operation analysis
- **Insecure Deserialization** - Object creation analysis

### Medium Severity
- **Hardcoded Credentials** - Credential pattern detection
- **Weak Cryptography** - Algorithm strength analysis
- **Insecure Random** - Random number generation analysis
- **Missing Input Validation** - Function parameter analysis

### Low Severity
- **Debug Code** - Production code analysis
- **Information Disclosure** - Error handling analysis
- **Code Quality Issues** - Complexity and maintainability

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Installation

```bash
# Clone the repository
git clone <repository-url>
cd sast_scanner

# Install dependencies
pip install -r requirements.txt

# Verify installation
python sast_scanner_cli.py version
```

### Development Installation

```bash
# Clone the repository
git clone <repository-url>
cd sast_scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

## Usage

### Basic Usage

#### Scan a Single File
```bash
# Scan a Python file
python sast_scanner_cli.py scan file app.py

# Scan with debug output
python sast_scanner_cli.py scan file app.py --debug

# Generate HTML report
python sast_scanner_cli.py scan file app.py --output html --output-file report.html
```

#### Scan a Directory
```bash
# Scan entire directory
python sast_scanner_cli.py scan directory /path/to/code

# Scan with specific file patterns
python sast_scanner_cli.py scan directory /path/to/code --patterns "*.py,*.js,*.php"

# Scan with custom worker threads
python sast_scanner_cli.py scan directory /path/to/code --max-workers 8
```

### Advanced Usage

#### Custom File Patterns
```bash
# Include specific file types
python sast_scanner_cli.py scan directory /path/to/code --patterns "*.py,*.js,*.java,*.cpp"

# Exclude test files
python sast_scanner_cli.py scan directory /path/to/code --exclude "*test*,*spec*"
```

#### Multiple Output Formats
```bash
# Generate JSON report
python sast_scanner_cli.py scan file app.py --output json

# Generate Markdown report
python sast_scanner_cli.py scan file app.py --output markdown

# Generate PDF report
python sast_scanner_cli.py scan file app.py --output pdf
```

#### Summary Reports
```bash
# Generate summary report only
python sast_scanner_cli.py scan directory /path/to/code --summary-only
```

### Command Line Options

```bash
python sast_scanner_cli.py scan [file|directory] <target> [options]

Options:
  --patterns PATTERNS     File patterns to include (comma-separated)
  --exclude PATTERNS      File patterns to exclude (comma-separated)
  --max-workers N         Maximum number of worker threads (default: 4)
  --output FORMAT         Output format: html, json, markdown, pdf (default: html)
  --output-file PATH      Output file path for report
  --summary-only          Generate summary report only
  --debug                 Enable debug output
  --verbose               Enable verbose output
```

## Supported Languages

### Python
- **Vulnerabilities**: SQL injection, command injection, path traversal, hardcoded credentials
- **Patterns**: `eval()`, `exec()`, `os.system()`, `pickle.loads()`, `yaml.load()`
- **Analysis**: AST-based analysis, function call tracking

### JavaScript/TypeScript
- **Vulnerabilities**: XSS, command injection, insecure random, debug code
- **Patterns**: `innerHTML`, `eval()`, `Math.random()`, `console.log()`
- **Analysis**: Function call analysis, DOM manipulation detection

### Java
- **Vulnerabilities**: SQL injection, insecure deserialization, path traversal
- **Patterns**: `Statement.executeQuery()`, `ObjectInputStream`, file operations
- **Analysis**: Method call analysis, import tracking

### C/C++
- **Vulnerabilities**: Buffer overflow, command injection, path traversal
- **Patterns**: `system()`, `exec()`, file operations, memory management
- **Analysis**: Function call analysis, include tracking

### PHP
- **Vulnerabilities**: SQL injection, XSS, command injection, file inclusion
- **Patterns**: `mysqli_query()`, `shell_exec()`, `include()`, `file_get_contents()`
- **Analysis**: Function call analysis, variable tracking

### Ruby
- **Vulnerabilities**: Command injection, path traversal, insecure deserialization
- **Patterns**: `system()`, `eval()`, `File.read()`, `YAML.load()`
- **Analysis**: Method call analysis, require tracking

### Go
- **Vulnerabilities**: Command injection, path traversal, insecure random
- **Patterns**: `exec.Command()`, file operations, `math/rand`
- **Analysis**: Function call analysis, import tracking

### Rust
- **Vulnerabilities**: Unsafe code, memory safety issues
- **Patterns**: `unsafe` blocks, raw pointers, FFI calls
- **Analysis**: Unsafe code detection, memory safety analysis

## AI Capabilities

### Semantic Analysis
- **Code understanding** using transformer models
- **Context-aware vulnerability detection**
- **Intelligent pattern recognition**
- **Natural language processing** of code comments

### Machine Learning Features
- **Vulnerability classification** using trained models
- **Risk assessment** based on code patterns
- **False positive reduction** through context analysis
- **Adaptive learning** from scan results

### Context Understanding
- **Code flow analysis** for better vulnerability detection
- **Dependency tracking** for impact assessment
- **Function relationship mapping**
- **Security control identification**

## Output Formats

### HTML Report
- **Interactive dashboard** with vulnerability details
- **Severity-based color coding**
- **Code snippets** with line highlighting
- **Mitigation recommendations**
- **Statistics and metrics**

### JSON Report
- **Machine-readable format** for integration
- **Complete scan results** with metadata
- **Structured vulnerability data**
- **AI insights and recommendations**

### Markdown Report
- **Human-readable format** for documentation
- **GitHub-compatible** markdown
- **Code blocks** with syntax highlighting
- **Executive summary** and detailed findings

### PDF Report
- **Professional report format** for stakeholders
- **Printable layout** with proper formatting
- **Executive summary** and technical details
- **Charts and statistics**

## Configuration

### Environment Variables
```bash
# Debug mode
export SAST_DEBUG=true

# Log level
export SAST_LOG_LEVEL=INFO

# Output directory
export SAST_OUTPUT_DIR=./reports
```

### Configuration File
Create `sast_config.json`:
```json
{
  "max_workers": 4,
  "default_output_format": "html",
  "exclude_patterns": ["*test*", "*spec*", "node_modules"],
  "include_patterns": ["*.py", "*.js", "*.java"],
  "debug_mode": false,
  "ai_enabled": true
}
```

## Examples

### Example 1: Basic Python Application Scan
```bash
# Scan a Flask application
python sast_scanner_cli.py scan directory ./flask_app --patterns "*.py"

# Output: HTML report with vulnerabilities found
```

### Example 2: JavaScript Project with Custom Patterns
```bash
# Scan a Node.js project
python sast_scanner_cli.py scan directory ./nodejs_app \
  --patterns "*.js,*.jsx,*.ts,*.tsx" \
  --exclude "node_modules,dist,build" \
  --output json \
  --output-file security_report.json
```

### Example 3: Multi-language Project
```bash
# Scan a full-stack application
python sast_scanner_cli.py scan directory ./fullstack_app \
  --patterns "*.py,*.js,*.java,*.php" \
  --max-workers 8 \
  --output html \
  --debug
```

### Example 4: CI/CD Integration
```bash
# Generate JSON report for CI/CD pipeline
python sast_scanner_cli.py scan directory ./codebase \
  --output json \
  --output-file sast_results.json

# Check for high severity vulnerabilities
python -c "
import json
with open('sast_results.json') as f:
    data = json.load(f)
high_vulns = [v for v in data['vulnerabilities'] if v['severity'] == 'high']
exit(1 if high_vulns else 0)
"
```

## Integration

### CI/CD Pipelines
```yaml
# GitHub Actions example
- name: SAST Scan
  run: |
    python sast_scanner_cli.py scan directory ./src \
      --output json \
      --output-file sast_results.json

- name: Check for High Severity Issues
  run: |
    python -c "
    import json
    with open('sast_results.json') as f:
        data = json.load(f)
    high_vulns = [v for v in data['vulnerabilities'] if v['severity'] == 'high']
    if high_vulns:
        print(f'Found {len(high_vulns)} high severity vulnerabilities')
        exit(1)
    "
```

### IDE Integration
```json
// VS Code settings.json
{
  "sast-scanner.enabled": true,
  "sast-scanner.autoScan": true,
  "sast-scanner.outputFormat": "html",
  "sast-scanner.debugMode": false
}
```

## Troubleshooting

### Common Issues

#### Installation Issues
```bash
# If you encounter dependency issues
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall

# For Windows users
pip install --upgrade setuptools wheel
```

#### Performance Issues
```bash
# Reduce worker threads for memory-constrained systems
python sast_scanner_cli.py scan directory ./code --max-workers 2

# Use summary-only for large codebases
python sast_scanner_cli.py scan directory ./code --summary-only
```

#### Debug Issues
```bash
# Enable debug mode for troubleshooting
python sast_scanner_cli.py scan file app.py --debug --verbose

# Check debug logs
tail -f logs/sast_scanner_*.log
```

## Contributing

### Development Setup
```bash
# Clone repository
git clone <repository-url>
cd sast_scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
flake8 src/
black src/
```

### Adding New Vulnerability Patterns
1. Add pattern to `vulnerability_detector.py`
2. Update language-specific analyzers
3. Add tests in `tests/` directory
4. Update documentation

### Adding New Language Support
1. Create language analyzer in `analyzers/`
2. Add file type mapping
3. Implement language-specific patterns
4. Add tests and documentation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

### Documentation
- [Installation Guide](docs/INSTALLATION.md)
- [Usage Guide](docs/USAGE.md)
- [API Reference](docs/API_REFERENCE.md)
- [Vulnerability Database](docs/VULNERABILITIES.md)

### Issues and Feedback
- Report bugs: [GitHub Issues](https://github.com/your-repo/issues)
- Feature requests: [GitHub Discussions](https://github.com/your-repo/discussions)
- Security issues: [Security Policy](SECURITY.md)

### Community
- [Discord Server](https://discord.gg/your-server)
- [Mailing List](mailto:sast-scanner@example.com)
- [Blog](https://blog.example.com/sast-scanner)

## Acknowledgments

- Security researchers and contributors
- Open source security tools and libraries
- AI/ML community for transformer models
- Security standards organizations (OWASP, CWE, CVE)

---

**Note**: This tool is designed for educational and security research purposes. Always follow responsible disclosure practices when reporting vulnerabilities found in production systems. 