# JWT Security Tester

A comprehensive, modern tool for analyzing and testing the security of JSON Web Tokens (JWTs). Supports CLI and REST API, advanced vulnerability detection (including CVEs), batch processing, parallel execution, and detailed reporting.

---

## Features
- **Comprehensive JWT analysis**: Structure, signature, claims, tampering, replay, fuzzing, and more
- **CVE-specific tests**: Detects known JWT vulnerabilities (alg=none, RS/HS256 confusion, key injection, etc.)
- **Batch processing**: Analyze multiple tokens in parallel with progress bars
- **Dictionary attacks**: Test common and custom secrets
- **Configurable**: JSON config, CLI overrides, environment variables
- **Colorful, user-friendly CLI**: Progress bars, color output, clear errors
- **HTML/JSON reporting**: Save and share detailed results
- **REST API**: Analyze tokens programmatically
- **Unit tested**: Robust, maintainable codebase

---

## Installation

1. **Clone the repo:**
   ```sh
   git clone https://github.com/your-org/jwt-security-tester.git
   cd jwt-security-tester/jwt_tool
   ```
2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
3. *(Optional)*: Use the provided `install.py` for guided setup.

---

## Quick Start

**Single token analysis:**
```sh
python src/jwt_security_tester.py --token "<your_jwt_here>"
```

**Batch mode:**
```sh
python src/jwt_security_tester.py --file tokens.txt --output batch_report.html
```

**Dictionary attack:**
```sh
python src/jwt_security_tester.py --token "<jwt>" --test dictionary --wordlist my_wordlist.txt
```

**Generate keys:**
```sh
python src/jwt_security_tester.py --test generate-keys --key-size 2048
```

---

## CLI Usage

Run `python src/jwt_security_tester.py --help` for all options.

**Key options:**
- `--token <JWT>`: Analyze a single token
- `--file <file>`: Analyze tokens from file (one per line)
- `--test <type>`: Specify test (structure, cve, dictionary, all, ...)
- `--output <file>`: Save report (HTML/JSON)
- `--config <file>`: Use custom config
- `--max-attempts <n>`: Max attempts for dictionary attack
- `--workers <n>`: Parallel workers for batch
- `--debug`: Enable debug logging
- `--version`, `--help`: Info and help

See [docs/USAGE.md](docs/USAGE.md) for advanced usage and examples.

---

## Configuration

- **Default config:** `config/default_config.json`
- **Override via:**
  - CLI flags (e.g., `--max-attempts`)
  - Environment variables (e.g., `JWT_DEBUG=true`)
- **Secrets:** `config/common_secrets.txt` (used for dictionary attacks)

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for full details.

---

## Reporting

- **HTML report:** Beautiful, detailed, color-coded
- **JSON report:** For automation/integration
- **Location:** Saved in `reports/` by default

See [docs/REPORTS.md](docs/REPORTS.md) for report structure and interpretation.

---

## REST API

### Basic API
Start the basic API:
```sh
python src/jwt_api.py
```

**Default Port:** 5000

**Endpoints:**
- `POST /analyze` — Analyze a JWT (JSON: `{ "token": "..." }`)
- `POST /batch` — Batch analysis
- `POST /report` — Generate HTML report
- `GET /status` — Health check

### Enhanced API (Recommended)
Start the enhanced API with scan ID management:
```sh
python src/jwt_api_enhanced.py
```

**Default Port:** 5000

### Port Configuration

If port 5000 is already in use by another process, you can change the port in several ways:

#### Method 1: Environment Variable
```sh
# Set port via environment variable
export JWT_API_PORT=8080
python src/jwt_api_enhanced.py
```

#### Method 2: Direct Code Modification
Edit the API file and change the port:
```python
# In src/jwt_api_enhanced.py (line ~248)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)  # Change 5000 to your desired port
```

#### Method 3: Command Line with Python
```sh
# Start API with custom port
python -c "
import sys
sys.path.append('src')
from jwt_api_enhanced import app
app.run(host='0.0.0.0', port=8080, debug=True)
"
```

#### Method 4: Using Flask CLI
```sh
# Set environment variable and use Flask
export FLASK_APP=src/jwt_api_enhanced.py
export FLASK_ENV=development
flask run --host=0.0.0.0 --port=8080
```

#### Method 5: Using Helper Script (Recommended)
```sh
# Start enhanced API on port 8080
python start_api.py --port 8080

# Start basic API on port 3000
python start_api.py --api-type basic --port 3000

# Start with environment variable
JWT_API_PORT=8080 python start_api.py
```

**Common Alternative Ports:**
- `8080` - Common alternative for web services
- `3000` - Popular for development servers
- `8000` - Django default alternative
- `9000` - Another common development port

**Note:** After changing the port, update your API calls to use the new port:
```sh
# Example: Using port 8080
curl http://localhost:8080/status
```

### Troubleshooting Port Issues

**Port Already in Use Error:**
```
OSError: [Errno 98] Address already in use
```

**Solutions:**
1. **Find what's using the port:**
   ```sh
   # Linux/Mac
   lsof -i :5000
   
   # Windows
   netstat -ano | findstr :5000
   ```

2. **Kill the process using the port:**
   ```sh
   # Linux/Mac
   kill -9 <PID>
   
   # Windows
   taskkill /PID <PID> /F
   ```

3. **Use a different port:**
   ```sh
   python start_api.py --port 8080
   ```

**Common Port Conflicts:**
- **Port 5000**: Often used by AirPlay, Docker, or other development servers
- **Port 3000**: Used by React, Node.js development servers
- **Port 8000**: Used by Django development server
- **Port 8080**: Used by many web services and proxies

**Enhanced Features:**
- **Scan ID Management**: Track multiple concurrent scans
- **Session Persistence**: Retrieve results later using scan ID
- **Report Generation**: Generate reports for specific scans
- **Scan Management**: List, monitor, and delete scan sessions

**Enhanced Endpoints:**
- `POST /scan/start` — Start new scan session
- `POST /scan/{scan_id}/analyze` — Analyze with scan tracking
- `POST /scan/{scan_id}/batch` — Batch analysis with tracking
- `GET /scan/{scan_id}/status` — Check scan status
- `GET /scan/{scan_id}/results` — Get scan results
- `GET /scan/{scan_id}/report` — Generate scan report
- `GET /scans` — List all scans
- `DELETE /scan/{scan_id}` — Delete scan session

See [docs/API_REFERENCE.md](docs/API_REFERENCE.md) for basic API docs and [docs/ENHANCED_API_USAGE.md](docs/ENHANCED_API_USAGE.md) for enhanced API usage.

---

## Testing & Development

- **Run all tests:**
  ```sh
  pytest tests/
  ```
- **Add new tests:** Place in `tests/` directory
- **Coverage:** All major features are unit tested

---

## Contributing

1. Fork and clone the repo
2. Create a feature branch
3. Add/fix code and tests
4. Open a pull request

---

## License
MIT

---

## Authors
QuickFix Security Team

---

## Docker Support

The tool includes comprehensive Docker support with multiple services:

### Quick Docker Setup
```sh
# Setup directories
python setup_docker_dirs.py

# Build and start enhanced API
docker-compose up jwt-api-enhanced
```

### Available Docker Services
- **jwt-api-enhanced**: Enhanced API with scan ID management (port 5001)
- **jwt-api-basic**: Basic API (port 5000)
- **jwt-api-enhanced-custom-port**: Enhanced API on port 8080
- **jwt-tool**: CLI tool for analysis
- **jwt-tests**: Unit tests

### Docker Features
- ✅ Separate CLI/API report directories
- ✅ Port configuration support
- ✅ Environment variable configuration
- ✅ Volume mounts for data persistence
- ✅ Non-root user security

See [DOCKER_USAGE.md](DOCKER_USAGE.md) for complete Docker documentation.

## More
- [docs/USAGE.md](docs/USAGE.md): Advanced CLI usage
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md): Config reference
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md): API docs
- [docs/ENHANCED_API_USAGE.md](docs/ENHANCED_API_USAGE.md): Enhanced API usage
- [docs/REPORTS.md](docs/REPORTS.md): Report formats
- [DOCKER_USAGE.md](DOCKER_USAGE.md): Docker usage guide 