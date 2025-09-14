# API Security Scanner - Folder Structure

## 📁 Current Project Structure

```
api_security_scanner/
├── 📦 api_security_scanner/           # Main Python package
│   ├── __init__.py                    # Package initialization
│   ├── 📁 cli/                        # Command-line interface
│   │   ├── __init__.py
│   │   └── main.py                    # CLI entry point
│   ├── 📁 core/                       # Core functionality
│   │   ├── __init__.py
│   │   ├── config.py                  # Configuration management
│   │   ├── db_manager.py              # Database operations
│   │   ├── report_generator.py        # HTML/JSON report generation
│   │   ├── scanner_plugins.py         # Plugin system base classes
│   │   └── zap_manager.py             # ZAP integration
│   ├── 📁 plugins/                    # Custom security plugins
│   │   ├── __init__.py
│   │   ├── comprehensive_security_checker.py
│   │   ├── cors_checker.py
│   │   ├── enhanced_security_checker.py
│   │   ├── rate_limiting_checker.py
│   │   └── security_headers_checker.py
│   └── 📁 utils/                      # Utility modules
│       ├── __init__.py
│       ├── auth_handler.py            # Authentication handling
│       ├── input_parsers.py           # Input file parsing
│       └── logger.py                  # Logging utilities
├── 📁 docs/                           # Documentation
│   ├── CUSTOM_PLUGIN_DEVELOPMENT.md
│   ├── DOCKER_USAGE_GUIDE.md
│   ├── ENVIRONMENT_CONFIGURATION.md
│   ├── MACOS_SETUP_GUIDE.md
│   ├── QUICK_REFERENCE.md
│   ├── TESTING_GUIDE.md
│   └── TROUBLESHOOTING_GUIDE.md
├── 📁 examples/                       # Example files
│   ├── README.md
│   ├── sample_openapi.yaml
│   ├── sample_postman_collection.json
│   ├── test_collection.json
│   └── test_openapi.yaml
├── 📁 logs/                           # Application logs
│   ├── error_logs.log
│   └── scan_logs.log
├── 📁 reports/                        # Generated reports
│   ├── *.html                         # HTML scan reports
│   └── *.json                         # JSON scan reports
├── 📁 templates/                      # Report templates
│   └── report_template.html           # Jinja2 HTML template
├── 📁 tests/                          # Test suite
│   ├── __init__.py
│   ├── conftest.py
│   ├── fixtures.py
│   ├── test_config.py
│   ├── test_container.py
│   ├── test_integration.py
│   ├── test_plugins.py
│   ├── test_runners.py
│   ├── test_src.py
│   └── test_utils.py
├── 🐳 Docker Files
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── build-docker.bat
│   ├── build-docker.sh
│   ├── mac-docker-setup.sh
│   ├── setup-container.bat
│   └── setup-container.sh
├── ⚙️ Configuration Files
│   ├── pyproject.toml                 # Modern Python packaging
│   ├── setup.py                       # Package setup
│   ├── pytest.ini                    # Test configuration
│   ├── requirements.txt               # Python dependencies
│   ├── env.example                    # Example environment file
│   ├── env.template                   # Environment template
│   └── container-config.py            # Container configuration
├── 📋 Documentation Files
│   ├── README.md                      # Main documentation
│   ├── API_COLLECTION_TESTING_GUIDE.md
│   ├── DOCKER_README.md
│   ├── ENHANCED_FEATURES_SUMMARY.md
│   ├── ENV_CONFIGURATION_SUMMARY.md
│   ├── FINAL_IMPLEMENTATION_SUMMARY.md
│   ├── PROJECT_SUMMARY.md
│   ├── STRUCTURE_CHANGES.md
│   └── FOLDER_STRUCTURE.md            # This file
├── 🚀 Entry Points
│   ├── main.py                        # Main entry point
│   ├── demo_api_collections.py        # Demo script
│   ├── test_api_collections.py        # Collection testing
│   ├── test_installation.py           # Installation test
│   ├── run_tests.py                   # Test runner
│   ├── healthcheck.py                 # Health check script
│   └── run_scanner.bat                # Windows batch runner
└── 📊 Data Files
    ├── scan_results.db                # SQLite database
    └── pyrightconfig.json             # Type checking config
```

## 🎯 **Key Structure Principles**

### 1. **Python Package Structure**
- **`api_security_scanner/`** - Main package following Python best practices
- **`__init__.py`** files in all packages for proper module recognition
- **Clear separation** of concerns across sub-packages

### 2. **Core Functionality** (`core/`)
- **`config.py`** - Configuration management and environment handling
- **`db_manager.py`** - SQLite database operations and schema
- **`report_generator.py`** - HTML/JSON report generation with Jinja2
- **`scanner_plugins.py`** - Base plugin classes and vulnerability models
- **`zap_manager.py`** - OWASP ZAP integration and API management

### 3. **Custom Plugins** (`plugins/`)
- **`comprehensive_security_checker.py`** - General security assessments
- **`cors_checker.py`** - CORS misconfiguration detection
- **`enhanced_security_checker.py`** - Advanced security checks
- **`rate_limiting_checker.py`** - Rate limiting and DoS protection
- **`security_headers_checker.py`** - Security header validation

### 4. **Utilities** (`utils/`)
- **`auth_handler.py`** - Authentication token/cookie/header handling
- **`input_parsers.py`** - Postman/OpenAPI/curl parsing
- **`logger.py`** - Structured logging with timers

### 5. **CLI Interface** (`cli/`)
- **`main.py`** - Click-based command-line interface
- **Commands**: `scan`, `plugins`, `reports`, `config`

## 🔧 **Usage Patterns**

### **Module Execution**
```bash
# Using the main package
python -m api_security_scanner.cli.main scan -f collection.json

# Using the entry point
python main.py scan -f collection.json
```

### **Import Patterns**
```python
# Core functionality
from api_security_scanner.core import DatabaseManager, ZAPManager
from api_security_scanner.core.report_generator import ReportGenerator

# Utilities
from api_security_scanner.utils import get_logger, parse_input

# Plugins
from api_security_scanner.plugins import CORSChecker, SecurityHeadersChecker
```

### **Plugin Development**
```python
# New plugins go in api_security_scanner/plugins/
from api_security_scanner.core.scanner_plugins import BasePlugin

class MyCustomPlugin(BasePlugin):
    name = "MyCustomPlugin"
    # Implementation...
```

## ✅ **Structure Benefits**

1. **Python Best Practices** - Follows PEP 8 and packaging standards
2. **Clear Organization** - Logical separation of concerns
3. **Easy Extension** - Simple to add new plugins and features
4. **IDE Support** - Proper autocomplete and navigation
5. **Testing** - Clear test organization and coverage
6. **Documentation** - Comprehensive docs in dedicated folder
7. **Container Ready** - Docker files and configuration included

## 🚀 **Entry Points**

| Method | Command | Description |
|--------|---------|-------------|
| **Module** | `python -m api_security_scanner.cli.main` | Recommended approach |
| **Script** | `python main.py` | Direct script execution |
| **Console** | `api-security-scanner` | After pip install |
| **Docker** | `docker run api-security-scanner` | Container execution |

This structure provides a clean, maintainable, and extensible foundation for the API Security Scanner project.
