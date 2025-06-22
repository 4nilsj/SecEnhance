# API Security Scanner - Project Structure

This document describes the organized structure of the API Security Scanner project.

## Root Directory Structure

```
api-security-scanner/
├── src/                    # Source code
├── reports/                # Generated reports
├── data/                   # Data files and uploads
├── scripts/                # Utility scripts
├── docs/                   # Documentation
├── venv/                   # Virtual environment
├── main.py                 # Main entry point
├── setup.py                # Package setup
├── requirements.txt        # Python dependencies
├── .gitignore             # Git ignore rules
├── README.md              # Project README
└── PROJECT_STRUCTURE.md   # This file
```

## Source Code (`src/`)

### Core Module (`src/core/`)
Contains the main scanner functionality:
- `scanner.py` - Main API security scanner class
- `api_security_scanner_*.py` - Various versions of the scanner
- `__init__.py` - Package initialization

### Web Interface (`src/web/`)
Contains the web application:
- `app.py` - Main Flask application
- `app_updated.py` - Updated version of the web app
- `templates/` - HTML templates
- `static/` - Static files (CSS, JS, images)
- `__init__.py` - Package initialization

### Scanners (`src/scanners/`)
Contains specialized security scanners:
- `burp_*.py` - Burp Suite integration modules
- `custom_bchecks.py` - Custom security checks
- `bcheck_scripts.py` - Security check scripts
- `__init__.py` - Package initialization

### Utilities (`src/utils/`)
Contains utility functions and helpers:
- `logger.py` - Logging utilities
- `debug.py` - Debug utilities
- `debug_endpoint_extraction.py` - Endpoint extraction utilities
- `performance_optimizer*.py` - Performance optimization tools
- `__init__.py` - Package initialization

### Tests (`src/tests/`)
Contains test modules:
- `test_*.py` - Various test files
- `__init__.py` - Package initialization

### Examples (`src/examples/`)
Contains example usage and demos:
- `demo_*.py` - Demonstration scripts
- `simple_*.py` - Simple examples
- `insecure_api.py` - Example insecure API
- `integration_examples.py` - Integration examples
- `__init__.py` - Package initialization

### Configuration (`src/config/`)
Contains configuration files:
- `default_config.json` - Default scanner configuration
- `debug_config.py` - Debug configuration
- `__init__.py` - Package initialization

### Documentation (`src/docs/`)
Contains source documentation:
- `__init__.py` - Package initialization

## Reports (`reports/`)

### JSON Reports (`reports/json/`)
Contains all generated JSON security reports:
- `api_security_report_*.json` - API security scan reports
- `comprehensive_test_report_*.json` - Comprehensive test reports
- `performance_*.json` - Performance test results
- Various other result files

### HTML Reports (`reports/html/`)
Contains all generated HTML security reports:
- `owasp_api_report_*.html` - OWASP API security reports

### Logs (`reports/logs/`)
Contains application logs:
- `api_scanner.log` - Main application log
- `diagnostics_*.json` - Diagnostic information

## Data (`data/`)

### Uploads (`data/uploads/`)
Contains uploaded Postman collections:
- `upload_*.json` - Uploaded collection files

### Test Data (`data/`)
Contains test data files:
- `test_collection.json` - Test Postman collection
- `test_api.db` - Test database

## Scripts (`scripts/`)

Contains utility scripts:
- `run_comprehensive_scan.py` - Comprehensive scanning script
- `run_scanner.py` - Basic scanner runner
- `verify_scanner.py` - Scanner verification script
- `workflow_automation.py` - Workflow automation

## Documentation (`docs/`)

Contains project documentation:
- `ERROR_FIX_SUMMARY.md` - Error fixes documentation
- `PROGRESS_BAR_SUMMARY.md` - Progress bar implementation docs
- `WEB_UI_SUMMARY.md` - Web UI documentation
- `PERFORMANCE_SUMMARY.md` - Performance improvements docs
- `setup_and_usage_guide.md` - Setup and usage guide
- `api_collection_upload_guide.md` - API collection upload guide
- `owasp_api_top10_checklist.md` - OWASP API Top 10 checklist
- `burp_direct_integration_guide.md` - Burp Suite integration guide
- `README_workflow.md` - Workflow documentation

## Key Files

### Main Entry Point (`main.py`)
- Command-line interface for the scanner
- Supports both scan and web interface modes
- Handles argument parsing and execution

### Package Setup (`setup.py`)
- Package configuration for distribution
- Entry points and dependencies
- Metadata and classifiers

### Dependencies (`requirements.txt`)
- Python package dependencies
- Version specifications

### Git Configuration (`.gitignore`)
- Excludes unnecessary files from version control
- Covers Python, IDE, and project-specific exclusions

## Benefits of This Structure

1. **Modularity**: Clear separation of concerns with dedicated modules
2. **Maintainability**: Easy to locate and modify specific functionality
3. **Scalability**: Easy to add new features and modules
4. **Testing**: Dedicated test directory with comprehensive test coverage
5. **Documentation**: Well-organized documentation structure
6. **Configuration**: Centralized configuration management
7. **Examples**: Clear examples for users and developers
8. **Reports**: Organized output with clear categorization

## Usage

### Command Line
```bash
# Run a security scan
python main.py scan --collection data/test_collection.json

# Start web interface
python main.py web --port 8080
```

### Development
```bash
# Install in development mode
pip install -e .

# Run tests
python -m pytest src/tests/

# Run examples
python src/examples/simple_scan_demo.py
```

This structure provides a clean, professional, and maintainable codebase that follows Python best practices and makes the project easy to understand, use, and contribute to. 