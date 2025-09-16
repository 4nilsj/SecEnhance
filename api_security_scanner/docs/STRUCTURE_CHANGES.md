# Project Structure Standardization

This document outlines the changes made to standardize the API Security Scanner project structure following Python best practices.

## ✅ Completed Changes

### 1. **Package Structure Reorganization**

**Before:**
```
api_security_scanner/
├── src/
│   ├── cli.py
│   ├── db_manager.py
│   ├── zap_manager.py
│   ├── report_generator.py
│   └── scanner_plugins.py
├── utils/
│   ├── logger.py
│   ├── auth_handler.py
│   └── input_parsers.py
├── plugins/
│   ├── cors_checker.py
│   ├── rate_limiting_checker.py
│   ├── security_headers_checker.py
│   └── enhanced_security_checker.py
└── main.py
```

**After:**
```
api_security_scanner/
├── api_security_scanner/          # Main package
│   ├── __init__.py
│   ├── core/                      # Core functionality
│   │   ├── __init__.py
│   │   ├── db_manager.py
│   │   ├── zap_manager.py
│   │   ├── report_generator.py
│   │   └── scanner_plugins.py
│   ├── cli/                       # Command-line interface
│   │   ├── __init__.py
│   │   └── main.py
│   ├── utils/                     # Utility modules
│   │   ├── __init__.py
│   │   ├── logger.py
│   │   ├── auth_handler.py
│   │   └── input_parsers.py
│   └── plugins/                   # Security plugins
│       ├── __init__.py
│       ├── cors_checker.py
│       ├── rate_limiting_checker.py
│       ├── security_headers_checker.py
│       └── enhanced_security_checker.py
├── tests/                         # Test suite
├── docs/                          # Documentation
├── examples/                      # Example files
├── main.py                        # Entry point
├── setup.py                       # Package setup
├── pyproject.toml                 # Modern Python packaging
└── requirements.txt               # Dependencies
```

### 2. **Import Statement Updates**

All import statements have been updated to use the new package structure:

**Core modules:**
- `from src.db_manager import DatabaseManager` → `from ..core.db_manager import DatabaseManager`
- `from src.zap_manager import ZAPManager` → `from ..core.zap_manager import ZAPManager`
- `from src.scanner_plugins import PluginManager` → `from ..core.scanner_plugins import PluginManager`

**Utility modules:**
- `from utils.logger import get_logger` → `from ..utils.logger import get_logger`
- `from utils.auth_handler import create_auth_handler` → `from ..utils.auth_handler import create_auth_handler`

**Plugin modules:**
- `from src.scanner_plugins import BasePlugin` → `from ..core.scanner_plugins import BasePlugin`

**Test modules:**
- `from src.db_manager import DatabaseManager` → `from api_security_scanner.core.db_manager import DatabaseManager`
- `from utils.logger import get_logger` → `from api_security_scanner.utils.logger import get_logger`

### 3. **Configuration Files Updated**

**pytest.ini:**
- Updated coverage paths: `--cov=src --cov=utils --cov=plugins` → `--cov=api_security_scanner`

**Docker files:**
- Updated entrypoint script to use: `python -m api_security_scanner.cli.main`

**Test configuration:**
- Updated Python path setup in all test files
- Updated module import validation in test runners

### 4. **Package Setup Files**

**setup.py:**
- Created comprehensive setup.py with proper metadata
- Added console script entry points
- Configured package discovery and data files

**pyproject.toml:**
- Created modern Python packaging configuration
- Added tool configurations for black, isort, mypy, pytest, coverage
- Defined project metadata and dependencies

### 5. **Entry Points**

**Console Scripts:**
- `api-security-scanner` → `api_security_scanner.cli.main:cli`
- `api-scanner` → `api_security_scanner.cli.main:cli`

**Module Execution:**
- `python main.py` → `python -m api_security_scanner.cli.main`

### 6. **Package Initialization**

**Main package (`api_security_scanner/__init__.py`):**
- Exports main components for easy importing
- Provides version and metadata information
- Clean public API

**Sub-packages:**
- All sub-packages have proper `__init__.py` files
- Clear module organization and exports

## 🎯 Benefits of Standardization

### 1. **Python Best Practices**
- Follows PEP 8 and Python packaging standards
- Proper namespace organization
- Clear separation of concerns

### 2. **Installation & Distribution**
- Can be installed via pip: `pip install -e .`
- Proper package discovery
- Console script entry points

### 3. **Development Experience**
- Clear import paths
- Better IDE support and autocomplete
- Easier testing and debugging

### 4. **Maintainability**
- Logical module organization
- Clear dependencies between modules
- Easier to extend and modify

### 5. **Container Compatibility**
- Works seamlessly with Docker/Podman
- Proper module execution in containers
- Maintained all container functionality

## 🔧 Usage Examples

### **Installation:**
```bash
# Development installation
pip install -e .

# Production installation
pip install api-security-scanner
```

### **Command Line Usage:**
```bash
# Using console script
api-security-scanner scan -f collection.json

# Using module execution
python -m api_security_scanner.cli.main scan -f collection.json

# Using main.py (backward compatibility)
python main.py scan -f collection.json
```

### **Python API Usage:**
```python
from api_security_scanner import DatabaseManager, ZAPManager
from api_security_scanner.utils import get_logger, parse_input
from api_security_scanner.plugins import CORSChecker

# Use the components
logger = get_logger(__name__)
db_manager = DatabaseManager()
zap_manager = ZAPManager()
```

### **Testing:**
```bash
# Run tests with new structure
python run_tests.py --full

# Direct pytest usage
pytest tests/ -v

# Coverage reporting
pytest --cov=api_security_scanner --cov-report=html
```

## 📁 Final Structure

The project now follows a clean, standardized Python package structure that:

- ✅ Follows Python packaging best practices
- ✅ Maintains all existing functionality
- ✅ Provides clear import paths
- ✅ Supports both development and production use
- ✅ Works with Docker/Podman containers
- ✅ Includes comprehensive testing
- ✅ Has proper documentation structure
- ✅ Supports modern Python packaging tools

All path-related issues have been resolved, and the project is now ready for distribution, development, and production use.
