"""
API Security Scanner

A comprehensive command-line tool for automated API security scanning with
extensibility for custom vulnerability checks and detailed reporting.

This package provides:
- OWASP ZAP integration for comprehensive security testing
- Custom plugin system for additional security checks
- Multiple input format support (Postman, OpenAPI, curl)
- Authentication support (token, cookie, header-based)
- Performance monitoring and comprehensive logging
- SQLite storage and HTML/JSON reporting
"""

__version__ = "1.0.0"
__author__ = "API Security Scanner Team"
__email__ = "security@example.com"
__description__ = "Automated API security scanning tool"

# Import main components for easy access
from .core.db_manager import DatabaseManager
from .core.zap_manager import ZAPManager
from .core.report_generator import ReportGenerator
from .core.scanner_plugins import PluginManager
from .core.config import get_config, get_config_manager

# Import utilities
from .utils.logger import get_logger, setup_logging
from .utils.auth_handler import create_auth_handler
from .utils.input_parsers import parse_input

# Import CLI
from .cli.main import cli

__all__ = [
    # Core components
    "DatabaseManager", 
    "ZAPManager",
    "ReportGenerator",
    "PluginManager",
    
    # Configuration
    "get_config",
    "get_config_manager",
    
    # Utilities
    "get_logger",
    "setup_logging",
    "create_auth_handler",
    "parse_input",
    
    # CLI
    "cli",
    
    # Package info
    "__version__",
    "__author__",
    "__email__",
    "__description__"
]
