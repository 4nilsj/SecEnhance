"""
Test configuration and utilities for API Security Scanner tests.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional


class TestConfig:
    """Test configuration class."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.test_dir = self.project_root / "tests"
        self.src_dir = self.project_root / "src"
        self.utils_dir = self.project_root / "utils"
        self.plugins_dir = self.project_root / "plugins"
        
        # Test configuration
        self.test_timeout = 300  # 5 minutes
        self.test_retries = 3
        self.test_parallel = False
        
        # Coverage configuration
        self.coverage_threshold = 80
        self.coverage_exclude = [
            "*/tests/*",
            "*/test_*",
            "*/__pycache__/*",
            "*/venv/*",
            "*/env/*"
        ]
        
        # Test markers
        self.test_markers = {
            "unit": "Unit tests",
            "integration": "Integration tests", 
            "slow": "Slow running tests",
            "network": "Tests requiring network access",
            "docker": "Tests requiring Docker",
            "zap": "Tests requiring ZAP",
            "database": "Tests requiring database"
        }
        
        # Environment variables for tests
        self.test_env_vars = {
            "PYTHONPATH": str(self.project_root),
            "TESTING": "true",
            "LOG_LEVEL": "DEBUG"
        }
    
    def setup_test_environment(self):
        """Setup test environment."""
        # Add project paths to Python path
        sys.path.insert(0, str(self.project_root))
        sys.path.insert(0, str(self.src_dir))
        sys.path.insert(0, str(self.utils_dir))
        sys.path.insert(0, str(self.plugins_dir))
        
        # Set environment variables
        for key, value in self.test_env_vars.items():
            os.environ[key] = value
    
    def get_test_files(self) -> Dict[str, Path]:
        """Get test file paths."""
        return {
            "utils": self.test_dir / "test_utils.py",
            "src": self.test_dir / "test_src.py",
            "plugins": self.test_dir / "test_plugins.py",
            "container": self.test_dir / "test_container.py",
            "integration": self.test_dir / "test_integration.py",
            "fixtures": self.test_dir / "fixtures.py",
            "runners": self.test_dir / "test_runners.py",
            "config": self.test_dir / "test_config.py"
        }
    
    def get_source_files(self) -> Dict[str, Path]:
        """Get source file paths."""
        return {
            "cli": self.src_dir / "cli.py",
            "db_manager": self.src_dir / "db_manager.py",
            "zap_manager": self.src_dir / "zap_manager.py",
            "scanner_plugins": self.src_dir / "scanner_plugins.py",
            "report_generator": self.src_dir / "report_generator.py"
        }
    
    def get_utility_files(self) -> Dict[str, Path]:
        """Get utility file paths."""
        return {
            "logger": self.utils_dir / "logger.py",
            "auth_handler": self.utils_dir / "auth_handler.py",
            "input_parsers": self.utils_dir / "input_parsers.py"
        }
    
    def get_plugin_files(self) -> Dict[str, Path]:
        """Get plugin file paths."""
        return {
            "cors_checker": self.plugins_dir / "cors_checker.py",
            "rate_limiting_checker": self.plugins_dir / "rate_limiting_checker.py",
            "security_headers_checker": self.plugins_dir / "security_headers_checker.py",
            "enhanced_security_checker": self.plugins_dir / "enhanced_security_checker.py"
        }
    
    def validate_test_structure(self) -> Dict[str, Any]:
        """Validate test structure."""
        results = {
            "valid": True,
            "errors": [],
            "warnings": []
        }
        
        # Check test files
        test_files = self.get_test_files()
        for name, path in test_files.items():
            if not path.exists():
                results["errors"].append(f"Missing test file: {name} ({path})")
                results["valid"] = False
        
        # Check source files
        source_files = self.get_source_files()
        for name, path in source_files.items():
            if not path.exists():
                results["errors"].append(f"Missing source file: {name} ({path})")
                results["valid"] = False
        
        # Check utility files
        utility_files = self.get_utility_files()
        for name, path in utility_files.items():
            if not path.exists():
                results["errors"].append(f"Missing utility file: {name} ({path})")
                results["valid"] = False
        
        # Check plugin files
        plugin_files = self.get_plugin_files()
        for name, path in plugin_files.items():
            if not path.exists():
                results["warnings"].append(f"Missing plugin file: {name} ({path})")
        
        # Check pytest configuration
        pytest_ini = self.project_root / "pytest.ini"
        if not pytest_ini.exists():
            results["warnings"].append("Missing pytest.ini configuration file")
        
        return results
    
    def get_pytest_args(self, 
                       verbose: bool = False,
                       coverage: bool = True,
                       markers: Optional[str] = None,
                       exclude_markers: Optional[str] = None) -> list:
        """Get pytest command line arguments."""
        args = []
        
        if verbose:
            args.append("-v")
        
        if coverage:
            args.extend([
                "--cov=src",
                "--cov=utils",
                "--cov=plugins",
                f"--cov-fail-under={self.coverage_threshold}",
                "--cov-report=term-missing",
                "--cov-report=html:htmlcov",
                "--cov-report=xml:coverage.xml"
            ])
        
        if markers:
            args.extend(["-m", markers])
        
        if exclude_markers:
            args.extend(["-m", f"not {exclude_markers}"])
        
        args.extend([
            "--tb=short",
            "--strict-markers",
            "--disable-warnings",
            str(self.test_dir)
        ])
        
        return args
    
    def get_test_environment_vars(self) -> Dict[str, str]:
        """Get test environment variables."""
        return self.test_env_vars.copy()
    
    def get_coverage_config(self) -> Dict[str, Any]:
        """Get coverage configuration."""
        return {
            "threshold": self.coverage_threshold,
            "exclude": self.coverage_exclude,
            "html_dir": "htmlcov",
            "xml_file": "coverage.xml"
        }


class TestDataManager:
    """Test data management utilities."""
    
    def __init__(self, test_dir: Optional[Path] = None):
        self.test_dir = test_dir or Path(__file__).parent
        self.data_dir = self.test_dir / "data"
        self.fixtures_dir = self.test_dir / "fixtures"
    
    def setup_test_data(self):
        """Setup test data directories."""
        self.data_dir.mkdir(exist_ok=True)
        self.fixtures_dir.mkdir(exist_ok=True)
    
    def get_test_data_path(self, filename: str) -> Path:
        """Get path to test data file."""
        return self.data_dir / filename
    
    def get_fixture_path(self, filename: str) -> Path:
        """Get path to fixture file."""
        return self.fixtures_dir / filename
    
    def create_test_data_file(self, filename: str, content: str) -> Path:
        """Create a test data file."""
        file_path = self.get_test_data_path(filename)
        file_path.write_text(content)
        return file_path
    
    def create_fixture_file(self, filename: str, content: str) -> Path:
        """Create a fixture file."""
        file_path = self.get_fixture_path(filename)
        file_path.write_text(content)
        return file_path


class TestLogger:
    """Test logging utilities."""
    
    def __init__(self, name: str = "test"):
        self.name = name
        self.logs = []
    
    def log(self, level: str, message: str):
        """Log a message."""
        log_entry = {
            "level": level,
            "message": message,
            "timestamp": self._get_timestamp()
        }
        self.logs.append(log_entry)
        print(f"[{level}] {message}")
    
    def info(self, message: str):
        """Log info message."""
        self.log("INFO", message)
    
    def warning(self, message: str):
        """Log warning message."""
        self.log("WARNING", message)
    
    def error(self, message: str):
        """Log error message."""
        self.log("ERROR", message)
    
    def debug(self, message: str):
        """Log debug message."""
        self.log("DEBUG", message)
    
    def get_logs(self, level: Optional[str] = None) -> list:
        """Get logs, optionally filtered by level."""
        if level:
            return [log for log in self.logs if log["level"] == level]
        return self.logs.copy()
    
    def clear_logs(self):
        """Clear all logs."""
        self.logs.clear()
    
    def _get_timestamp(self) -> str:
        """Get current timestamp."""
        from datetime import datetime
        return datetime.now().isoformat()


# Global test configuration instance
test_config = TestConfig()

# Global test data manager instance
test_data_manager = TestDataManager()

# Global test logger instance
test_logger = TestLogger("api_scanner_tests")


def setup_test_environment():
    """Setup test environment."""
    test_config.setup_test_environment()
    test_data_manager.setup_test_data()
    test_logger.info("Test environment setup complete")


def get_test_config() -> TestConfig:
    """Get test configuration."""
    return test_config


def get_test_data_manager() -> TestDataManager:
    """Get test data manager."""
    return test_data_manager


def get_test_logger() -> TestLogger:
    """Get test logger."""
    return test_logger


if __name__ == "__main__":
    """Test configuration validation."""
    setup_test_environment()
    
    # Validate test structure
    validation_result = test_config.validate_test_structure()
    
    print("Test Configuration Validation:")
    print(f"Valid: {validation_result['valid']}")
    
    if validation_result['errors']:
        print("Errors:")
        for error in validation_result['errors']:
            print(f"  - {error}")
    
    if validation_result['warnings']:
        print("Warnings:")
        for warning in validation_result['warnings']:
            print(f"  - {warning}")
    
    # Print configuration
    print("\nTest Configuration:")
    print(f"Project root: {test_config.project_root}")
    print(f"Test directory: {test_config.test_dir}")
    print(f"Coverage threshold: {test_config.coverage_threshold}%")
    print(f"Test timeout: {test_config.test_timeout}s")
    
    # Print pytest args
    pytest_args = test_config.get_pytest_args(verbose=True, coverage=True)
    print(f"\nPytest arguments: {' '.join(pytest_args)}")
    
    sys.exit(0 if validation_result['valid'] else 1)
