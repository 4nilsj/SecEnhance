"""
Test runners and utilities for API Security Scanner tests.
"""

import pytest
import sys
import os
from pathlib import Path
import subprocess
import tempfile
import shutil


class TestRunner:
    """Test runner utility class."""
    
    def __init__(self, project_root=None):
        self.project_root = project_root or Path(__file__).parent.parent
        self.test_dir = self.project_root / "tests"
        self.src_dir = self.project_root / "src"
        self.utils_dir = self.project_root / "utils"
        self.plugins_dir = self.project_root / "plugins"
    
    def run_unit_tests(self, verbose=False, coverage=True):
        """Run unit tests."""
        cmd = ["python", "-m", "pytest"]
        
        if verbose:
            cmd.append("-v")
        
        if coverage:
            cmd.extend([
                "--cov=src",
                "--cov=utils", 
                "--cov=plugins",
                "--cov-report=term-missing",
                "--cov-report=html:htmlcov"
            ])
        
        cmd.extend([
            str(self.test_dir / "test_utils.py"),
            str(self.test_dir / "test_src.py"),
            str(self.test_dir / "test_plugins.py"),
            str(self.test_dir / "test_container.py")
        ])
        
        return self._run_command(cmd)
    
    def run_integration_tests(self, verbose=False):
        """Run integration tests."""
        cmd = ["python", "-m", "pytest"]
        
        if verbose:
            cmd.append("-v")
        
        cmd.extend([
            "-m", "integration",
            str(self.test_dir / "test_integration.py")
        ])
        
        return self._run_command(cmd)
    
    def run_all_tests(self, verbose=False, coverage=True):
        """Run all tests."""
        cmd = ["python", "-m", "pytest"]
        
        if verbose:
            cmd.append("-v")
        
        if coverage:
            cmd.extend([
                "--cov=src",
                "--cov=utils",
                "--cov=plugins",
                "--cov-report=term-missing",
                "--cov-report=html:htmlcov",
                "--cov-report=xml:coverage.xml"
            ])
        
        cmd.append(str(self.test_dir))
        
        return self._run_command(cmd)
    
    def run_specific_test(self, test_file, test_function=None, verbose=False):
        """Run a specific test file or function."""
        cmd = ["python", "-m", "pytest"]
        
        if verbose:
            cmd.append("-v")
        
        if test_function:
            cmd.append(f"{test_file}::{test_function}")
        else:
            cmd.append(str(test_file))
        
        return self._run_command(cmd)
    
    def run_tests_with_markers(self, markers, verbose=False):
        """Run tests with specific markers."""
        cmd = ["python", "-m", "pytest"]
        
        if verbose:
            cmd.append("-v")
        
        if isinstance(markers, list):
            markers = " or ".join(markers)
        
        cmd.extend(["-m", markers, str(self.test_dir)])
        
        return self._run_command(cmd)
    
    def run_tests_exclude_markers(self, markers, verbose=False):
        """Run tests excluding specific markers."""
        cmd = ["python", "-m", "pytest"]
        
        if verbose:
            cmd.append("-v")
        
        if isinstance(markers, list):
            markers = " and ".join([f"not {marker}" for marker in markers])
        else:
            markers = f"not {markers}"
        
        cmd.extend(["-m", markers, str(self.test_dir)])
        
        return self._run_command(cmd)
    
    def _run_command(self, cmd):
        """Run a command and return the result."""
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": "Test execution timed out",
                "success": False
            }
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }


class TestEnvironment:
    """Test environment setup and teardown."""
    
    def __init__(self, project_root=None):
        self.project_root = project_root or Path(__file__).parent.parent
        self.temp_dirs = []
    
    def setup_test_environment(self):
        """Setup test environment."""
        # Create temporary directories
        temp_dir = tempfile.mkdtemp(prefix="api_scanner_test_")
        self.temp_dirs.append(temp_dir)
        
        # Create subdirectories
        subdirs = ["data", "logs", "reports", "workspace"]
        for subdir in subdirs:
            os.makedirs(os.path.join(temp_dir, subdir), exist_ok=True)
        
        return temp_dir
    
    def cleanup_test_environment(self):
        """Cleanup test environment."""
        for temp_dir in self.temp_dirs:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
        self.temp_dirs.clear()
    
    def create_test_files(self, temp_dir):
        """Create test files in temporary directory."""
        from tests.fixtures import create_test_files
        return create_test_files(temp_dir)


class TestValidator:
    """Test validation utilities."""
    
    @staticmethod
    def validate_test_structure(project_root=None):
        """Validate test structure."""
        project_root = project_root or Path(__file__).parent.parent
        test_dir = project_root / "tests"
        
        required_files = [
            "__init__.py",
            "conftest.py",
            "test_utils.py",
            "test_src.py",
            "test_plugins.py",
            "test_container.py",
            "test_integration.py",
            "fixtures.py",
            "test_runners.py"
        ]
        
        missing_files = []
        for file in required_files:
            if not (test_dir / file).exists():
                missing_files.append(file)
        
        return {
            "valid": len(missing_files) == 0,
            "missing_files": missing_files
        }
    
    @staticmethod
    def validate_test_coverage(project_root=None):
        """Validate test coverage."""
        project_root = project_root or Path(__file__).parent.parent
        
        # Check if coverage report exists
        coverage_file = project_root / "htmlcov" / "index.html"
        coverage_xml = project_root / "coverage.xml"
        
        return {
            "html_coverage_exists": coverage_file.exists(),
            "xml_coverage_exists": coverage_xml.exists()
        }
    
    @staticmethod
    def validate_imports():
        """Validate that all modules can be imported."""
        project_root = Path(__file__).parent.parent
        sys.path.insert(0, str(project_root))
        
        import_errors = []
        
        # Test imports
        modules_to_test = [
            ("api_security_scanner.cli.main", "CLI module"),
            ("api_security_scanner.core.db_manager", "Database manager"),
            ("api_security_scanner.core.zap_manager", "ZAP manager"),
            ("api_security_scanner.core.scanner_plugins", "Scanner plugins"),
            ("api_security_scanner.core.report_generator", "Report generator"),
            ("api_security_scanner.utils.logger", "Logger utility"),
            ("api_security_scanner.utils.auth_handler", "Auth handler"),
            ("api_security_scanner.utils.input_parsers", "Input parsers"),
            ("api_security_scanner.plugins.cors_checker", "CORS checker plugin"),
            ("api_security_scanner.plugins.rate_limiting_checker", "Rate limiting checker plugin"),
            ("api_security_scanner.plugins.security_headers_checker", "Security headers checker plugin"),
            ("api_security_scanner.plugins.enhanced_security_checker", "Enhanced security checker plugin"),
            ("api_security_scanner.container_config", "Container configuration")
        ]
        
        for module_name, description in modules_to_test:
            try:
                __import__(module_name)
            except ImportError as e:
                import_errors.append(f"{description} ({module_name}): {e}")
        
        return {
            "valid": len(import_errors) == 0,
            "import_errors": import_errors
        }


def run_quick_tests():
    """Run quick tests for development."""
    runner = TestRunner()
    return runner.run_tests_exclude_markers(["slow", "integration", "network", "docker"], verbose=True)


def run_full_test_suite():
    """Run full test suite."""
    runner = TestRunner()
    return runner.run_all_tests(verbose=True, coverage=True)


def run_unit_tests_only():
    """Run only unit tests."""
    runner = TestRunner()
    return runner.run_unit_tests(verbose=True, coverage=True)


def run_integration_tests_only():
    """Run only integration tests."""
    runner = TestRunner()
    return runner.run_integration_tests(verbose=True)


def validate_test_environment():
    """Validate test environment."""
    validator = TestValidator()
    
    structure_result = validator.validate_test_structure()
    import_result = validator.validate_imports()
    
    return {
        "structure_valid": structure_result["valid"],
        "imports_valid": import_result["valid"],
        "missing_files": structure_result["missing_files"],
        "import_errors": import_result["import_errors"]
    }


if __name__ == "__main__":
    """Command line interface for test runners."""
    import argparse
    
    parser = argparse.ArgumentParser(description="API Security Scanner Test Runner")
    parser.add_argument("--quick", action="store_true", help="Run quick tests")
    parser.add_argument("--full", action="store_true", help="Run full test suite")
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--integration", action="store_true", help="Run integration tests only")
    parser.add_argument("--validate", action="store_true", help="Validate test environment")
    parser.add_argument("--file", help="Run specific test file")
    parser.add_argument("--function", help="Run specific test function")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.validate:
        result = validate_test_environment()
        print("Test Environment Validation:")
        print(f"Structure valid: {result['structure_valid']}")
        print(f"Imports valid: {result['imports_valid']}")
        if result['missing_files']:
            print(f"Missing files: {result['missing_files']}")
        if result['import_errors']:
            print(f"Import errors: {result['import_errors']}")
        sys.exit(0 if result['structure_valid'] and result['imports_valid'] else 1)
    
    runner = TestRunner()
    
    if args.quick:
        result = run_quick_tests()
    elif args.full:
        result = run_full_test_suite()
    elif args.unit:
        result = run_unit_tests_only()
    elif args.integration:
        result = run_integration_tests_only()
    elif args.file:
        result = runner.run_specific_test(args.file, args.function, args.verbose)
    else:
        result = run_quick_tests()
    
    print("Test Results:")
    print(f"Success: {result['success']}")
    print(f"Return code: {result['returncode']}")
    if result['stdout']:
        print("STDOUT:")
        print(result['stdout'])
    if result['stderr']:
        print("STDERR:")
        print(result['stderr'])
    
    sys.exit(result['returncode'])
