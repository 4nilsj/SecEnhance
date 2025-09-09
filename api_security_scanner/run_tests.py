
#!/usr/bin/env python3
"""
Test runner script for API Security Scanner.

This script provides a convenient way to run tests with different configurations.
"""

import sys
import os
import argparse
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from tests.test_runners import TestRunner, TestEnvironment, TestValidator
from tests.test_config import setup_test_environment, get_test_config


def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(
        description="API Security Scanner Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_tests.py --quick              # Run quick tests (exclude slow/integration)
  python run_tests.py --full               # Run full test suite with coverage
  python run_tests.py --unit               # Run unit tests only
  python run_tests.py --integration        # Run integration tests only
  python run_tests.py --validate           # Validate test environment
  python run_tests.py --file test_utils.py # Run specific test file
  python run_tests.py --coverage           # Run with coverage report
  python run_tests.py --parallel           # Run tests in parallel
        """
    )
    
    # Test type options
    test_group = parser.add_mutually_exclusive_group()
    test_group.add_argument("--quick", action="store_true", 
                           help="Run quick tests (exclude slow/integration/network/docker)")
    test_group.add_argument("--full", action="store_true", 
                           help="Run full test suite")
    test_group.add_argument("--unit", action="store_true", 
                           help="Run unit tests only")
    test_group.add_argument("--integration", action="store_true", 
                           help="Run integration tests only")
    test_group.add_argument("--validate", action="store_true", 
                           help="Validate test environment")
    
    # Test selection options
    parser.add_argument("--file", help="Run specific test file")
    parser.add_argument("--function", help="Run specific test function")
    parser.add_argument("--markers", help="Run tests with specific markers (comma-separated)")
    parser.add_argument("--exclude-markers", help="Exclude tests with specific markers (comma-separated)")
    
    # Test execution options
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Verbose output")
    parser.add_argument("--coverage", action="store_true", 
                       help="Generate coverage report")
    parser.add_argument("--no-coverage", action="store_true", 
                       help="Disable coverage report")
    parser.add_argument("--parallel", "-n", type=int, metavar="NUM", 
                       help="Run tests in parallel with NUM workers")
    parser.add_argument("--timeout", type=int, default=300, 
                       help="Test timeout in seconds (default: 300)")
    
    # Output options
    parser.add_argument("--html-report", action="store_true", 
                       help="Generate HTML coverage report")
    parser.add_argument("--xml-report", action="store_true", 
                       help="Generate XML coverage report")
    parser.add_argument("--junit-xml", help="Generate JUnit XML report")
    
    # Configuration options
    parser.add_argument("--config", help="Use specific test configuration file")
    parser.add_argument("--setup-only", action="store_true", 
                       help="Only setup test environment, don't run tests")
    
    args = parser.parse_args()
    
    # Setup test environment
    setup_test_environment()
    
    if args.setup_only:
        print("Test environment setup complete.")
        return 0
    
    # Validate test environment if requested
    if args.validate:
        validator = TestValidator()
        result = validator.validate_test_structure()
        import_result = validator.validate_imports()
        
        print("Test Environment Validation:")
        print(f"Structure valid: {result['valid']}")
        print(f"Imports valid: {import_result['valid']}")
        
        if result['missing_files']:
            print(f"Missing files: {result['missing_files']}")
        
        if import_result['import_errors']:
            print(f"Import errors: {import_result['import_errors']}")
        
        return 0 if result['valid'] and import_result['valid'] else 1
    
    # Initialize test runner
    runner = TestRunner()
    
    # Determine test execution strategy
    if args.quick:
        result = runner.run_tests_exclude_markers(
            ["slow", "integration", "network", "docker"], 
            verbose=args.verbose
        )
    elif args.full:
        result = runner.run_all_tests(
            verbose=args.verbose, 
            coverage=args.coverage and not args.no_coverage
        )
    elif args.unit:
        result = runner.run_unit_tests(
            verbose=args.verbose, 
            coverage=args.coverage and not args.no_coverage
        )
    elif args.integration:
        result = runner.run_integration_tests(verbose=args.verbose)
    elif args.file:
        result = runner.run_specific_test(
            args.file, 
            args.function, 
            args.verbose
        )
    elif args.markers:
        markers = args.markers.split(",")
        result = runner.run_tests_with_markers(markers, args.verbose)
    elif args.exclude_markers:
        markers = args.exclude_markers.split(",")
        result = runner.run_tests_exclude_markers(markers, args.verbose)
    else:
        # Default to quick tests
        result = runner.run_tests_exclude_markers(
            ["slow", "integration", "network", "docker"], 
            verbose=args.verbose
        )
    
    # Print results
    print("\n" + "="*60)
    print("TEST RESULTS")
    print("="*60)
    print(f"Success: {result['success']}")
    print(f"Return code: {result['returncode']}")
    
    if result['stdout']:
        print("\nSTDOUT:")
        print("-" * 40)
        print(result['stdout'])
    
    if result['stderr']:
        print("\nSTDERR:")
        print("-" * 40)
        print(result['stderr'])
    
    # Print coverage information if available
    if args.coverage and not args.no_coverage:
        coverage_file = project_root / "htmlcov" / "index.html"
        if coverage_file.exists():
            print(f"\nCoverage report available at: {coverage_file}")
    
    print("="*60)
    
    return result['returncode']


def run_quick_tests():
    """Run quick tests for development."""
    return main_with_args(["--quick", "--verbose"])


def run_full_tests():
    """Run full test suite."""
    return main_with_args(["--full", "--verbose", "--coverage"])


def run_unit_tests():
    """Run unit tests only."""
    return main_with_args(["--unit", "--verbose", "--coverage"])


def run_integration_tests():
    """Run integration tests only."""
    return main_with_args(["--integration", "--verbose"])


def validate_environment():
    """Validate test environment."""
    return main_with_args(["--validate"])


def main_with_args(args):
    """Run main with specific arguments."""
    original_argv = sys.argv
    sys.argv = [sys.argv[0]] + args
    try:
        return main()
    finally:
        sys.argv = original_argv


if __name__ == "__main__":
    sys.exit(main())
