#!/usr/bin/env python3
"""
Python 3 Compatibility Checker for Dependencies
Analyzes all requirements.txt files to identify potential Python 3 incompatibilities
"""

import sys
import subprocess
import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import re


def check_python_version() -> Tuple[bool, str]:
    """Check if current Python version is compatible."""
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    is_compatible = version >= (3, 8)
    return is_compatible, version_str


def find_requirements_files() -> List[str]:
    """Find all requirements.txt files in the project."""
    project_root = Path(__file__).parent
    requirements_files = []
    
    for req_file in project_root.rglob("requirements.txt"):
        requirements_files.append(str(req_file))
    
    return requirements_files


def parse_requirements_file(file_path: str) -> List[Dict[str, str]]:
    """Parse a requirements.txt file and extract package information."""
    packages = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Parse package specification
                package_info = parse_package_spec(line)
                if package_info:
                    package_info['file'] = file_path
                    package_info['line'] = line_num
                    packages.append(package_info)
    
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}")
    
    return packages


def parse_package_spec(spec: str) -> Optional[Dict[str, str]]:
    """Parse a package specification line."""
    # Remove comments
    spec = spec.split('#')[0].strip()
    if not spec:
        return None
    
    # Basic parsing - this could be enhanced for more complex cases
    package_info = {
        'name': '',
        'version': '',
        'specifier': '',
        'raw': spec
    }
    
    # Handle different formats: package, package==version, package>=version, etc.
    if '==' in spec:
        parts = spec.split('==', 1)
        package_info['name'] = parts[0].strip()
        package_info['version'] = parts[1].strip()
        package_info['specifier'] = '=='
    elif '>=' in spec:
        parts = spec.split('>=', 1)
        package_info['name'] = parts[0].strip()
        package_info['version'] = parts[1].strip()
        package_info['specifier'] = '>='
    elif '<=' in spec:
        parts = spec.split('<=', 1)
        package_info['name'] = parts[0].strip()
        package_info['version'] = parts[1].strip()
        package_info['specifier'] = '<='
    elif '>' in spec:
        parts = spec.split('>', 1)
        package_info['name'] = parts[0].strip()
        package_info['version'] = parts[1].strip()
        package_info['specifier'] = '>'
    elif '<' in spec:
        parts = spec.split('<', 1)
        package_info['name'] = parts[0].strip()
        package_info['version'] = parts[1].strip()
        package_info['specifier'] = '<'
    else:
        # No version specified
        package_info['name'] = spec.strip()
    
    return package_info


def get_known_python2_packages() -> Dict[str, Dict[str, str]]:
    """Return a dictionary of packages known to have Python 2 compatibility issues."""
    return {
        'zipfile36': {
            'issue': 'Python 2 compatibility package - not needed in Python 3',
            'recommendation': 'Remove this package as zipfile is built-in to Python 3',
            'severity': 'high'
        },
        'configparser': {
            'issue': 'Python 2 compatibility package - not needed in Python 3',
            'recommendation': 'Remove this package as configparser is built-in to Python 3',
            'severity': 'high'
        },
        'futures': {
            'issue': 'Python 2 compatibility package for concurrent.futures',
            'recommendation': 'Remove this package as concurrent.futures is built-in to Python 3',
            'severity': 'high'
        },
        'six': {
            'issue': 'Python 2/3 compatibility library',
            'recommendation': 'Consider if still needed - many modern packages don\'t require it',
            'severity': 'medium'
        },
        'pathlib2': {
            'issue': 'Python 2 compatibility package for pathlib',
            'recommendation': 'Remove this package as pathlib is built-in to Python 3',
            'severity': 'high'
        },
        'typing': {
            'issue': 'Python 2 compatibility package for typing',
            'recommendation': 'Remove this package as typing is built-in to Python 3',
            'severity': 'high'
        },
        'enum34': {
            'issue': 'Python 2 compatibility package for enum',
            'recommendation': 'Remove this package as enum is built-in to Python 3',
            'severity': 'high'
        },
        'backports': {
            'issue': 'Python 2 compatibility backports',
            'recommendation': 'Review if still needed for Python 3',
            'severity': 'medium'
        }
    }


def get_potentially_problematic_packages() -> Dict[str, Dict[str, str]]:
    """Return packages that might have Python 3 compatibility issues."""
    return {
        'androguard': {
            'issue': 'May have Python 3 compatibility issues in older versions',
            'recommendation': 'Ensure using version 3.4.0+ for Python 3.8+ compatibility',
            'severity': 'medium'
        },
        'apkleaks': {
            'issue': 'May have dependencies that are Python 2 specific',
            'recommendation': 'Verify all dependencies are Python 3 compatible',
            'severity': 'medium'
        },
        'mitmproxy': {
            'issue': 'Some versions may have Python 3 compatibility issues',
            'recommendation': 'Ensure using version 10.1.0+ for Python 3.8+',
            'severity': 'low'
        },
        'pyshark': {
            'issue': 'Depends on tshark/Wireshark, may have Python 3 issues',
            'recommendation': 'Verify tshark installation and Python 3 compatibility',
            'severity': 'medium'
        },
        'python-magic': {
            'issue': 'May require system-level libmagic installation',
            'recommendation': 'Ensure libmagic is installed for Python 3 compatibility',
            'severity': 'low'
        },
        'weasyprint': {
            'issue': 'Requires system dependencies that may not be Python 3 compatible',
            'recommendation': 'Verify system dependencies (cairo, pango, etc.)',
            'severity': 'medium'
        }
    }


def check_package_compatibility(package_name: str, version: str = "") -> Dict[str, str]:
    """Check if a package has known Python 3 compatibility issues."""
    python2_packages = get_known_python2_packages()
    problematic_packages = get_potentially_problematic_packages()
    
    # Check for known Python 2 compatibility packages
    if package_name in python2_packages:
        return {
            'status': 'incompatible',
            'issue': python2_packages[package_name]['issue'],
            'recommendation': python2_packages[package_name]['recommendation'],
            'severity': python2_packages[package_name]['severity']
        }
    
    # Check for potentially problematic packages
    if package_name in problematic_packages:
        return {
            'status': 'warning',
            'issue': problematic_packages[package_name]['issue'],
            'recommendation': problematic_packages[package_name]['recommendation'],
            'severity': problematic_packages[package_name]['severity']
        }
    
    return {
        'status': 'compatible',
        'issue': '',
        'recommendation': '',
        'severity': 'none'
    }


def analyze_all_requirements() -> Dict[str, List]:
    """Analyze all requirements.txt files for Python 3 compatibility."""
    requirements_files = find_requirements_files()
    all_packages = []
    compatibility_issues = []
    warnings = []
    
    print(f"🔍 Analyzing {len(requirements_files)} requirements.txt files...")
    
    for req_file in requirements_files:
        packages = parse_requirements_file(req_file)
        all_packages.extend(packages)
        
        for package in packages:
            compatibility = check_package_compatibility(package['name'], package['version'])
            
            if compatibility['status'] == 'incompatible':
                compatibility_issues.append({
                    'package': package,
                    'compatibility': compatibility
                })
            elif compatibility['status'] == 'warning':
                warnings.append({
                    'package': package,
                    'compatibility': compatibility
                })
    
    return {
        'all_packages': all_packages,
        'compatibility_issues': compatibility_issues,
        'warnings': warnings,
        'files_analyzed': requirements_files
    }


def print_compatibility_report():
    """Print a comprehensive Python 3 compatibility report."""
    print("🐍 Python 3 Dependency Compatibility Report")
    print("=" * 60)
    
    # Check current Python version
    is_compatible, version_str = check_python_version()
    print(f"✅ Python Version: {version_str}")
    print(f"✅ Python 3.8+ Compatible: {'Yes' if is_compatible else 'No'}")
    
    # Analyze all requirements
    analysis = analyze_all_requirements()
    
    print(f"\n📁 Files Analyzed: {len(analysis['files_analyzed'])}")
    for file_path in analysis['files_analyzed']:
        print(f"   - {file_path}")
    
    print(f"\n📦 Total Packages Found: {len(analysis['all_packages'])}")
    
    # Report compatibility issues
    if analysis['compatibility_issues']:
        print(f"\n❌ Compatibility Issues Found: {len(analysis['compatibility_issues'])}")
        print("-" * 40)
        
        for issue in analysis['compatibility_issues']:
            package = issue['package']
            compat = issue['compatibility']
            
            print(f"🚨 {package['name']} (in {package['file']}:{package['line']})")
            print(f"   Issue: {compat['issue']}")
            print(f"   Recommendation: {compat['recommendation']}")
            print(f"   Severity: {compat['severity']}")
            print()
    else:
        print("\n✅ No Python 2 compatibility packages found!")
    
    # Report warnings
    if analysis['warnings']:
        print(f"\n⚠️  Warnings: {len(analysis['warnings'])}")
        print("-" * 30)
        
        for warning in analysis['warnings']:
            package = warning['package']
            compat = warning['compatibility']
            
            print(f"⚠️  {package['name']} (in {package['file']}:{package['line']})")
            print(f"   Issue: {compat['issue']}")
            print(f"   Recommendation: {compat['recommendation']}")
            print(f"   Severity: {compat['severity']}")
            print()
    else:
        print("\n✅ No potential compatibility warnings!")
    
    # Summary
    print("\n📋 Summary:")
    print("-" * 20)
    print(f"✅ Files analyzed: {len(analysis['files_analyzed'])}")
    print(f"✅ Total packages: {len(analysis['all_packages'])}")
    print(f"❌ Compatibility issues: {len(analysis['compatibility_issues'])}")
    print(f"⚠️  Warnings: {len(analysis['warnings'])}")
    
    if analysis['compatibility_issues']:
        print("\n🎯 Action Required:")
        print("   - Remove Python 2 compatibility packages")
        print("   - Update packages with known issues")
        print("   - Test functionality after changes")
    else:
        print("\n🎉 All dependencies appear to be Python 3 compatible!")
    
    print("\n" + "=" * 60)
    
    # Return exit code based on issues found
    if analysis['compatibility_issues']:
        print("❌ Python 3 compatibility issues found!")
        return 1
    else:
        print("✅ All Python 3 compatibility checks passed!")
        return 0


if __name__ == "__main__":
    exit_code = print_compatibility_report()
    sys.exit(exit_code) 