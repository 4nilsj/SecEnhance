#!/usr/bin/env python3
"""
Setup script for API Security Scanner.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read requirements
requirements = []
with open('requirements.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#'):
            requirements.append(line)

setup(
    name="api-security-scanner",
    version="1.0.0",
    author="API Security Scanner Team",
    author_email="security@example.com",
    description="A comprehensive command-line tool for automated API security scanning",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/api-security-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.10.0",
            "pytest-timeout>=2.1.0",
            "pytest-xdist>=3.3.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "api-security-scanner=api_security_scanner.cli.main:cli",
            "api-scanner=api_security_scanner.cli.main:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "api_security_scanner": [
            "templates/*.html",
            "templates/*.json",
            "examples/*.json",
            "examples/*.yaml",
        ],
    },
    keywords=[
        "security",
        "api",
        "scanning",
        "owasp",
        "zap",
        "vulnerability",
        "testing",
        "automation",
    ],
    project_urls={
        "Bug Reports": "https://github.com/example/api-security-scanner/issues",
        "Source": "https://github.com/example/api-security-scanner",
        "Documentation": "https://api-security-scanner.readthedocs.io/",
    },
)