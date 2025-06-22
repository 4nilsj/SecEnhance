#!/usr/bin/env python3
"""
Setup script for API Security Scanner
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="api-security-scanner",
    version="1.0.0",
    author="API Security Team",
    author_email="security@example.com",
    description="A comprehensive API security testing tool",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/api-security-scanner",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "api-security-scanner=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json", "*.html", "*.css", "*.js"],
    },
    keywords="api security testing owasp vulnerability scanner",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/api-security-scanner/issues",
        "Source": "https://github.com/yourusername/api-security-scanner",
        "Documentation": "https://github.com/yourusername/api-security-scanner/docs",
    },
) 