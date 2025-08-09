#!/usr/bin/env python3
"""
Setup script for SAST Scanner
AI-enabled Static Application Security Testing tool.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    with open(readme_path, "r", encoding="utf-8") as f:
        long_description = f.read()

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    with open(requirements_path, "r", encoding="utf-8") as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="sast-scanner",
    version="1.0.0",
    author="SAST Scanner Team",
    author_email="sast-scanner@example.com",
    description="AI-enabled Static Application Security Testing tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/sast-scanner",
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
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "pytest-cov>=2.10.0",
            "black>=21.0.0",
            "flake8>=3.8.0",
            "mypy>=0.800",
            "pre-commit>=2.15.0",
        ],
        "pdf": [
            "weasyprint>=59.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "sast-scanner=sast_scanner_cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["templates/*.html", "*.md", "*.txt"],
    },
    keywords=[
        "security",
        "sast",
        "static-analysis",
        "vulnerability-detection",
        "ai",
        "machine-learning",
        "code-analysis",
        "security-testing",
    ],
    project_urls={
        "Bug Reports": "https://github.com/your-repo/sast-scanner/issues",
        "Source": "https://github.com/your-repo/sast-scanner",
        "Documentation": "https://github.com/your-repo/sast-scanner/docs",
    },
) 