#!/usr/bin/env python3
"""
Setup script for Threat Modeling Tool
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements
requirements = []
with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="threat-modeler",
    version="1.0.0",
    author="SecEnhance Team",
    author_email="security@secenhance.com",
    description="Comprehensive threat modeling tool for application security analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/secenhance/threat-modeler",
    packages=find_packages(),
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
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
        "pdf": [
            "weasyprint>=59.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "threat-modeler=src.threat_modeler:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt", "*.yaml", "*.json"],
    },
    keywords="security threat-modeling stride pasta dread application-security",
    project_urls={
        "Bug Reports": "https://github.com/secenhance/threat-modeler/issues",
        "Source": "https://github.com/secenhance/threat-modeler",
        "Documentation": "https://github.com/secenhance/threat-modeler/blob/main/README.md",
    },
) 