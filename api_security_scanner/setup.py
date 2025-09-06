#!/usr/bin/env python3
"""
Setup script for API Security Scanner.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README file
readme_file = Path(__file__).parent / 'README.md'
long_description = readme_file.read_text(encoding='utf-8') if readme_file.exists() else ''

# Read requirements
requirements_file = Path(__file__).parent / 'requirements.txt'
requirements = []
if requirements_file.exists():
    with open(requirements_file, 'r', encoding='utf-8') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='api-security-scanner',
    version='1.0.0',
    description='A comprehensive CLI tool for automated API security scanning',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='API Security Scanner Team',
    author_email='security@example.com',
    url='https://github.com/example/api-security-scanner',
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'apiscanner=main:cli',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: Software Development :: Testing',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    keywords='security api testing zap owasp vulnerability scanner',
    project_urls={
        'Bug Reports': 'https://github.com/example/api-security-scanner/issues',
        'Source': 'https://github.com/example/api-security-scanner',
        'Documentation': 'https://github.com/example/api-security-scanner/wiki',
    },
)
