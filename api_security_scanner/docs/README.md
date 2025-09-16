# API Security Scanner Documentation

Welcome to the comprehensive documentation for the API Security Scanner. This documentation covers all aspects of the tool, from basic usage to advanced AI-powered detection capabilities.

## 📚 Documentation Index

### 🤖 AI-Powered Detection

- **[AI Detection Guide](AI_DETECTION_GUIDE.md)** - Complete user guide for AI-powered detection features
- **[AI Detection Quick Reference](AI_DETECTION_QUICK_REFERENCE.md)** - Quick reference for common AI detection tasks
- **[AI Detection Architecture](AI_DETECTION_ARCHITECTURE.md)** - Technical architecture and implementation details
- **[AI Detection API Reference](AI_DETECTION_API_REFERENCE.md)** - Complete API reference for developers

### 🚀 Getting Started

- **[Quick Reference](QUICK_REFERENCE.md)** - Quick start guide and common commands
- **[Environment Configuration](ENVIRONMENT_CONFIGURATION.md)** - Configuration management and environment variables
- **[Docker Usage Guide](DOCKER_USAGE_GUIDE.md)** - Complete guide for containerized deployment
- **[macOS Setup Guide](MACOS_SETUP_GUIDE.md)** - Setup guide for macOS users

### 🎯 Scan Modes

- **[Scan Modes Guide](SCAN_MODES_GUIDE.md)** - Complete guide to all available scan modes (Safe, Attack, Spidering, etc.)

### 🔧 Advanced Features

- **[Plugin Selection](PLUGIN_SELECTION.md)** - Guide to selecting and configuring security plugins
- **[Custom Plugin Development](CUSTOM_PLUGIN_DEVELOPMENT.md)** - Guide for developing custom security plugins
- **[OWASP API Top 10 Plugins](OWASP_API_TOP_10_PLUGINS.md)** - Comprehensive guide to OWASP API Top 10 security plugins
- **[HAR File Support](HAR_FILE_SUPPORT.md)** - Support for HAR (HTTP Archive) files from various tools
- **[Multi-Format Reporting](MULTI_FORMAT_REPORTING.md)** - Comprehensive reporting capabilities

### 🧪 Testing & Troubleshooting

- **[Testing Guide](TESTING_GUIDE.md)** - Testing the scanner and running test suites
- **[Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md)** - Common issues and solutions

## 🎯 Quick Start

### Basic Usage

```bash
# Scan a Postman collection (safe mode - default)
python main.py scan -f collection.json --scan-mode safe

# Quick development scan
python main.py scan -f collection.json --scan-mode quick

# Aggressive penetration testing
python main.py scan -f collection.json --scan-mode attack

# List all available scan modes
python main.py scan-modes

# Scan with AI detection
python main.py scan -f collection.json --ai-detection

# Scan with specific plugins
python main.py scan -f collection.json --plugins AISecurityChecker,JWTSecurityChecker
```

### Docker Usage

```bash
# Quick Docker setup
./setup-container.sh
./build-docker.sh

# Run scan in container
docker-compose run --rm scanner scan -f /workspace/collection.json
```

## 🔍 Key Features

### 🎯 Multiple Scan Modes
- **8 Predefined Modes**: Safe, Attack, Spidering, Comprehensive, Stealth, Aggressive, Quick, API-Focused
- **Optimized Configurations**: Each mode tailored for specific testing scenarios
- **Risk-Based Selection**: Choose appropriate mode based on environment and requirements
- **Flexible Override**: Customize any mode with command-line parameters

### 🤖 AI-Powered Detection
- **Anomaly Detection**: Identifies unusual patterns in API requests
- **Vulnerability Classification**: Automatically classifies attack types
- **Risk Scoring**: Calculates comprehensive risk scores
- **Intelligent Fuzzing**: Suggests targeted fuzzing approaches
- **Learning**: Improves detection accuracy over time

### 🔌 Plugin System
- **Extensible Architecture**: Easy to add custom security checks
- **Multiple Plugins**: JWT, GraphQL, Security Headers, and more
- **Configurable**: Enable/disable plugins as needed
- **Standardized Interface**: Consistent plugin development

### 📊 Comprehensive Reporting
- **Multiple Formats**: HTML, PDF, Excel, XML, JSON
- **Detailed Analysis**: Vulnerability details and remediation
- **Performance Metrics**: Scan timing and statistics
- **Customizable Templates**: Jinja2-based report templates

### 🐳 Container Support
- **Docker/Podman**: Full containerized deployment
- **No Dependencies**: No need to install Python or ZAP
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Easy Setup**: One-command setup and execution

## 📖 Documentation Structure

### User Documentation
- **Guides**: Step-by-step instructions for common tasks
- **Quick References**: Fast lookup for commands and options
- **Examples**: Real-world usage examples and use cases

### Developer Documentation
- **Architecture**: Technical implementation details
- **API Reference**: Complete API documentation
- **Plugin Development**: Guide for extending the scanner
- **Testing**: Testing strategies and test suites

### Operational Documentation
- **Configuration**: Environment and configuration management
- **Deployment**: Docker, local installation, and setup
- **Troubleshooting**: Common issues and solutions
- **Performance**: Optimization and best practices

## 🚀 Getting Help

### Documentation
1. Start with the [Quick Reference](QUICK_REFERENCE.md) for basic usage
2. Check the [AI Detection Guide](AI_DETECTION_GUIDE.md) for AI features
3. Review the [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md) for issues

### Support
- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive guides and references
- **Examples**: Demo scripts and usage examples
- **Tests**: Test suites for verification

### Community
- **Contributions**: Welcome contributions and improvements
- **Plugins**: Share custom plugins with the community
- **Feedback**: Help improve the tool with your feedback

## 📋 Documentation Standards

### Writing Guidelines
- **Clear and Concise**: Easy to understand and follow
- **Comprehensive**: Cover all aspects of the feature
- **Examples**: Include practical examples and use cases
- **Up-to-Date**: Keep documentation current with code changes

### Structure
- **Consistent Format**: Standardized structure across all docs
- **Cross-References**: Link related documentation
- **Index**: Easy navigation and discovery
- **Search**: Findable content with clear headings

## 🔄 Keeping Documentation Current

### Update Process
1. **Code Changes**: Update documentation when code changes
2. **Feature Additions**: Document new features and capabilities
3. **Bug Fixes**: Update troubleshooting guides
4. **User Feedback**: Incorporate user suggestions and improvements

### Version Control
- **Git Integration**: Documentation in version control
- **Change Tracking**: Track documentation changes
- **Review Process**: Review documentation changes
- **Release Notes**: Document changes in releases

## 📊 Documentation Metrics

### Coverage
- **Features**: All features documented
- **APIs**: Complete API reference
- **Examples**: Comprehensive examples
- **Troubleshooting**: Common issues covered

### Quality
- **Accuracy**: Documentation matches implementation
- **Clarity**: Clear and understandable
- **Completeness**: All necessary information included
- **Usability**: Easy to find and use

## 🎯 Future Documentation

### Planned Additions
- **Video Tutorials**: Visual guides for complex features
- **Interactive Examples**: Hands-on learning experiences
- **API Documentation**: Auto-generated from code
- **Performance Guides**: Optimization and tuning guides

### Community Contributions
- **User Guides**: Community-written guides
- **Best Practices**: Shared experiences and tips
- **Case Studies**: Real-world usage examples
- **Plugin Documentation**: Community plugin guides

---

**Last Updated**: December 2024  
**Version**: 1.0.0  
**Maintainer**: API Security Scanner Team
