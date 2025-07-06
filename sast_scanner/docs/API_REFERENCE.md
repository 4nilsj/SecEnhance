# API Reference

This document provides detailed API reference for the AI-Enabled SAST Scanner.

## Table of Contents

- [CLI Interface](#cli-interface)
- [Python API](#python-api)
- [Configuration API](#configuration-api)
- [Vulnerability Detection API](#vulnerability-detection-api)
- [AI Analysis API](#ai-analysis-api)
- [Reporting API](#reporting-api)
- [Error Handling](#error-handling)

## CLI Interface

### Command Structure

```bash
python sast_scanner_cli.py <command> <target> [options]
```

### Commands

#### `scan`
Perform security scan on files or directories.

**Syntax:**
```bash
python sast_scanner_cli.py scan <target> [options]
```

**Targets:**
- `file <path>` - Scan a single file
- `directory <path>` - Scan a directory

**Options:**
```bash
# Output options
--output <format>          # Output format: html, json, markdown, pdf
--output-file <path>       # Output file path
--template <path>          # Custom report template

# Scanning options
--patterns <patterns>      # File patterns to include (comma-separated)
--exclude <patterns>       # File patterns to exclude (comma-separated)
--max-workers <number>     # Number of worker threads (default: 4)
--max-depth <number>       # Maximum directory depth (default: unlimited)
--summary-only            # Generate summary only

# AI options
--ai-enabled              # Enable AI analysis (default: true)
--no-ai                   # Disable AI analysis
--ai-model-path <path>    # AI model directory path
--ai-confidence <float>   # AI confidence threshold (0.0-1.0)

# Filtering options
--include-vulns <list>    # Include specific vulnerability types
--exclude-vulns <list>    # Exclude specific vulnerability types
--severity <levels>       # Minimum severity level

# Configuration options
--config <path>           # Configuration file path
--debug                   # Enable debug mode
--verbose                 # Verbose output
--quiet                   # Quiet mode

# Performance options
--timeout <seconds>       # Scan timeout in seconds
--memory-limit <mb>       # Memory limit in MB
```

#### `version`
Show version information.

**Syntax:**
```bash
python sast_scanner_cli.py version
```

#### `help`
Show help information.

**Syntax:**
```bash
python sast_scanner_cli.py help [command]
```

#### `diagnose`
Run system diagnostics.

**Syntax:**
```bash
python sast_scanner_cli.py diagnose
```

## Python API

### Core Scanner

#### `SASTScanner`

Main scanner class for performing security analysis.

```python
from sast_scanner import SASTScanner

# Initialize scanner
scanner = SASTScanner(
    max_workers=4,
    ai_enabled=True,
    debug_mode=False,
    config_file=None
)

# Scan a file
results = scanner.scan_file("app.py")

# Scan a directory
results = scanner.scan_directory("./src")

# Get scan statistics
stats = scanner.get_statistics()
```

**Constructor Parameters:**
- `max_workers` (int): Number of worker threads
- `ai_enabled` (bool): Enable AI analysis
- `debug_mode` (bool): Enable debug mode
- `config_file` (str): Path to configuration file

**Methods:**
- `scan_file(file_path: str) -> ScanResult`
- `scan_directory(dir_path: str) -> ScanResult`
- `get_statistics() -> dict`
- `configure(config: dict) -> None`

#### `ScanResult`

Result object containing scan information.

```python
class ScanResult:
    vulnerabilities: List[Vulnerability]
    statistics: dict
    scan_info: dict
    ai_insights: List[dict]
    
    def to_dict(self) -> dict
    def to_json(self) -> str
    def save_report(self, format: str, path: str) -> None
```

### Vulnerability Detection

#### `VulnerabilityDetector`

Core vulnerability detection engine.

```python
from sast_scanner.detector import VulnerabilityDetector

detector = VulnerabilityDetector(
    patterns_file="patterns.json",
    ai_enabled=True
)

# Detect vulnerabilities in code
vulnerabilities = detector.detect_vulnerabilities(
    code="def test(): pass",
    language="python",
    file_path="test.py"
)
```

**Methods:**
- `detect_vulnerabilities(code: str, language: str, file_path: str) -> List[Vulnerability]`
- `add_pattern(pattern: dict) -> None`
- `remove_pattern(pattern_name: str) -> None`
- `get_patterns() -> List[dict]`

#### `Vulnerability`

Vulnerability object containing detailed information.

```python
class Vulnerability:
    file: str                    # File path
    line: int                    # Line number
    column: int                  # Column number
    vulnerability_type: str      # Vulnerability type
    severity: str                # Severity level
    description: str             # Description
    cwe: str                     # CWE identifier
    impact: str                  # Impact description
    vulnerable_code: str         # Vulnerable code snippet
    pattern_match: str           # Pattern that matched
    detection_method: str        # Detection method used
    confidence: float            # Detection confidence (0.0-1.0)
    false_positive_summary: str  # False positive explanation
    potential_fix: str           # General fix guidance
    mitigation: str              # Mitigation strategy
    ai_fix: str                  # AI-generated specific fix
    ai_fix_explanation: str      # AI fix explanation
    ai_fix_confidence: float     # AI fix confidence (0.0-1.0)
    
    def to_dict(self) -> dict
    def to_markdown(self) -> str
    def get_context(self, lines: int = 2) -> str
```

### AI Analysis

#### `AIAnalyzer`

AI-powered code analysis and fix generation.

```python
from sast_scanner.ai import AIAnalyzer

analyzer = AIAnalyzer(
    model_path="./models",
    confidence_threshold=0.8
)

# Analyze vulnerability
ai_result = analyzer.analyze_vulnerability(
    vulnerability=vulnerability,
    code_context=code_context
)

# Generate fix
fix_result = analyzer.generate_fix(
    vulnerability=vulnerability,
    language="python"
)
```

**Methods:**
- `analyze_vulnerability(vulnerability: Vulnerability, code_context: str) -> AIAnalysisResult`
- `generate_fix(vulnerability: Vulnerability, language: str) -> FixResult`
- `get_confidence_score(vulnerability: Vulnerability) -> float`
- `explain_fix(fix: str, vulnerability: Vulnerability) -> str`

#### `AIAnalysisResult`

Result of AI analysis.

```python
class AIAnalysisResult:
    confidence: float            # Analysis confidence
    explanation: str             # Analysis explanation
    context_understanding: str   # Context understanding
    risk_assessment: str         # Risk assessment
    recommendations: List[str]   # Recommendations
```

#### `FixResult`

Result of AI fix generation.

```python
class FixResult:
    fix_code: str               # Generated fix code
    confidence: float           # Fix confidence
    explanation: str            # Fix explanation
    before_code: str            # Code before fix
    after_code: str             # Code after fix
    language: str               # Programming language
    vulnerability_type: str     # Vulnerability type
```

### Reporting

#### `ReportGenerator`

Generate reports in various formats.

```python
from sast_scanner.reporting import ReportGenerator

generator = ReportGenerator()

# Generate HTML report
generator.generate_html(
    scan_result=scan_result,
    output_path="report.html",
    template_path="custom_template.html"
)

# Generate JSON report
generator.generate_json(
    scan_result=scan_result,
    output_path="report.json"
)

# Generate Markdown report
generator.generate_markdown(
    scan_result=scan_result,
    output_path="report.md"
)

# Generate PDF report
generator.generate_pdf(
    scan_result=scan_result,
    output_path="report.pdf"
)
```

**Methods:**
- `generate_html(scan_result: ScanResult, output_path: str, template_path: str = None) -> None`
- `generate_json(scan_result: ScanResult, output_path: str) -> None`
- `generate_markdown(scan_result: ScanResult, output_path: str) -> None`
- `generate_pdf(scan_result: ScanResult, output_path: str) -> None`
- `generate_summary(scan_result: ScanResult) -> str`

## Configuration API

### Configuration Management

#### `ConfigurationManager`

Manage scanner configuration.

```python
from sast_scanner.config import ConfigurationManager

config_manager = ConfigurationManager()

# Load configuration from file
config = config_manager.load_config("sast_config.json")

# Load configuration from environment
config = config_manager.load_from_env()

# Merge configurations
config = config_manager.merge_configs(config1, config2)

# Validate configuration
is_valid = config_manager.validate_config(config)
```

**Configuration Schema:**
```json
{
  "max_workers": 4,
  "default_output_format": "html",
  "exclude_patterns": ["*test*", "*spec*"],
  "include_patterns": ["*.py", "*.js"],
  "debug_mode": false,
  "ai_enabled": true,
  "ai_model_path": "./models",
  "log_level": "INFO",
  "output_directory": "./reports",
  "confidence_threshold": 0.8,
  "severity_filter": ["high", "medium"],
  "custom_patterns": {
    "pattern_name": {
      "pattern": "regex_pattern",
      "severity": "high|medium|low",
      "description": "Description"
    }
  }
}
```

### Pattern Management

#### `PatternManager`

Manage vulnerability patterns.

```python
from sast_scanner.patterns import PatternManager

pattern_manager = PatternManager()

# Add custom pattern
pattern_manager.add_pattern({
    "name": "custom_vuln",
    "pattern": "dangerous_function\\(.*\\)",
    "severity": "medium",
    "description": "Custom vulnerability pattern",
    "languages": ["python", "javascript"]
})

# Get patterns for language
patterns = pattern_manager.get_patterns("python")

# Validate pattern
is_valid = pattern_manager.validate_pattern(pattern)
```

## Error Handling

### Exception Classes

#### `SASTScannerError`
Base exception class for SAST scanner errors.

```python
class SASTScannerError(Exception):
    def __init__(self, message: str, error_code: str = None):
        self.message = message
        self.error_code = error_code
```

#### `ConfigurationError`
Configuration-related errors.

```python
class ConfigurationError(SASTScannerError):
    pass
```

#### `ScanError`
Scanning-related errors.

```python
class ScanError(SASTScannerError):
    pass
```

#### `AIError`
AI analysis-related errors.

```python
class AIError(SASTScannerError):
    pass
```

### Error Handling Examples

```python
from sast_scanner.exceptions import *

try:
    scanner = SASTScanner()
    results = scanner.scan_file("app.py")
except ConfigurationError as e:
    print(f"Configuration error: {e.message}")
except ScanError as e:
    print(f"Scan error: {e.message}")
except AIError as e:
    print(f"AI error: {e.message}")
except SASTScannerError as e:
    print(f"General error: {e.message}")
```

## Advanced Usage Examples

### Custom Vulnerability Detector

```python
from sast_scanner import SASTScanner, VulnerabilityDetector

# Create custom detector
class CustomDetector(VulnerabilityDetector):
    def detect_custom_vuln(self, code: str, file_path: str):
        # Custom detection logic
        if "dangerous_pattern" in code:
            return Vulnerability(
                file=file_path,
                line=1,
                vulnerability_type="custom_vulnerability",
                severity="high",
                description="Custom vulnerability detected"
            )
        return None

# Use custom detector
scanner = SASTScanner()
scanner.detector = CustomDetector()
results = scanner.scan_file("app.py")
```

### Custom Report Template

```python
from sast_scanner.reporting import ReportGenerator

# Custom HTML template
custom_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Custom Security Report</title>
</head>
<body>
    <h1>Security Scan Results</h1>
    <p>Scanned: {{ scan_info.target }}</p>
    <p>Vulnerabilities found: {{ scan_info.vulnerabilities_found }}</p>
    
    {% for vuln in vulnerabilities %}
    <div class="vulnerability">
        <h3>{{ vuln.vulnerability_type }}</h3>
        <p>File: {{ vuln.file }}:{{ vuln.line }}</p>
        <p>Severity: {{ vuln.severity }}</p>
        <pre>{{ vuln.vulnerable_code }}</pre>
    </div>
    {% endfor %}
</body>
</html>
"""

# Generate report with custom template
generator = ReportGenerator()
generator.generate_html(
    scan_result=results,
    output_path="custom_report.html",
    template_string=custom_template
)
```

### Batch Processing

```python
import os
from sast_scanner import SASTScanner

scanner = SASTScanner()

# Scan multiple directories
directories = ["./src", "./tests", "./docs"]
results = []

for directory in directories:
    if os.path.exists(directory):
        result = scanner.scan_directory(directory)
        results.append(result)

# Combine results
combined_results = scanner.combine_results(results)
combined_results.save_report("html", "combined_report.html")
```

### Integration with CI/CD

```python
import sys
from sast_scanner import SASTScanner

def main():
    scanner = SASTScanner()
    results = scanner.scan_directory("./src")
    
    # Check for high severity vulnerabilities
    high_severity = [v for v in results.vulnerabilities if v.severity == "high"]
    
    if high_severity:
        print(f"Found {len(high_severity)} high severity vulnerabilities")
        results.save_report("json", "sast_results.json")
        sys.exit(1)
    else:
        print("No high severity vulnerabilities found")
        sys.exit(0)

if __name__ == "__main__":
    main()
```

## Performance Optimization

### Memory Management

```python
from sast_scanner import SASTScanner

# Configure memory limits
scanner = SASTScanner(
    max_workers=2,  # Reduce workers for memory-constrained systems
    memory_limit=1024  # 1GB memory limit
)

# Use streaming for large files
scanner.enable_streaming = True
```

### Parallel Processing

```python
import multiprocessing
from sast_scanner import SASTScanner

# Use optimal worker count
optimal_workers = min(multiprocessing.cpu_count(), 8)
scanner = SASTScanner(max_workers=optimal_workers)
```

### Caching

```python
from sast_scanner import SASTScanner

# Enable caching for repeated scans
scanner = SASTScanner()
scanner.enable_caching = True
scanner.cache_directory = "./cache"

# Clear cache when needed
scanner.clear_cache()
```

## Next Steps

After reviewing this API reference:

1. **Try the [Usage Guide](USAGE.md)** for practical examples
2. **Check the [Vulnerability Database](VULNERABILITIES.md)** for supported patterns
3. **Explore the source code** for advanced customization
4. **Join the community** for API support and updates 