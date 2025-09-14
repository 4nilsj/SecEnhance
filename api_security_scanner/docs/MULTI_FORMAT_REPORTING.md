# Multi-Format Report Generation

The API Security Scanner supports generating comprehensive security reports in multiple formats to meet different organizational needs and use cases.

## Overview

By default, the scanner generates HTML and JSON reports for every scan. Additional formats (PDF, Excel, XML) are generated only when specifically requested using command-line options.

## Supported Formats

### 📄 HTML Reports (Default)
- **Format**: Interactive web-based reports
- **Best For**: Detailed analysis, sharing with teams, web-based viewing
- **Features**: 
  - Interactive charts and visualizations
  - Detailed vulnerability information
  - Responsive design for different screen sizes
  - Clickable links and navigation
  - Professional styling with CSS

### 📊 JSON Reports (Default)
- **Format**: Structured data format
- **Best For**: API integration, automated processing, data analysis
- **Features**:
  - Complete scan metadata
  - All vulnerability details
  - Performance statistics
  - Machine-readable format
  - Easy to parse and process

### 📋 PDF Reports (On-Demand)
- **Format**: Professional PDF documents
- **Best For**: Executive presentations, documentation, formal reports
- **Features**:
  - Professional layout with tables
  - Risk summaries and statistics
  - Vulnerability details (first 20 for readability)
  - Performance metrics
  - Print-ready format

### 📈 Excel Reports (On-Demand)
- **Format**: Multi-sheet Excel workbooks
- **Best For**: Data analysis, tracking, detailed review
- **Features**:
  - Multiple sheets: Summary, Vulnerabilities, Performance
  - Sortable and filterable data
  - Full vulnerability details with descriptions
  - Risk level categorization
  - Data analysis capabilities

### 🔧 XML Reports (On-Demand)
- **Format**: Machine-readable XML
- **Best For**: Integration with other tools, CI/CD pipelines
- **Features**:
  - Structured data format
  - Complete scan metadata
  - All vulnerability findings
  - Tool integration friendly
  - Automated processing support

## Usage Examples

### Basic Report Generation
```bash
# Generate default HTML and JSON reports
python main.py scan -f collection.json

# Generate additional PDF report
python main.py scan -f collection.json --export-pdf security-report.pdf

# Generate Excel report for analysis
python main.py scan -f api-spec.yaml --export-excel detailed-analysis.xlsx
```

### Multiple Format Generation
```bash
# Generate all report formats
python main.py scan -f collection.json \
  --export-pdf executive-summary.pdf \
  --export-excel security-data.xlsx \
  --export-xml ci-results.xml

# Generate specific formats for different audiences
python main.py scan -f har-export.har \
  --export-pdf management-report.pdf \
  --export-excel technical-analysis.xlsx
```

### CI/CD Integration
```bash
# Generate XML for automated processing
python main.py scan -f postman-collection.json \
  --export-xml security-findings.xml

# Generate JSON for API integration
python main.py scan -f api-spec.yaml \
  --export-json scan-results.json
```

### Docker Usage
```bash
# Generate reports in Docker container
docker run --rm -v $(pwd):/workspace api-security-scanner \
  scan -f /workspace/collection.json \
  --export-pdf /workspace/security-report.pdf \
  --export-excel /workspace/analysis.xlsx
```

## Report Content Details

### HTML Reports
- **Scan Information**: ID, target, duration, status
- **Risk Summary**: Count by severity level
- **Vulnerability Details**: Full descriptions, solutions, evidence
- **Performance Statistics**: Timing for each scan phase
- **Interactive Features**: Expandable sections, filtering

### PDF Reports
- **Executive Summary**: High-level overview
- **Scan Metadata**: Basic scan information
- **Risk Breakdown**: Counts by severity
- **Vulnerability List**: Key findings (limited to 20)
- **Performance Metrics**: Scan timing data

### Excel Reports
- **Summary Sheet**: Overview and risk counts
- **Vulnerabilities Sheet**: Complete vulnerability data
  - Risk Level, Name, URL, Method
  - Plugin Source, Description, Solution
- **Performance Sheet**: Detailed timing information

### XML Reports
- **Scan Information**: Complete metadata
- **Risk Summary**: Counts by level
- **Vulnerabilities**: All findings with full details
- **Performance Statistics**: Timing data
- **Structured Format**: Easy to parse programmatically

### JSON Reports
- **scan_metadata**: Complete scan information
- **vulnerabilities**: Array of all findings
- **performance_stats**: Timing data
- **risk_counts**: Summary statistics
- **generated_at**: Timestamp
- **report_version**: Format version

## Dependencies

### Required Dependencies
- **HTML/JSON**: Built-in (no additional dependencies)
- **PDF**: `reportlab` package
- **Excel**: `openpyxl` package
- **XML**: Built-in (no additional dependencies)

### Installation
```bash
# Install all report dependencies
pip install reportlab openpyxl

# Or install individually
pip install reportlab  # For PDF reports
pip install openpyxl   # For Excel reports
```

### Docker Support
All dependencies are included in the Docker image, so no additional installation is required when using containers.

## Best Practices

### Report Selection
- **HTML**: Use for team sharing and detailed analysis
- **PDF**: Use for executive presentations and formal documentation
- **Excel**: Use for data analysis and vulnerability tracking
- **XML**: Use for tool integration and automated processing
- **JSON**: Use for API integration and programmatic access

### File Naming
```bash
# Use descriptive names with timestamps
python main.py scan -f collection.json \
  --export-pdf "security-scan-$(date +%Y%m%d).pdf" \
  --export-excel "vulnerability-analysis-$(date +%Y%m%d).xlsx"

# Use environment-specific names
python main.py scan -f production-api.json \
  --export-pdf "production-security-report.pdf" \
  --export-xml "production-findings.xml"
```

### Storage and Sharing
- Store reports in version control for tracking
- Use secure file sharing for sensitive reports
- Implement retention policies for report storage
- Consider encryption for sensitive data

## Integration Examples

### CI/CD Pipeline Integration
```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    python main.py scan -f api-collection.json \
      --export-xml security-results.xml \
      --export-json scan-data.json

- name: Process Results
  run: |
    # Process XML/JSON results
    python process-security-results.py security-results.xml
```

### Automated Reporting
```bash
#!/bin/bash
# Automated security reporting script

SCAN_DATE=$(date +%Y%m%d)
REPORT_DIR="reports/$SCAN_DATE"

mkdir -p "$REPORT_DIR"

python main.py scan -f api-collection.json \
  --export-pdf "$REPORT_DIR/security-report.pdf" \
  --export-excel "$REPORT_DIR/vulnerability-data.xlsx" \
  --export-xml "$REPORT_DIR/findings.xml"

# Send reports via email or upload to storage
```

### Data Analysis
```python
# Python script to analyze Excel reports
import pandas as pd

# Read vulnerability data from Excel
df = pd.read_excel('vulnerability-data.xlsx', sheet_name='Vulnerabilities')

# Analyze by risk level
risk_analysis = df.groupby('Risk Level').size()
print("Risk Level Distribution:")
print(risk_analysis)

# Filter high-risk vulnerabilities
high_risk = df[df['Risk Level'] == 'High']
print(f"\nHigh Risk Vulnerabilities: {len(high_risk)}")
```

## Troubleshooting

### Common Issues

**PDF Generation Fails**
```bash
# Check ReportLab installation
python -c "import reportlab; print('ReportLab available')"

# Install if missing
pip install reportlab
```

**Excel Generation Fails**
```bash
# Check OpenPyXL installation
python -c "import openpyxl; print('OpenPyXL available')"

# Install if missing
pip install openpyxl
```

**Large Report Files**
- PDF reports are limited to first 20 vulnerabilities for readability
- Excel reports include all vulnerabilities but may be large
- Consider filtering vulnerabilities before report generation

**Permission Issues**
```bash
# Ensure write permissions for report directory
chmod 755 reports/
chown $USER:$USER reports/
```

### Performance Considerations
- PDF generation is fastest for small vulnerability sets
- Excel generation may be slower for large datasets
- XML and JSON generation is typically fastest
- Consider report format based on data size

## Future Enhancements

- **Custom Templates**: User-defined report templates
- **Report Scheduling**: Automated report generation
- **Report Comparison**: Compare scans over time
- **Advanced Filtering**: Filter vulnerabilities before report generation
- **Report Encryption**: Secure report storage and transmission
- **Cloud Integration**: Direct upload to cloud storage services

---

For more information, see the main [README.md](../README.md) or contact the development team.
