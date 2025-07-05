# Local Vulnerability Database Guide

## Overview

The Local Vulnerability Database is a SQLite-based system for storing and querying NVD (National Vulnerability Database) vulnerability data locally. This enables **Phase 1, Step 2: Package Vulnerability Matching** for offline container security scanning.

## Features

### Core Capabilities
- **Local SQLite Database**: Fast, reliable local storage for vulnerability data
- **NVD Data Integration**: Automatic download and parsing of NVD JSON feeds
- **Package Vulnerability Matching**: Search vulnerabilities by package name, version, and manager
- **Scan Results Storage**: Persistent storage of container scan results
- **Comprehensive Statistics**: Detailed vulnerability and scan analytics
- **Offline Operation**: Full functionality without internet connectivity after initial setup

### Database Schema

#### Tables
1. **vulnerabilities**: Core CVE information
2. **affected_packages**: Package-vulnerability relationships
3. **packages**: Package information storage
4. **scan_results**: Container scan results
5. **scan_vulnerabilities**: Scan-vulnerability relationships
6. **db_metadata**: Database metadata and timestamps

#### Key Relationships
- Vulnerabilities ↔ Affected Packages (One-to-Many)
- Scan Results ↔ Scan Vulnerabilities (One-to-Many)
- Packages ↔ Affected Packages (Many-to-Many)

## Installation

### Prerequisites
```bash
# Python dependencies
pip install sqlite3 requests gzip

# Optional: NVD API key for higher rate limits
export NVD_API_KEY="your_api_key_here"
```

### Database Location
```
container_tool/
├── data/
│   └── vulnerability.db    # SQLite database file
├── src/
│   └── database/
│       └── local_vulnerability_db.py
└── scripts/
    └── init_database.py
```

## Usage

### Database Initialization

#### Command Line
```bash
# Initialize database with current year and previous 2 years
python scripts/init_database.py init

# Initialize with specific years
python scripts/init_database.py init --years 2023 2024

# Force update existing data
python scripts/init_database.py init --force

# With debug output
python scripts/init_database.py init --debug
```

#### Programmatic
```python
from src.database.local_vulnerability_db import LocalVulnerabilityDB

# Initialize database
db = LocalVulnerabilityDB(debug=True)

# Download NVD data for specific year
success = db.download_nvd_data(2024, force_update=False)

# Close database
db.close()
```

### Database Updates

#### Command Line
```bash
# Update current year data
python scripts/init_database.py update

# Update specific years
python scripts/init_database.py update --years 2023 2024

# With debug output
python scripts/init_database.py update --debug
```

#### Programmatic
```python
# Update existing database
db = LocalVulnerabilityDB(debug=True)

# Force update current year
success = db.download_nvd_data(2024, force_update=True)

db.close()
```

### Vulnerability Search

#### Basic Search
```python
from src.database.local_vulnerability_db import LocalVulnerabilityDB

db = LocalVulnerabilityDB()

# Search by package name
vulnerabilities = db.search_vulnerabilities("openssl")

# Search by package name and version
vulnerabilities = db.search_vulnerabilities("openssl", "1.1.1n-0+deb11u4")

# Search by package name, version, and manager
vulnerabilities = db.search_vulnerabilities("openssl", "1.1.1n-0+deb11u4", "dpkg")

db.close()
```

#### Search Results
```python
# Example vulnerability result
{
    'cve_id': 'CVE-2023-1234',
    'description': 'OpenSSL vulnerability in version 1.1.1...',
    'severity': 'HIGH',
    'cvss_score': 8.1,
    'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'published_date': '2023-01-15T10:30:00Z',
    'last_modified_date': '2023-01-20T14:45:00Z',
    'status': 'PUBLISHED',
    'package_name': 'openssl',
    'package_version': '1.1.1n-0+deb11u4',
    'package_manager': 'dpkg'
}
```

### Scan Results Storage

#### Save Scan Results
```python
# Create scan data
scan_id = "scan_20240115_143022"
image_name = "debian:bullseye-slim"
scan_data = {
    "total_packages": 156,
    "vulnerable_packages": 12,
    "critical_vulnerabilities": 2,
    "high_vulnerabilities": 5,
    "medium_vulnerabilities": 3,
    "low_vulnerabilities": 2,
    "scan_duration": 45.23,
    "vulnerabilities": [
        {
            "cve_id": "CVE-2023-1234",
            "package_name": "openssl",
            "package_version": "1.1.1n-0+deb11u4",
            "severity": "HIGH",
            "cvss_score": 8.1
        }
    ]
}

# Save to database
db = LocalVulnerabilityDB()
success = db.save_scan_results(scan_id, image_name, scan_data)
db.close()
```

#### Retrieve Scan History
```python
db = LocalVulnerabilityDB()

# Get recent scans
scan_history = db.get_scan_history(limit=10)

for scan in scan_history:
    print(f"Image: {scan['image_name']}")
    print(f"Date: {scan['scan_date']}")
    print(f"Vulnerabilities: {scan['vulnerable_packages']}/{scan['total_packages']}")

db.close()
```

### Database Statistics

#### Get Statistics
```python
db = LocalVulnerabilityDB()
stats = db.get_vulnerability_stats()

print(f"Total vulnerabilities: {stats['total_vulnerabilities']}")
print(f"Total affected packages: {stats['total_affected_packages']}")
print(f"Recent vulnerabilities (30 days): {stats['recent_vulnerabilities']}")

# Severity breakdown
for severity, count in stats['severity_breakdown'].items():
    print(f"{severity}: {count}")

# Package managers
for manager, count in stats['package_managers'].items():
    print(f"{manager}: {count}")

db.close()
```

## NVD Data Integration

### Data Sources
- **NVD JSON Feeds**: Primary source for vulnerability data
- **NVD API**: Alternative source for specific queries
- **Local Caching**: Automatic caching for offline operation

### Data Processing
1. **Download**: Fetch gzipped JSON feeds from NVD
2. **Parse**: Extract CVE information and affected packages
3. **Normalize**: Standardize package names and versions
4. **Store**: Insert into SQLite database with proper indexing

### Supported Package Managers
- **dpkg**: Debian/Ubuntu packages
- **rpm**: Red Hat/CentOS packages
- **apk**: Alpine packages
- **pip**: Python packages
- **npm**: Node.js packages
- **gem**: Ruby packages
- **composer**: PHP packages

## Performance Optimization

### Database Indexes
```sql
-- Vulnerability indexes
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_cvss_score ON vulnerabilities(cvss_score);
CREATE INDEX idx_vulnerabilities_published_date ON vulnerabilities(published_date);

-- Package indexes
CREATE INDEX idx_affected_packages_name ON affected_packages(package_name);
CREATE INDEX idx_affected_packages_version ON affected_packages(package_version);
CREATE INDEX idx_affected_packages_manager ON affected_packages(package_manager);
```

### Query Optimization
- **Indexed Searches**: Fast package name and version lookups
- **Batch Operations**: Efficient bulk vulnerability matching
- **Connection Pooling**: Reuse database connections
- **Memory Management**: Stream processing for large datasets

### Storage Optimization
- **Compression**: Gzipped NVD feeds reduce download size
- **Deduplication**: Avoid duplicate vulnerability entries
- **Cleanup**: Automatic cleanup of old scan results
- **Archiving**: Archive old vulnerability data

## Integration with Container Scanner

### Phase 1, Step 2 Integration
```python
from src.database.local_vulnerability_db import LocalVulnerabilityDB
from src.analyzers.debian_package_analyzer import DebianPackageAnalyzer

# Initialize components
db = LocalVulnerabilityDB()
debian_analyzer = DebianPackageAnalyzer()

# Extract packages from image (Phase 1, Step 1)
debian_results = debian_analyzer.extract_debian_image("debian:bullseye-slim")

# Match packages against vulnerability database (Phase 1, Step 2)
vulnerabilities = []
for layer in debian_results['layers']:
    for package in layer['debian_packages']:
        package_vulns = db.search_vulnerabilities(
            package['name'],
            package['version'],
            'dpkg'
        )
        vulnerabilities.extend(package_vulns)

# Generate vulnerability report
vulnerability_report = {
    'total_packages': len(debian_results['debian_info']['packages']),
    'vulnerable_packages': len(set(v['package_name'] for v in vulnerabilities)),
    'vulnerabilities': vulnerabilities
}

db.close()
```

### Automated Vulnerability Matching
```python
def match_packages_vulnerabilities(packages, db):
    """Match packages against vulnerability database."""
    results = {
        'total_packages': len(packages),
        'vulnerable_packages': 0,
        'vulnerabilities': [],
        'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    }
    
    for package in packages:
        vulns = db.search_vulnerabilities(
            package['name'],
            package['version'],
            package.get('manager', 'dpkg')
        )
        
        if vulns:
            results['vulnerable_packages'] += 1
            results['vulnerabilities'].extend(vulns)
            
            for vuln in vulns:
                severity = vuln['severity']
                results['severity_counts'][severity] += 1
    
    return results
```

## Monitoring and Maintenance

### Database Health Checks
```python
def check_database_health(db):
    """Check database health and performance."""
    stats = db.get_vulnerability_stats()
    
    # Check data freshness
    recent_vulns = stats.get('recent_vulnerabilities', 0)
    if recent_vulns == 0:
        print("⚠️  No recent vulnerabilities - database may be outdated")
    
    # Check data volume
    total_vulns = stats.get('total_vulnerabilities', 0)
    if total_vulns < 1000:
        print("⚠️  Low vulnerability count - database may be incomplete")
    
    # Check scan history
    scan_history = db.get_scan_history(limit=1)
    if not scan_history:
        print("ℹ️  No scan history found")
    
    return stats
```

### Automated Updates
```python
import schedule
import time

def update_database_daily():
    """Daily database update job."""
    db = LocalVulnerabilityDB()
    current_year = datetime.now().year
    success = db.download_nvd_data(current_year, force_update=False)
    db.close()
    return success

# Schedule daily updates
schedule.every().day.at("02:00").do(update_database_daily)

# Run scheduler
while True:
    schedule.run_pending()
    time.sleep(3600)  # Check every hour
```

### Backup and Recovery
```python
import shutil
import sqlite3

def backup_database(db_path, backup_path):
    """Create database backup."""
    shutil.copy2(db_path, backup_path)
    print(f"Database backed up to: {backup_path}")

def restore_database(backup_path, db_path):
    """Restore database from backup."""
    shutil.copy2(backup_path, db_path)
    print(f"Database restored from: {backup_path}")

def verify_database_integrity(db_path):
    """Verify database integrity."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check database integrity
    cursor.execute("PRAGMA integrity_check")
    result = cursor.fetchone()
    
    conn.close()
    return result[0] == "ok"
```

## Troubleshooting

### Common Issues

#### Database Connection Errors
```python
# Error: database is locked
# Solution: Ensure proper connection closing
try:
    db = LocalVulnerabilityDB()
    # ... operations ...
finally:
    db.close()

# Error: no such table
# Solution: Reinitialize database
db = LocalVulnerabilityDB()
db._init_database()
```

#### NVD Download Issues
```python
# Error: network timeout
# Solution: Increase timeout and retry
import requests
requests.adapters.DEFAULT_RETRIES = 5

# Error: rate limiting
# Solution: Use NVD API key
export NVD_API_KEY="your_api_key_here"
```

#### Performance Issues
```python
# Slow queries
# Solution: Check indexes
db.cursor.execute("PRAGMA index_list(vulnerabilities)")

# Large database size
# Solution: Clean up old data
db.cursor.execute("DELETE FROM scan_results WHERE scan_date < date('now', '-90 days')")
```

### Debug Mode
```python
# Enable debug logging
db = LocalVulnerabilityDB(debug=True)

# Check debug output
tail -f container_security_debug.log
```

### Database Inspection
```python
# Interactive database inspection
import sqlite3

conn = sqlite3.connect('data/vulnerability.db')
cursor = conn.cursor()

# List tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()

# Check table sizes
for table in tables:
    cursor.execute(f"SELECT COUNT(*) FROM {table[0]}")
    count = cursor.fetchone()[0]
    print(f"{table[0]}: {count} rows")

conn.close()
```

## Best Practices

### Data Management
- **Regular Updates**: Update NVD data weekly
- **Backup Strategy**: Daily backups of database
- **Cleanup Policy**: Archive old scan results
- **Monitoring**: Monitor database size and performance

### Security Considerations
- **Access Control**: Restrict database file permissions
- **Encryption**: Consider encrypting sensitive scan data
- **Audit Logging**: Log database access and modifications
- **Input Validation**: Validate all database inputs

### Performance Optimization
- **Indexing**: Maintain proper database indexes
- **Query Optimization**: Use efficient queries
- **Connection Management**: Properly close database connections
- **Batch Operations**: Use batch operations for large datasets

## API Reference

### LocalVulnerabilityDB Class

#### Constructor
```python
LocalVulnerabilityDB(db_path=None, debug=False)
```

#### Methods
- `download_nvd_data(year, force_update=False)`: Download NVD data
- `search_vulnerabilities(package_name, version=None, manager=None)`: Search vulnerabilities
- `save_scan_results(scan_id, image_name, scan_data)`: Save scan results
- `get_scan_history(limit=10)`: Get scan history
- `get_vulnerability_stats()`: Get database statistics
- `close()`: Close database connection

#### Context Manager
```python
with LocalVulnerabilityDB() as db:
    # Database operations
    pass  # Automatic cleanup
```

## Examples

### Complete Workflow Example
```python
#!/usr/bin/env python3
"""Complete vulnerability matching workflow."""

from src.database.local_vulnerability_db import LocalVulnerabilityDB
from src.analyzers.debian_package_analyzer import DebianPackageAnalyzer
import json

def main():
    # Initialize components
    db = LocalVulnerabilityDB(debug=True)
    debian_analyzer = DebianPackageAnalyzer(debug=True)
    
    # Phase 1, Step 1: Extract packages
    print("🔍 Phase 1, Step 1: Extracting packages...")
    debian_results = debian_analyzer.extract_debian_image("debian:bullseye-slim")
    
    # Phase 1, Step 2: Match vulnerabilities
    print("🔍 Phase 1, Step 2: Matching vulnerabilities...")
    all_vulnerabilities = []
    
    for layer in debian_results['layers']:
        for package in layer['debian_packages']:
            vulns = db.search_vulnerabilities(
                package['name'],
                package['version'],
                'dpkg'
            )
            all_vulnerabilities.extend(vulns)
    
    # Generate report
    report = {
        'image_name': 'debian:bullseye-slim',
        'total_packages': debian_results['debian_info']['package_count'],
        'vulnerable_packages': len(set(v['package_name'] for v in all_vulnerabilities)),
        'total_vulnerabilities': len(all_vulnerabilities),
        'vulnerabilities': all_vulnerabilities
    }
    
    # Save results
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    db.save_scan_results(scan_id, report['image_name'], report)
    
    # Print summary
    print(f"📊 Scan Summary:")
    print(f"   - Total packages: {report['total_packages']}")
    print(f"   - Vulnerable packages: {report['vulnerable_packages']}")
    print(f"   - Total vulnerabilities: {report['total_vulnerabilities']}")
    
    db.close()

if __name__ == "__main__":
    main()
```

This local vulnerability database provides the foundation for **Phase 1, Step 2: Package Vulnerability Matching** in the container security scanner, enabling comprehensive offline vulnerability analysis of container images. 