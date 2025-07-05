# Mobile Security Testing Tool

A comprehensive automated mobile client-side security testing tool similar to Drozer and MobSF, designed to perform security analysis of Android and iOS applications.

## 🚀 Features

### Core Security Testing
- **Static Analysis**: APK/IPA file analysis, manifest inspection, permission analysis (100+ security checks)
- **Dynamic Analysis**: Runtime behavior monitoring, network traffic analysis, device analysis
- **Code Analysis**: Source code review, vulnerability scanning, pattern detection
- **Network Analysis**: SSL/TLS testing, certificate pinning, API endpoint analysis
- **Storage Analysis**: Local storage analysis, sensitive data detection, cache analysis
- **Configuration Analysis**: Security settings, encryption implementation

### Advanced Capabilities
- **Automated Exploitation**: Proof-of-concept exploit generation
- **Reverse Engineering**: APK/IPA decompilation and analysis
- **Network Security**: SSL/TLS testing, certificate pinning bypass
- **Input Validation**: Fuzzing, injection testing
- **Session Management**: Token analysis, session hijacking tests
- **Cryptography**: Encryption algorithm analysis, key management

## 📋 Requirements

### System Requirements
- Python 3.8+
- Java 8+ (for APK analysis)
- Android SDK Platform Tools (for dynamic analysis)
- Android device or emulator (for dynamic analysis)

### Dependencies
```bash
pip install -r requirements.txt
```

## 📖 Usage

### Local Usage

#### Basic Usage

#### Quick Security Analysis
```bash
# Basic analysis of an APK file
python src/mobile_security_tester.py app.apk

# With debug output
python src/mobile_security_tester.py app.apk --debug

# Save results to file
python src/mobile_security_tester.py app.apk --output results.json
```

### Docker Usage

#### Basic Docker Commands
```bash
# Run with Docker (mount APK file)
docker run --rm -v $(pwd)/app.apk:/app/input/app.apk mobile-security-tester /app/input/app.apk

# Run with volume for output
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/output:/app/output \
    mobile-security-tester \
    /app/input/app.apk --output /app/output/results.json

# Interactive mode
docker run --rm -it mobile-security-tester
```

#### Docker Compose Usage
```bash
# Basic analysis
docker-compose run --rm mobile-tool /app/input/app.apk

# Static analysis only
docker-compose run --rm mobile-tool-static

# Comprehensive analysis
docker-compose run --rm mobile-tool-comprehensive

# Interactive mode
docker-compose run --rm mobile-tool-interactive

# Batch processing
docker-compose run --rm mobile-tool-batch
```

#### Advanced Docker Examples
```bash
# Static analysis with output
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/output:/app/output \
    mobile-security-tester \
    /app/input/app.apk --analysis-type static --output /app/output/static_analysis.json

# Comprehensive analysis with all reports
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/output:/app/output \
    -v $(pwd)/reports:/app/reports \
    mobile-security-tester \
    /app/input/app.apk \
    --analysis-type comprehensive \
    --output /app/output/comprehensive.json \
    --report /app/reports/report.html \
    --csv /app/output/results.csv

# Debug mode with detailed logging
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/output:/app/output \
    mobile-security-tester \
    /app/input/app.apk --debug --output /app/output/debug_report.json

# Batch processing multiple APKs
docker run --rm \
    -v $(pwd)/apks:/app/input \
    -v $(pwd)/output:/app/output \
    mobile-security-tester \
    /app/input --output /app/output/batch_results.json --summary /app/output/summary.txt
```

#### Docker with Custom Configuration
```bash
# Create directories
mkdir -p input output reports

# Copy APK to input directory
cp your_app.apk input/

# Run analysis
docker run --rm \
    -v $(pwd)/input:/app/input \
    -v $(pwd)/output:/app/output \
    -v $(pwd)/reports:/app/reports \
    mobile-security-tester \
    /app/input/your_app.apk \
    --analysis-type comprehensive \
    --output /app/output/analysis.json \
    --report /app/reports/report.html
```