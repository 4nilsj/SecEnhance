# ZAP Scan Modes Guide

The API Security Scanner provides multiple ZAP scan modes to suit different testing scenarios and environments. Each mode is optimized for specific use cases with different levels of aggressiveness, coverage, and impact on target systems.

**Important:** Scan modes only apply to ZAP scanning. Custom plugins run independently and are not affected by scan modes. For plugin-only scanning, use `--no-zap` without specifying a scan mode.

## Available Scan Modes

### 1. Safe Mode (Default)
**Mode:** `safe`  
**Risk Level:** Low  
**Duration:** 15-30 minutes  
**Use Case:** Production environments, sensitive systems

**Configuration:**
- ZAP Enabled: Yes
- Spider Depth: 3
- Request Delay: 500ms
- Concurrent Requests: 1
- Aggressive Scanning: No
- Stealth Mode: Yes

**Features:**
- Conservative scanning approach
- Minimal impact on target systems
- Comprehensive security checks
- Suitable for production environments
- Includes all security plugins

**Recommended for:**
- Production API testing
- Sensitive systems
- Regular security assessments
- Compliance testing

---

### 2. Attack Mode
**Mode:** `attack`  
**Risk Level:** High  
**Duration:** 1-2 hours  
**Use Case:** Penetration testing, security assessments

**Configuration:**
- ZAP Enabled: Yes
- Spider Depth: 10
- Request Delay: 100ms
- Concurrent Requests: 5
- Aggressive Scanning: Yes
- Stealth Mode: No
- SSL Verification: Disabled (for testing)

**Features:**
- Aggressive vulnerability testing
- Comprehensive attack vectors
- Maximum coverage
- Includes fuzzing and injection tests
- All security plugins enabled

**Recommended for:**
- Penetration testing
- Security assessments
- Red team exercises
- Vulnerability research

---

### 3. Spidering Mode
**Mode:** `spidering`  
**Risk Level:** Very Low  
**Duration:** 30-60 minutes  
**Use Case:** Endpoint discovery, API mapping

**Configuration:**
- ZAP Enabled: Yes
- Spider Depth: 15
- Request Delay: 200ms
- Concurrent Requests: 3
- Aggressive Scanning: No
- Stealth Mode: Yes

**Features:**
- Focus on endpoint discovery
- API mapping and enumeration
- Minimal security testing
- Maximum spider depth
- Stealth approach

**Recommended for:**
- API endpoint discovery
- Application mapping
- Reconnaissance phase
- Understanding API structure

---

### 4. Comprehensive Mode
**Mode:** `comprehensive`  
**Risk Level:** Medium  
**Duration:** 2-3 hours  
**Use Case:** Full security audit, compliance testing

**Configuration:**
- ZAP Enabled: Yes
- Spider Depth: 8
- Request Delay: 200ms
- Concurrent Requests: 3
- Aggressive Scanning: Yes
- Stealth Mode: No

**Features:**
- Complete security assessment
- All available tools and plugins
- Balanced approach
- Maximum coverage
- Detailed reporting

**Recommended for:**
- Full security audits
- Compliance testing
- Pre-deployment testing
- Comprehensive assessments

---

### 5. Stealth Mode
**Mode:** `stealth`  
**Risk Level:** Very Low  
**Duration:** 10-15 minutes  
**Use Case:** Covert testing, avoiding WAF detection

**Configuration:**
- ZAP Enabled: No
- Spider Depth: 2
- Request Delay: 2 seconds
- Concurrent Requests: 1
- Aggressive Scanning: No
- Stealth Mode: Yes
- Custom User Agent: Browser-like

**Features:**
- Minimal footprint
- Browser-like requests
- Slow scanning
- Avoids detection
- Limited scope

**Recommended for:**
- Covert testing
- Avoiding WAF detection
- Stealth reconnaissance
- Low-impact testing

---

### 6. Aggressive Mode
**Mode:** `aggressive`  
**Risk Level:** Very High  
**Duration:** 3-4 hours  
**Use Case:** Red team exercises, maximum coverage testing

**Configuration:**
- ZAP Enabled: Yes
- Spider Depth: 20
- Request Delay: 50ms
- Concurrent Requests: 10
- Aggressive Scanning: Yes
- Stealth Mode: No
- SSL Verification: Disabled

**Features:**
- Maximum intensity scanning
- All attack vectors
- High concurrency
- Extended spider depth
- Comprehensive fuzzing

**Recommended for:**
- Red team exercises
- Maximum coverage testing
- Stress testing
- Advanced penetration testing

---

### 7. Quick Mode
**Mode:** `quick`  
**Risk Level:** Very Low  
**Duration:** 2-5 minutes  
**Use Case:** Development testing, CI/CD pipelines

**Configuration:**
- ZAP Enabled: No
- Spider Depth: 1
- Request Delay: 100ms
- Concurrent Requests: 5
- Aggressive Scanning: No
- Stealth Mode: No

**Features:**
- Fast execution
- Essential security checks
- Development-friendly
- CI/CD integration
- Basic coverage

**Recommended for:**
- Development testing
- CI/CD pipelines
- Quick security checks
- Pre-commit testing

---

### 8. API-Focused Mode
**Mode:** `api-focused`  
**Risk Level:** Low  
**Duration:** 20-30 minutes  
**Use Case:** API security testing, microservices assessment

**Configuration:**
- ZAP Enabled: No
- Spider Depth: 5
- Request Delay: 200ms
- Concurrent Requests: 3
- Aggressive Scanning: No
- Stealth Mode: No

**Features:**
- Specialized for APIs
- REST/GraphQL/gRPC support
- API-specific vulnerabilities
- Fuzzing enabled
- All API security plugins

**Recommended for:**
- API security testing
- Microservices assessment
- REST API testing
- GraphQL security
- gRPC security

---

## Usage Examples

### Command Line Usage

```bash
# Safe mode for production
python main.py scan -f api.json --scan-mode safe

# Aggressive penetration testing
python main.py scan -f api.json --scan-mode attack

# Quick development scan
python main.py scan -f api.json --scan-mode quick

# Comprehensive security audit
python main.py scan -f api.json --scan-mode comprehensive

# Stealth mode to avoid detection
python main.py scan -f api.json --scan-mode stealth

# API-focused scanning
python main.py scan -f api.json --scan-mode api-focused

# Spidering for endpoint discovery
python main.py scan -f api.json --scan-mode spidering

# Maximum intensity scanning
python main.py scan -f api.json --scan-mode aggressive
```

### List Available Modes

```bash
# Show all available scan modes
python main.py scan-modes
```

### Interactive Mode

```bash
# Interactive mode with scan mode selection
python main.py --interactive scan
```

## Mode Selection Guide

### For Production Environments
- **Safe Mode**: Conservative approach, minimal impact
- **Stealth Mode**: Avoid detection, low footprint

### For Development
- **Quick Mode**: Fast feedback, CI/CD integration
- **API-Focused Mode**: API-specific testing

### For Security Testing
- **Comprehensive Mode**: Full security audit
- **Attack Mode**: Penetration testing
- **Aggressive Mode**: Maximum coverage

### For Discovery
- **Spidering Mode**: Endpoint discovery
- **API-Focused Mode**: API structure analysis

## Configuration Override

Scan modes can be customized by overriding specific parameters:

```bash
# Use attack mode but with custom spider depth
python main.py scan -f api.json --scan-mode attack --spider-depth 5

# Use safe mode but disable ZAP
python main.py scan -f api.json --scan-mode safe --no-zap

# Use quick mode with specific plugins
python main.py scan -f api.json --scan-mode quick --plugins JWTSecurityChecker,SecurityHeadersChecker
```

## Environment Variables

Scan modes can also be configured via environment variables:

```bash
# Set default scan mode
export SCAN_MODE=safe

# Override specific mode settings
export SCAN_MODE_REQUEST_DELAY=0.5
export SCAN_MODE_CONCURRENT_REQUESTS=2
export SCAN_MODE_AGGRESSIVE=false
export SCAN_MODE_STEALTH=true
```

## Best Practices

1. **Start with Safe Mode**: Always begin with safe mode for production systems
2. **Use Appropriate Mode**: Match the scan mode to your testing scenario
3. **Consider Impact**: Be aware of the impact on target systems
4. **Time Constraints**: Choose modes that fit your time constraints
5. **Compliance**: Use comprehensive mode for compliance testing
6. **Development**: Use quick mode for development workflows

## ZAP Mode Comparison

| Mode | ZAP | Duration | Risk | Use Case |
|------|-----|----------|------|----------|
| Safe | ✓ | 15-30 min | Low | Production |
| Attack | ✓ | 1-2 hours | High | Penetration |
| Spidering | ✓ | 30-60 min | Very Low | Discovery |
| Comprehensive | ✓ | 2-3 hours | Medium | Full Audit |
| Stealth | ✓ | 10-15 min | Very Low | Covert |
| Aggressive | ✓ | 3-4 hours | Very High | Red Team |
| Quick | ✓ | 2-5 min | Very Low | Development |
| API-Focused | ✓ | 20-30 min | Low | API Testing |

**Note:** All scan modes now use ZAP. For plugin-only scanning without ZAP, use `--no-zap` without specifying a scan mode.

## Troubleshooting

### Common Issues

1. **Mode Not Found**: Ensure you're using the correct mode name
2. **Permission Denied**: Some modes require elevated permissions
3. **Timeout Issues**: Aggressive modes may timeout on slow systems
4. **Resource Usage**: High-intensity modes consume more resources

### Getting Help

```bash
# Show scan mode help
python main.py scan-modes

# Show general help
python main.py help

# Show scan command help
python main.py scan --help
```

## Advanced Configuration

For advanced users, scan modes can be fully customized by modifying the configuration files or using environment variables. See the [Configuration Guide](CONFIGURATION_GUIDE.md) for more details.
