### Configuration Guide

This guide walks through configuring, loading, and using the Burp Automation Tool components.

## 1. Prerequisites
- Burp Suite Professional (latest)
- Java 11+ (for Java extensions)
- Optional: Jython 2.7 standalone jar for Python extensions
- Python 3.9+ for utilities

## 2. Python environment (optional)
```bash
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
```

## 3. Create a config
Copy the sample and edit:
```bash
copy config\\burp_config.example.yaml config\\burp_config.yaml
```
Supported keys:
```yaml
burp:
  # No REST/Enterprise API configuration required.
  timeout: 30
paths:
  bchecks_dir: bchecks\\vulnerability_checks
  bambdas_dir: bambdas\\request_bambdas
  extensions_dir: extensions\\python_extensions
```

## 4. Load BChecks
- Open Burp > BCheck (Import)
- Import from `bchecks/vulnerability_checks/*.bcheck`
- BChecks include applicability pre-checks to avoid running on irrelevant endpoints.

## 5. Load Extensions
- Java: Build `extensions/java_extensions/CustomScanner.java` into a JAR and load in Burp Extender
- Python: Load `extensions/python_extensions/api_security_scanner.py` or `advanced_api_scanner.py`
  - Configure Jython (Burp Extender > Options) if not already set

## 6. Use Bambdas
- Load scripts from `bambdas/request_bambdas/`
- Recommended: `comprehensive_api_security.py`
- Apply in Repeater/Scanner contexts to mutate outgoing requests
- Applicability intelligence will skip non-applicable mutations

## 7. Common scenarios
- API authentication testing: load `api_authentication_bypass.bcheck`, use Bambda JWT tests
- SSRF: use BCheck `api_ssrf_detection.bcheck` and Bambda SSRF handler
- CORS: use `api_cors_misconfiguration.bcheck` or the CORS probe in the comprehensive Bambda
- Prototype pollution: `api_json_prototype_pollution.bcheck` and the JSON mutation Bambda

## 8. Tips
- Keep Burp project-specific: save a Burp project file with your imported BChecks and extensions
- Limit scope to the API host to reduce noise (Target > Scope)
- Use Repeater to validate findings from BChecks/Bambdas manually

## 9. Troubleshooting
- Python extension not loading: configure Jython and restart Burp
- BChecks not triggering: verify the endpoint path matches API patterns and the pre-check conditions
- Network issues: verify Burp Proxy settings and system proxy