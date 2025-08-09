### Loading Components in Burp Suite

This guide shows how to load BChecks, Bambdas (request scripts), and Extensions into Burp Suite Professional.

## BChecks
1) Open Burp > Dashboard > BChecks (or Scanner > BChecks depending on version)
2) Click Import/Load BCheck
3) Select files from:
   - `bchecks/vulnerability_checks/*.bcheck`
4) Recommended to start with:
   - `api_authentication_bypass.bcheck`
   - `api_ssrf_detection.bcheck`
   - `api_insecure_http_methods.bcheck`
   - `api_host_header_injection.bcheck`
   - `api_http_parameter_pollution.bcheck`
   - `api_http_request_smuggling.bcheck`
   - `api_oauth_security.bcheck`
   - `api_graphql_security.bcheck`
   - `api_cors_misconfiguration.bcheck`
   - `api_json_prototype_pollution.bcheck`

Notes
- Each BCheck includes a quick applicability pre-check to skip non-relevant endpoints.
- Limit scope to API hosts: Target > Scope > Include your API domain(s).

## Bambdas (Request/Response scripts)
Depending on your Burp edition/feature availability for request scripting:
1) Open the scripting/Bambda interface
2) Add a new script and choose Python (where applicable)
3) Load the content from:
   - `bambdas/request_bambdas/comprehensive_api_security.py`
4) Apply the Bambda in Repeater/Proxy/Scanner contexts to mutate outgoing requests.

Notes
- The comprehensive script performs SSRF, Host header injection, parameter pollution, insecure methods, request smuggling, CORS probe, JSON prototype pollution, and JWT kid/jku tampering.
- Applicability checks skip non-relevant mutations automatically.

## Extensions
### Python extensions
1) Burp > Extender > Options: set Jython standalone jar path (if not already set)
2) Burp > Extender > Extensions > Add
   - Extension Type: Python
   - Extension file: choose one of:
     - `extensions/python_extensions/api_security_scanner.py`
     - `extensions/python_extensions/advanced_api_scanner.py`
3) Confirm it loads; check Extender output tab for logs.

### Java extensions
1) Build the Java extension (e.g., with Maven/Gradle) into a JAR containing `burp` package classes
2) Burp > Extender > Extensions > Add
   - Extension Type: Java
   - Extension file: select the built JAR (from `extensions/java_extensions/` sources)
3) Confirm load logs in output.

## Optional: Bulk helper CLI
We provide a helper CLI to list and bundle BChecks/Bambdas/Extensions for easy sharing/import.
- See `scripts/burp_loader_cli.py`
- Example usage (Windows PowerShell):
```powershell
python scripts/burp_loader_cli.py list
python scripts/burp_loader_cli.py zip --out artifacts
```
This creates zip bundles under `artifacts/` for quick import.

This toolkit does not rely on Burp REST/Enterprise API. Avoid REST-dependent features/extensions; use manual import and the provided CLI for listing/zipping artifacts.

## Tips
- Save a Burp project file after importing components to reuse the setup
- Use Target > Scope to reduce noise
- Validate findings in Repeater after BCheck/Bambda triggers