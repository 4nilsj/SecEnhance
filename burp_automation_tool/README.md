# Burp Automation Tool

A collection of BChecks, Extensions, and Bambdas for comprehensive API security testing with applicability-aware execution to reduce noise and speed up testing.

## Quick start

1) Prerequisites
- Burp Suite Professional (latest)
- Java 11+ (for Java extensions)
- Optional: Jython 2.7 standalone jar if you plan to load Python extensions in Burp (Burp Extender > Options)
- Python 3.9+ (for editing, payload utilities, and running helpers outside Burp)

2) Install Python deps (optional, for utils/CLI)
```bash
python -m venv .venv
.venv\Scripts\activate  # on Windows
pip install -r requirements.txt
```

3) Project layout (key parts)
- `bchecks/` BChecks to load into Burp
- `extensions/` Java/Python extensions to load in Burp Extender
- `bambdas/` request mutation scripts you can use to transform requests
- `src/utils/` helpers, including ApplicabilityChecker

## Configuration

If you will integrate with Burp's REST API or centralize settings, copy the sample config:

- Create `config/burp_config.yaml` from the example:
```bash
copy config\burp_config.example.yaml config\burp_config.yaml
```

Edit values:
```yaml
burp:
  host: localhost
  port: 1337
  api_key: "YOUR_BURP_API_KEY"
  timeout: 30
paths:
  bchecks_dir: bchecks\vulnerability_checks
  bambdas_dir: bambdas\request_bambdas
  extensions_dir: extensions\python_extensions
```

## Using BChecks

- In Burp, go to the BCheck interface, and import files from:
  - `bchecks/vulnerability_checks/*.bcheck`
- Recommended to start with:
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
- Each BCheck contains a fast applicability pre-check to skip non-relevant endpoints automatically.

## Using Extensions

- Java: build and load `extensions/java_extensions/CustomScanner.java` as a JAR (Burp Extender > Extensions > Add > Java)
- Python: load `extensions/python_extensions/api_security_scanner.py` or `advanced_api_scanner.py` (Burp Extender > Extensions > Add > Python)
  - Set Jython standalone jar in Burp Extender > Options if not configured
- Extensions add passive/active API security tests and work across Proxy/Repeater/Scanner.

## Using Bambdas

- Open the Bambda/script interface in Burp (load as a request/response modifier depending on your Burp edition)
- Recommended scripts:
  - `bambdas/request_bambdas/comprehensive_api_security.py`
  - `bambdas/request_bambdas/api_security_testing.py` (if present)
- These scripts perform applicability-aware mutations:
  - SSRF, Host header injection, parameter pollution, insecure methods, request smuggling
  - CORS probes, JSON prototype pollution injection
  - JWT `kid`/`jku` header tampering tests

Tip: Apply Bambdas in Repeater to a baseline request, then replay to observe effects safely.

## Applicability Intelligence

- Implemented in `src/utils/intelligence_checker.py`
- Checks the request path, method, headers, params, and content type to decide if a test should run
- Integrated into Bambdas; BChecks also include inline pre-checks

## Reporting & Logs

- Burp will display issues in the Scanner/Dashboard
- You can add your own logging under `logs/`

## Troubleshooting

- If Python extensions fail to load, ensure Jython is configured in Burp Extender > Options
- If BChecks seem noisy, disable some and rely on targeted Bambdas/Extensions; applicability rules should already minimize noise
- For corporate proxies, configure Burp Proxy and system environment accordingly
- If your editor shows unresolved imports for `utils.*` in Bambdas/Extensions, the repo includes a root `pyrightconfig.json` and `.vscode/settings.json` that add `burp_automation_tool/src` to analysis paths. Reload the window or restart the language server.

## Roadmap

- CLI to batch-load BChecks and scripts via Burp REST API
- gRPC/WebSocket deeper active tests
- Race condition and business-logic testing helpers 