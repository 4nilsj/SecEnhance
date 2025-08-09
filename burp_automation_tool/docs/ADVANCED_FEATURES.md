### Advanced Features

This document summarizes the advanced modules, how to load/use them, and example commands.

## OpenAPI ingestion and schema-based tests
- CLI: `scripts/openapi_import_cli.py`
- What it does: Loads an OpenAPI/Swagger spec, emits normalized endpoints and schema-derived JSON test cases.
- Output:
  - `artifacts/endpoints.json` – normalized endpoints
  - `artifacts/schema_tests.json` – schema-derived test cases
- Example:
```bash
python scripts/openapi_import_cli.py path/to/openapi.yaml --out artifacts
```

## Schema-based generation
- Library: `src/generators/schema_test_generator.py`
- Purpose: Create boundary/negative cases from JSON Schemas (objects, arrays, enums, formats).

## Access control testing (IDOR/BOLA)
- Extension: `extensions/python_extensions/advanced_access_control_tester.py`
- Load in Burp Extender (Python)
- Active scan: mutates IDs in paths and drops Authorization to detect IDOR/BOLA.

## Race condition testing
- Extension: `extensions/python_extensions/race_condition_tester.py`
- Active scan: sends concurrent requests with varying `Idempotency-Key` to detect double-processing.

## gRPC/HTTP/2 probes
- Extension: `extensions/python_extensions/grpc_http2_probes.py`
- Passive: detect `application/grpc` content-type, Alt-Svc h2 hints
- Active: send basic gRPC/TE: trailers probe and report variations

## CORS and Prototype Pollution
- BChecks:
  - `bchecks/vulnerability_checks/api_cors_misconfiguration.bcheck`
  - `bchecks/vulnerability_checks/api_json_prototype_pollution.bcheck`
- Applicability-aware; run them via Burp BCheck import.

## Unauthenticated Access Probe (Bambda)
- Script: `bambdas/request_bambdas/unauthenticated_access_probe.py`
- What it does: Strips Authorization/API key/CSRF headers, cookies, and token params from URL/body to test access without credentials.
- How to use: Load as a request script in Burp (e.g., via Repeater), send both with and without probe to compare behavior.

## HTTP Request Smuggling Probe (Bambda)
- Script: `bambdas/request_bambdas/http_request_smuggling_probe.py`
- What it does: Prepares a single HRS variant per invocation by adjusting headers/body (CL.TE, TE.CL, TE.TE, CL.CL, duplicate/invalid TE, negative/zero CL, header injection after chunk terminator).
- Applicability: Only for API-like paths and body-capable methods (POST/PUT/PATCH).
- How to use:
  - Load in the Bambda/request scripting interface.
  - Optionally set header `X-HRS-Variant: cl.te|te.cl|te.te|cl.cl|te.dup|te.invalid|cl.neg|cl.zero|te.inject`.
  - Send in Repeater; observe anomalies (errors, timeouts, desync behavior) and validate manually.

## Email Security Probe (Bambda)
- Script: `bambdas/request_bambdas/email_security_probe.py`
- What it does: Detects email-like parameters and injects diverse payloads (RFC edge cases, aliasing, unicode, IP-literals, long labels, SQL/NoSQL/XSS strings, CRLF/SMTP header injection).
- Applicability: API-like requests; targets keys containing: email, user_email, login, username, user, contact, mail.
- How to use:
  - Load in Bambda/request scripting.
  - In Repeater, set `X-Email-Payload-Index: 0..N` to choose a payload; otherwise rotates.
  - Compare validation, error handling, backend behavior differences across payloads.

## Directory Enumeration CLI (Dirb/DirBuster-like)
- CLI: `scripts/dir_enum_cli.py`
- Features:
  - Concurrent directory/file discovery
  - Extensions (e.g., `-e php,txt,html`)
  - Include/exclude status filtering
  - Redirect control, timeouts, custom headers/UA
  - Outputs plaintext and JSON
- Examples:
```bash
# Quick
python scripts/dir_enum_cli.py https://target.tld/app/ -w wordlist.txt -e php,txt \
  --status 200,301,302 --output artifacts/enum/scan1

# Fast HEAD probing with more threads
python scripts/dir_enum_cli.py https://api.tld/ -m HEAD -t 50
```

## OWASP/CWE Reporter
- Library: `src/reporters/owasp_cwe_reporter.py`
- Purpose: Map issue categories to OWASP API Top 10 and CWE, render JSON/HTML summaries.
- Use in your automation to aggregate and export findings.

## Related helper CLIs
- Bulk loader/listing: `scripts/burp_loader_cli.py`
  - `list` – list all BChecks/Bambdas/Extensions
  - `zip` – create bundles under `artifacts/`
  - `emit-rest-payloads` – print example JSON for hypothetical REST import workflows

## Notes
- All BChecks include applicability pre-checks to reduce noise.
- Bambdas and Extensions use applicability where possible to skip non-relevant probes.
- For Python extensions in Burp, ensure Jython is configured (Burp Extender > Options).

## Collaborator OAST Scanner (Out-of-Band)
- Extension: `extensions/python_extensions/collaborator_oast_scanner.py`
- Requirements: Burp Suite Professional with Collaborator enabled (Project Options > Misc > Collaborator)
- What it does:
  - Generates unique Collaborator payloads (DNS/HTTP)
  - Injects them into likely SSRF/webhook parameters and JWT `jku`
  - Polls Collaborator for interactions and raises issues with OAST evidence
- How to use:
  1) In Burp, ensure Collaborator is available (either default server or self-hosted)
  2) Load the extension (Burp Extender > Extensions > Add > Python)
  3) Run active scans on API endpoints; the extension will inject and poll
  4) Findings appear in Issues with payload and interaction type counts
- Notes:
  - Applicability-gated to API-like paths
  - Keeps payload budget light; expand logic if needed for broader probes