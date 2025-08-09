#!/usr/bin/env python3
"""
Unauthenticated Access Probe Bambda
Removes Authorization headers, API keys, CSRF headers, token params, and cookies from the request.
"""
import os
import sys
import json
from urllib.parse import urlencode, urlparse, parse_qs

CURRENT_DIR = os.path.dirname(__file__)
SRC_PATH = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.append(SRC_PATH)

try:
    from utils.intelligence_checker import ApplicabilityChecker
    checker = ApplicabilityChecker()
except Exception:
    checker = None

AUTH_HEADER_KEYS = {
    "authorization", "x-api-key", "api-key", "x-auth-token", "x-access-token",
    "x-token", "auth-token", "x-session-id", "session"
}
CSRF_HEADER_KEYS = {"x-csrf-token", "x-xsrf-token", "x-requested-with"}
TOKEN_PARAM_KEYS = {
    "token", "auth", "auth_token", "access_token", "id_token", "jwt", "session",
    "sid", "csrf", "xsrf"
}


def _strip_headers(headers: dict) -> dict:
    new_headers = {}
    for k, v in (headers or {}).items():
        kl = str(k).lower()
        if kl in AUTH_HEADER_KEYS or kl in CSRF_HEADER_KEYS:
            continue
        if kl == "cookie":
            continue
        new_headers[k] = v
    return new_headers


def _strip_params(params: dict) -> dict:
    new_params = {}
    for k, v in (params or {}).items():
        kl = str(k).lower()
        if kl in TOKEN_PARAM_KEYS:
            continue
        new_params[k] = v
    return new_params


def _strip_body(body, headers: dict):
    ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
    if "application/json" in ct:
        try:
            data = json.loads(body or "{}")
            if isinstance(data, dict):
                data = {k: v for k, v in data.items() if str(k).lower() not in TOKEN_PARAM_KEYS}
                return json.dumps(data)
        except Exception:
            return body
    if "application/x-www-form-urlencoded" in ct:
        try:
            pairs = []
            for k, v in parse_qs(body or "", keep_blank_values=True).items():
                if str(k).lower() in TOKEN_PARAM_KEYS:
                    continue
                for val in v:
                    pairs.append((k, val))
            return urlencode(pairs)
        except Exception:
            return body
    return body


def main(request):
    if checker and not checker.is_general_api_applicable(request):
        return request
    headers = _strip_headers(getattr(request, "headers", {}) or {})
    params = _strip_params(getattr(request, "parameters", {}) or {})
    body = _strip_body(getattr(request, "body", None), headers)
    request.headers = headers
    request.parameters = params
    if body is not None:
        request.body = body
    return request

if __name__ == "__main__":
    print("Unauthenticated Access Probe Bambda loaded")