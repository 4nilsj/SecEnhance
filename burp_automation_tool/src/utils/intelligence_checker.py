#!/usr/bin/env python3
"""
Applicability Intelligence Utility
Determines whether a given security check is applicable to a request/context.
"""
from typing import Any, Dict

class ApplicabilityChecker:
    """Lightweight heuristics to decide if a check should run for a request."""

    API_PATH_HINTS = ("/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql", "/gql")
    STATIC_EXTENSIONS = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")

    def _safe_get(self, request: Any, attr: str, default: Any = None):
        return getattr(request, attr, default)

    def _get_headers(self, request: Any) -> Dict[str, str]:
        headers = self._safe_get(request, "headers", {}) or {}
        return {str(k).strip(): str(v) for k, v in headers.items()} if isinstance(headers, dict) else {}

    def _get_path(self, request: Any) -> str:
        return (self._safe_get(request, "path", "") or "").lower()

    def _get_method(self, request: Any) -> str:
        return (self._safe_get(request, "method", "GET") or "GET").upper()

    def _get_params(self, request: Any) -> Dict[str, Any]:
        params = self._safe_get(request, "parameters", {}) or {}
        return params if isinstance(params, dict) else {}

    def _get_content_type(self, request: Any) -> str:
        headers = self._get_headers(request)
        return headers.get("Content-Type") or headers.get("content-type") or ""

    def _looks_like_api(self, path: str) -> bool:
        return any(h in path for h in self.API_PATH_HINTS) and not path.endswith(self.STATIC_EXTENSIONS)

    def is_general_api_applicable(self, request: Any) -> bool:
        return self._looks_like_api(self._get_path(request))

    def is_json_api(self, request: Any) -> bool:
        return "json" in self._get_content_type(request).lower() or self._get_path(request).endswith((".json",))

    def has_parameters(self, request: Any) -> bool:
        return len(self._get_params(request)) > 0

    def is_graphql(self, request: Any) -> bool:
        path = self._get_path(request)
        if "/graphql" in path or "/gql" in path:
            return True
        ct = self._get_content_type(request).lower()
        body = self._safe_get(request, "body", "") or ""
        if "json" in ct and isinstance(body, (str, bytes)):
            text = body.decode("utf-8", errors="ignore") if isinstance(body, bytes) else body
            return "__schema" in text or "query" in text or "mutation" in text
        return False

    def is_oauth_flow(self, request: Any) -> bool:
        path = self._get_path(request)
        if any(p in path for p in ("/oauth", "/authorize", "/token", "/callback")):
            return True
        params = {k.lower(): v for k, v in self._get_params(request).items()}
        return any(k in params for k in ("response_type", "client_id", "redirect_uri", "scope"))

    def is_ssrf_applicable(self, request: Any) -> bool:
        if not self.is_general_api_applicable(request):
            return False
        params = {str(k).lower(): v for k, v in self._get_params(request).items()}
        url_like_keys = ("url", "uri", "link", "redirect", "target", "callback", "path")
        if any(any(key in k for key in url_like_keys) for k in params.keys()):
            return True
        body = self._safe_get(request, "body", "") or ""
        if isinstance(body, (str, bytes)):
            text = body.decode("utf-8", errors="ignore") if isinstance(body, bytes) else body
            return any(f in text.lower() for f in url_like_keys)
        return False

    def is_insecure_methods_applicable(self, request: Any) -> bool:
        path = self._get_path(request)
        if not self._looks_like_api(path):
            return False
        if any(seg in path for seg in ("/static/", "/assets/", "/content/", "/images/", "/scripts/")):
            return False
        return True

    def is_host_header_injection_applicable(self, request: Any) -> bool:
        headers = {k.lower(): v for k, v in self._get_headers(request).items()}
        path = self._get_path(request)
        has_host = "host" in headers
        not_static = not any(path.endswith(ext) for ext in self.STATIC_EXTENSIONS)
        return has_host and not_static

    def is_parameter_pollution_applicable(self, request: Any) -> bool:
        return self.has_parameters(request) and self.is_general_api_applicable(request)

    def is_request_smuggling_applicable(self, request: Any) -> bool:
        if not self._looks_like_api(self._get_path(request)):
            return False
        return self._get_method(request) in ("POST", "PUT", "PATCH")

    def is_auth_bypass_applicable(self, request: Any) -> bool:
        headers = {k.lower(): v for k, v in self._get_headers(request).items()}
        path = self._get_path(request)
        if any(seg in path for seg in ("/login", "/signin", "/auth", "/oauth", "/token")):
            return True
        return any(h in headers for h in ("authorization", "x-api-key", "api-key", "x-auth-token", "x-access-token"))

    # New applicability helpers
    def is_cors_applicable(self, request: Any) -> bool:
        path = self._get_path(request)
        if not self._looks_like_api(path):
            return False
        return not any(path.endswith(ext) for ext in self.STATIC_EXTENSIONS)

    def is_json_mutation_applicable(self, request: Any) -> bool:
        if self._get_method(request) not in ("POST", "PUT", "PATCH"):
            return False
        ct = self._get_content_type(request).lower()
        return "json" in ct

    def is_jwt_header_applicable(self, request: Any) -> bool:
        headers = {k.lower(): v for k, v in self._get_headers(request).items()}
        auth = headers.get("authorization", "")
        return auth.lower().startswith("bearer ") or self.is_auth_bypass_applicable(request)