#!/usr/bin/env python3
"""
OpenAPI Loader
Parses OpenAPI 3.x and Swagger 2.0 files into normalized endpoint specifications.
"""
from typing import Any, Dict, List, Optional, Tuple
import json
from pathlib import Path

try:
    import yaml  # type: ignore
except Exception:  # Fallback if PyYAML not available
    yaml = None  # type: ignore

class OpenAPILoader:
    """Load OpenAPI/Swagger documents and extract endpoints with schemas."""

    def __init__(self, spec_path: str) -> None:
        self.spec_path = Path(spec_path)
        self.raw: Dict[str, Any] = {}
        self.version: str = ""

    def load(self) -> Dict[str, Any]:
        text = self.spec_path.read_text(encoding="utf-8")
        data: Dict[str, Any]
        if self.spec_path.suffix.lower() in (".yaml", ".yml"):
            if not yaml:
                raise RuntimeError("PyYAML not installed. Install pyyaml to parse YAML specs.")
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
        self.raw = data
        self.version = str(data.get("openapi") or data.get("swagger") or "")
        return data

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Return a list of endpoints with method, path, params, requestBody schema, responses."""
        if not self.raw:
            self.load()
        paths = self.raw.get("paths", {})
        components = self.raw.get("components", {})
        out: List[Dict[str, Any]] = []
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, op in methods.items():
                if method.lower() not in {"get","post","put","patch","delete","options","head"}:
                    continue
                spec: Dict[str, Any] = {
                    "method": method.upper(),
                    "path": path,
                    "operationId": op.get("operationId"),
                    "tags": op.get("tags", []),
                    "parameters": self._resolve_parameters(op, self.raw),
                    "requestBody": self._resolve_request_body(op, self.raw),
                    "responses": op.get("responses", {}),
                    "security": op.get("security", self.raw.get("security", [])),
                }
                out.append(spec)
        return out

    def _resolve_parameters(self, op: Dict[str, Any], doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        params = op.get("parameters", [])
        resolved: List[Dict[str, Any]] = []
        for p in params:
            if "$ref" in p:
                ref = p["$ref"]
                resolved.append(self._resolve_ref(ref, doc) or {})
            else:
                resolved.append(p)
        return resolved

    def _resolve_request_body(self, op: Dict[str, Any], doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        rb = op.get("requestBody")
        if not rb:
            return None
        if "$ref" in rb:
            rb = self._resolve_ref(rb["$ref"], doc)
        return rb

    def _resolve_ref(self, ref: str, doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not ref.startswith("#/"):
            return None
        parts = ref[2:].split("/")
        node: Any = doc
        for key in parts:
            if not isinstance(node, dict):
                return None
            node = node.get(key)
        return node if isinstance(node, dict) else None

    def iter_request_schemas(self) -> List[Tuple[str, str, Dict[str, Any]]]:
        """Yield (method, path, schema) for JSON request bodies."""
        items: List[Tuple[str, str, Dict[str, Any]]] = []
        for ep in self.get_endpoints():
            rb = ep.get("requestBody") or {}
            content = rb.get("content", {})
            appjson = content.get("application/json")
            if appjson and "schema" in appjson:
                schema = appjson.get("schema", {})
                items.append((ep["method"], ep["path"], schema))
        return items