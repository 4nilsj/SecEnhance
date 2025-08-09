#!/usr/bin/env python3
"""
Schema-based Test Generator
Generates boundary and negative test cases from OpenAPI JSON Schemas.
"""
from typing import Any, Dict, List
import itertools

class SchemaTestGenerator:
    """Generate test inputs based on JSON Schema-like definitions."""

    def __init__(self) -> None:
        pass

    def generate_for_schema(self, schema: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate a list of JSON bodies from a JSON schema object.
        Focus on object type with properties; supports enums, min/max, formats.
        """
        if not isinstance(schema, dict):
            return []
        if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
            # Simple array: generate few counts
            item = schema["items"]
            base = self._value_for(item)
            return [[], [base], [base, base]]
        if schema.get("type") == "object":
            props = schema.get("properties", {})
            required = set(schema.get("required", []))
            base: Dict[str, Any] = {}
            for name, prop in props.items():
                base[name] = self._value_for(prop)
            cases = [base]
            # Negative cases: drop required, wrong types, enum violations
            for r in required:
                bad = dict(base)
                bad.pop(r, None)
                cases.append(bad)
            for name, prop in props.items():
                # Wrong type
                bad = dict(base)
                bad[name] = self._wrong_type_for(prop)
                cases.append(bad)
                # Enum violation
                if "enum" in prop:
                    bad2 = dict(base)
                    bad2[name] = "__not_an_enum_value__"
                    cases.append(bad2)
            return cases
        # Primitive
        return [{"value": self._value_for(schema)}]

    def _value_for(self, prop: Dict[str, Any]) -> Any:
        t = prop.get("type")
        if isinstance(t, list):
            t = [x for x in t if x != "null"][0] if t else None
        if "enum" in prop:
            return prop["enum"][0]
        if t == "string":
            fmt = prop.get("format")
            min_len = prop.get("minLength", 1)
            if fmt == "email":
                return "user@example.com"
            if fmt == "uuid":
                return "123e4567-e89b-12d3-a456-426614174000"
            return "a" * min_len
        if t == "integer":
            return prop.get("minimum", 0)
        if t == "number":
            return float(prop.get("minimum", 0))
        if t == "boolean":
            return True
        if t == "array":
            items = prop.get("items", {"type": "string"})
            return [self._value_for(items)]
        if t == "object":
            return {k: self._value_for(v) for k, v in prop.get("properties", {}).items()}
        return None

    def _wrong_type_for(self, prop: Dict[str, Any]) -> Any:
        t = prop.get("type")
        if isinstance(t, list):
            t = [x for x in t if x != "null"][0] if t else None
        mapping = {
            "string": 123,
            "integer": "not-an-int",
            "number": "not-a-number",
            "boolean": "not-a-bool",
            "array": "not-an-array",
            "object": "not-an-object",
        }
        return mapping.get(t, None)