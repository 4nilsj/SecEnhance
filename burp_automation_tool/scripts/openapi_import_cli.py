#!/usr/bin/env python3
"""
OpenAPI Import CLI
Loads an OpenAPI spec and emits endpoints and schema-based test cases as JSON files.
"""
import argparse
import json
from pathlib import Path
from src.openapi.openapi_loader import OpenAPILoader
from src.generators.schema_test_generator import SchemaTestGenerator


def main():
    p = argparse.ArgumentParser(description="OpenAPI Import CLI")
    p.add_argument("spec", help="Path to OpenAPI/Swagger file (json/yaml)")
    p.add_argument("--out", default="artifacts", help="Output directory")
    args = p.parse_args()

    outdir = Path(args.out); outdir.mkdir(parents=True, exist_ok=True)

    loader = OpenAPILoader(args.spec)
    loader.load()
    endpoints = loader.get_endpoints()
    (outdir / "endpoints.json").write_text(json.dumps(endpoints, indent=2), encoding="utf-8")

    gen = SchemaTestGenerator()
    tests = []
    for method, path, schema in loader.iter_request_schemas():
        cases = gen.generate_for_schema(schema)
        tests.append({"method": method, "path": path, "cases": cases})
    (outdir / "schema_tests.json").write_text(json.dumps(tests, indent=2), encoding="utf-8")
    print(f"Wrote {outdir / 'endpoints.json'} and {outdir / 'schema_tests.json'}")


if __name__ == "__main__":
    main()