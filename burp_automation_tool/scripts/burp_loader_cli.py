#!/usr/bin/env python3
"""
Burp Loader CLI
- List BChecks, Bambdas, and Extensions
- Package them into zip bundles for easy import/sharing
"""
import argparse
import os
import sys
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BCH_DIR = ROOT / "bchecks" / "vulnerability_checks"
BAM_DIR = ROOT / "bambdas" / "request_bambdas"
EXT_PY = ROOT / "extensions" / "python_extensions"
EXT_JAVA = ROOT / "extensions" / "java_extensions"
ARTIFACTS = ROOT / "artifacts"

CATEGORIES = {
    "bchecks": BCH_DIR,
    "bambdas": BAM_DIR,
    "extensions_python": EXT_PY,
    "extensions_java": EXT_JAVA,
}


def collect_files() -> dict:
    collected = {}
    for key, path in CATEGORIES.items():
        files = []
        if path.exists():
            for p in path.rglob("*"):
                if p.is_file():
                    files.append(str(p.relative_to(ROOT)))
        collected[key] = sorted(files)
    return collected


def list_cmd(_: argparse.Namespace) -> None:
    collected = collect_files()
    print(json.dumps(collected, indent=2))


def zip_cmd(args: argparse.Namespace) -> None:
    ARTIFACTS.mkdir(exist_ok=True)
    collected = collect_files()
    out_dir = ARTIFACTS if not args.out else Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Create bundles per category
    for cat, files in collected.items():
        if not files:
            continue
        zip_path = out_dir / f"{cat}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel in files:
                abs_path = ROOT / rel
                zf.write(abs_path, arcname=rel)
        print(f"Wrote: {zip_path}")

    # Combined bundle
    all_zip = out_dir / "burp_automation_bundle.zip"
    with zipfile.ZipFile(all_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for files in collected.values():
            for rel in files:
                abs_path = ROOT / rel
                zf.write(abs_path, arcname=rel)
    print(f"Wrote: {all_zip}")


# Note: No REST API helpers are provided to avoid reliance on Burp Enterprise features.


def main(argv=None):
    parser = argparse.ArgumentParser(description="Burp Loader CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="List available components")
    p_list.set_defaults(func=list_cmd)

    p_zip = sub.add_parser("zip", help="Zip components for import")
    p_zip.add_argument("--out", default=str(ARTIFACTS), help="Output directory for zips")
    p_zip.set_defaults(func=zip_cmd)

    # No REST-related subcommands

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()