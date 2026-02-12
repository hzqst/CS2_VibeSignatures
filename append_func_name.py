#!/usr/bin/env python3
"""Append func_name to YAML files under bin/ that contain func_va."""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml


def extract_func_name(file_path: Path) -> str:
    """Extract function name from a file name like Foo_Bar.linux.yaml."""
    base = file_path.name
    if base.endswith(".yaml"):
        base = base[:-5]
    if "." in base:
        base = base.split(".", 1)[0]
    return base


def process_yaml_file(file_path: Path) -> bool:
    """Return True when file content was changed."""
    with file_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict) or "func_va" not in data:
        return False

    func_name = extract_func_name(file_path)
    if data.get("func_name") == func_name:
        return False

    data["func_name"] = func_name

    with file_path.open("w", encoding="utf-8", newline="\n") as f:
        yaml.safe_dump(
            data,
            f,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=False,
        )

    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Append func_name for YAML files that contain func_va."
    )
    parser.add_argument(
        "--root",
        default="bin",
        help="Root directory to scan (default: bin).",
    )
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        raise SystemExit(f"Root path does not exist: {root}")

    updated = 0
    scanned = 0

    for yaml_file in root.rglob("*.yaml"):
        scanned += 1
        if process_yaml_file(yaml_file):
            updated += 1
            print(f"updated: {yaml_file}")

    print(f"done: scanned={scanned}, updated={updated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
