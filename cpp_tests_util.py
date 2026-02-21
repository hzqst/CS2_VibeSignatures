#!/usr/bin/env python3
"""Utility helpers for C++ vtable test scripts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:
    import yaml
except ImportError:
    yaml = None


VFTABLE_HEADER_RE = re.compile(
    r"^\s*(?:VFTable|VTable) indices for '([^']+)' \((\d+) entries\)\.\s*$"
)
VFTABLE_ENTRY_RE = re.compile(r"^\s*(\d+)\s+\|\s+(.+?)\s*$")


def map_target_triple_to_platform(target_triple: str) -> Optional[str]:
    """
    Map configured target triple to platform name used by YAML output files.

    Rules:
    - x86_64-pc-windows-msvc => windows
    - x86_64-pc-windows-gnu  => linux
    - x86_64-*-linux-gnu     => linux
    """
    if target_triple == "x86_64-pc-windows-msvc":
        return "windows"
    if target_triple == "x86_64-pc-windows-gnu":
        return "linux"
    if re.match(r"^x86_64-[^-]+-linux-gnu$", target_triple):
        return "linux"
    return None


def pointer_size_from_target_triple(target_triple: str) -> int:
    """Infer pointer size from the target triple."""
    if target_triple.startswith("x86_64-"):
        return 8
    return 8


def parse_vftable_layouts(compiler_output: str) -> Dict[str, Dict[str, Any]]:
    """
    Parse clang `-fdump-vtable-layouts` output.

    Returns:
        {
          "<ClassName>": {
            "declared_entries": int,
            "methods_by_index": {
              <idx>: {
                "signature": "<full signature line>",
                "member_name": "<member token if parsed>"
              }
            },
            "entry_count": int
          },
          ...
        }
    """
    parsed: Dict[str, Dict[str, Any]] = {}
    current_class: Optional[str] = None
    current_declared_entries = 0

    for raw_line in compiler_output.splitlines():
        header = VFTABLE_HEADER_RE.match(raw_line)
        if header:
            current_class = header.group(1)
            declared_entries = int(header.group(2))
            current_declared_entries = declared_entries
            parsed[current_class] = {
                "declared_entries": declared_entries,
                "methods_by_index": {},
                "entry_count": 0,
            }
            continue

        if current_class is None:
            continue

        entry = VFTABLE_ENTRY_RE.match(raw_line)
        if not entry:
            if (
                current_class is not None
                and parsed[current_class]["methods_by_index"]
                and not raw_line.strip()
            ):
                current_class = None
                current_declared_entries = 0
            continue

        index = int(entry.group(1))
        # Stop at section boundary to avoid swallowing "N | ..." lines
        # from other vtable-related blocks in clang output.
        if index >= current_declared_entries:
            current_class = None
            current_declared_entries = 0
            continue

        signature = entry.group(2).strip()
        member_name = _extract_member_name(signature, current_class)
        parsed[current_class]["methods_by_index"][index] = {
            "signature": signature,
            "member_name": member_name,
        }

        if len(parsed[current_class]["methods_by_index"]) >= current_declared_entries:
            current_class = None
            current_declared_entries = 0

    for class_name, section in parsed.items():
        section["entry_count"] = len(section["methods_by_index"])

    return parsed


def _extract_member_name(signature: str, class_name: str) -> str:
    marker = f"{class_name}::"
    pos = signature.find(marker)
    if pos < 0:
        return ""
    tail = signature[pos + len(marker) :]
    end = tail.find("(")
    if end < 0:
        end = len(tail)
    return tail[:end].strip()


def _parse_int_maybe(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def _normalize_reference_member_name(
    class_name: str,
    func_name: Optional[str],
    file_stem: str,
) -> str:
    candidate = (func_name or file_stem).strip()
    prefix = f"{class_name}_"
    if candidate.startswith(prefix):
        return candidate[len(prefix) :]
    return candidate


def load_reference_vtable_data(
    bindir: Path,
    gamever: str,
    class_name: str,
    platform: str,
    reference_modules: Sequence[str],
) -> Optional[Dict[str, Any]]:
    """
    Load reference YAML info for a class from modules in priority order.

    The first module that contains vtable/vfunc metadata is selected.
    """
    if yaml is None:
        raise RuntimeError("PyYAML is required to read reference YAML files")

    for module in reference_modules:
        module_dir = bindir / gamever / module
        if not module_dir.is_dir():
            continue

        pattern = f"{class_name}_*.{platform}.yaml"
        files = sorted(module_dir.glob(pattern))
        if not files:
            continue

        vtable_size: Optional[int] = None
        vtable_size_raw: Optional[str] = None
        vtable_numvfunc: Optional[int] = None
        reference_functions: Dict[int, Dict[str, str]] = {}
        matched_files: List[str] = []

        for path in files:
            try:
                with path.open("r", encoding="utf-8") as f:
                    payload = yaml.safe_load(f) or {}
            except Exception:
                continue

            if not isinstance(payload, dict):
                continue

            matched_files.append(str(path))

            if "vtable_size" in payload:
                parsed_size = _parse_int_maybe(payload.get("vtable_size"))
                if parsed_size is not None:
                    vtable_size = parsed_size
                    vtable_size_raw = str(payload.get("vtable_size"))
                parsed_numvfunc = _parse_int_maybe(payload.get("vtable_numvfunc"))
                if parsed_numvfunc is not None:
                    vtable_numvfunc = parsed_numvfunc

            parsed_index = _parse_int_maybe(payload.get("vfunc_index"))
            if parsed_index is None:
                continue

            func_name = payload.get("func_name")
            member_name = _normalize_reference_member_name(
                class_name=class_name,
                func_name=str(func_name) if func_name is not None else None,
                file_stem=path.stem,
            )
            reference_functions[parsed_index] = {
                "func_name": str(func_name) if func_name is not None else path.stem,
                "member_name": member_name,
                "path": str(path),
            }

        if vtable_size is not None or reference_functions:
            return {
                "module": module,
                "files": matched_files,
                "vtable_size": vtable_size,
                "vtable_size_raw": vtable_size_raw,
                "vtable_numvfunc": vtable_numvfunc,
                "functions_by_index": reference_functions,
            }

    return None


def compare_compiler_vtable_with_yaml(
    *,
    class_name: str,
    compiler_output: str,
    bindir: Path,
    gamever: str,
    platform: str,
    reference_modules: Sequence[str],
    pointer_size: int,
) -> Dict[str, Any]:
    """
    Compare compiler vtable layout dump against YAML references.

    Returns a structured report containing differences.
    """
    parsed_layouts = parse_vftable_layouts(compiler_output)
    compiler_section = parsed_layouts.get(class_name)
    reference = load_reference_vtable_data(
        bindir=bindir,
        gamever=gamever,
        class_name=class_name,
        platform=platform,
        reference_modules=reference_modules,
    )

    report: Dict[str, Any] = {
        "class_name": class_name,
        "platform": platform,
        "compiler_found": compiler_section is not None,
        "reference_found": reference is not None,
        "reference_module": reference["module"] if reference else None,
        "differences": [],
        "notes": [],
    }

    if compiler_section is None:
        report["notes"].append(
            f"No vtable section for class '{class_name}' found in compiler output."
        )
        return report

    compiler_entry_count = compiler_section["entry_count"]
    declared_entries = compiler_section["declared_entries"]
    methods_by_index = compiler_section["methods_by_index"]
    report["compiler_entry_count"] = compiler_entry_count
    report["compiler_declared_entries"] = declared_entries

    if declared_entries != compiler_entry_count:
        report["differences"].append(
            {
                "type": "compiler_declared_count_mismatch",
                "message": (
                    f"Compiler declares {declared_entries} vtable entries, "
                    f"but parsed {compiler_entry_count} entries."
                ),
            }
        )

    if reference is None:
        report["notes"].append(
            f"No matching reference YAML found for modules: {', '.join(reference_modules)}"
        )
        return report

    expected_size = reference.get("vtable_size")
    expected_numvfunc = reference.get("vtable_numvfunc")
    reference_functions = reference.get("functions_by_index", {})
    report["reference_vtable_size"] = expected_size
    report["reference_vtable_numvfunc"] = expected_numvfunc
    report["reference_functions_count"] = len(reference_functions)

    actual_size = compiler_entry_count * pointer_size
    report["compiler_vtable_size"] = actual_size

    if expected_size is not None and expected_size != actual_size:
        report["differences"].append(
            {
                "type": "vtable_size_mismatch",
                "message": (
                    f"vtable_size mismatch: YAML={hex(expected_size)} "
                    f"vs compiler={hex(actual_size)} (entry_count={compiler_entry_count}, "
                    f"ptr_size={pointer_size})."
                ),
            }
        )

    if expected_numvfunc is not None and expected_numvfunc != compiler_entry_count:
        report["differences"].append(
            {
                "type": "vtable_numvfunc_mismatch",
                "message": (
                    f"vtable_numvfunc mismatch: YAML={expected_numvfunc} "
                    f"vs compiler={compiler_entry_count}."
                ),
            }
        )

    for index in sorted(reference_functions.keys()):
        ref_item = reference_functions[index]
        compiled = methods_by_index.get(index)
        if compiled is None:
            report["differences"].append(
                {
                    "type": "vfunc_index_missing",
                    "message": (
                        f"Index {index} missing in compiler output "
                        f"(reference: {ref_item['func_name']}, file: {ref_item['path']})."
                    ),
                }
            )
            continue

        expected_member = ref_item.get("member_name", "")
        actual_member = compiled.get("member_name", "")
        if expected_member and actual_member and expected_member != actual_member:
            report["differences"].append(
                {
                    "type": "vfunc_name_mismatch",
                    "message": (
                        f"Index {index} mismatch: YAML expects '{expected_member}' "
                        f"but compiler reports '{actual_member}'."
                    ),
                }
            )

    if not report["differences"]:
        report["notes"].append(
            "No differences detected for vtable_size/vtable_numvfunc/vfunc_index mapping."
        )

    return report


def format_vtable_compare_report(report: Dict[str, Any]) -> List[str]:
    """Format a comparison report into human-readable lines."""
    lines: List[str] = []
    lines.append(
        f"Class '{report['class_name']}' compare target platform: {report.get('platform', 'unknown')}"
    )

    if not report.get("compiler_found"):
        lines.extend(report.get("notes", []))
        return lines

    compiler_count = report.get("compiler_entry_count")
    compiler_declared = report.get("compiler_declared_entries")
    lines.append(
        f"Compiler vtable entries: parsed={compiler_count}, declared={compiler_declared}"
    )

    if report.get("reference_found"):
        lines.append(
            f"Reference module: {report.get('reference_module')}, "
            f"reference functions: {report.get('reference_functions_count', 0)}"
        )
    else:
        lines.append("Reference module: not found")

    diffs = report.get("differences", [])
    if diffs:
        lines.append(f"Differences found: {len(diffs)}")
        for item in diffs:
            lines.append(f"- {item['message']}")
    else:
        for note in report.get("notes", []):
            lines.append(note)

    return lines
