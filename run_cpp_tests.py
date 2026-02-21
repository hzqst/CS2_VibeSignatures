#!/usr/bin/env python3
"""
Run C++ tests declared in config.yaml and compare clang vtable dumps with YAML references.
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Sequence

try:
    import yaml
except ImportError as e:
    print(f"Error: Missing required dependency: {e.name}")
    print("Please install required packages: pip install pyyaml")
    sys.exit(1)

from cpp_tests_util import (
    compare_compiler_vtable_with_yaml,
    format_vtable_compare_report,
    map_target_triple_to_platform,
    pointer_size_from_target_triple,
)


DEFAULT_CONFIG_FILE = "config.yaml"
DEFAULT_BIN_DIR = "bin"
DEFAULT_CLANG = "clang++"
DEFAULT_CPP_STD = "c++20"


def parse_args():
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Run configured C++ tests with clang++ and compare vtable metadata"
    )
    parser.add_argument(
        "-configyaml",
        default=DEFAULT_CONFIG_FILE,
        help=f"Path to config.yaml file (default: {DEFAULT_CONFIG_FILE})",
    )
    parser.add_argument(
        "-bindir",
        default=DEFAULT_BIN_DIR,
        help=f"Directory containing YAML outputs (default: {DEFAULT_BIN_DIR})",
    )
    parser.add_argument(
        "-gamever",
        required=True,
        help="Game version subdirectory name under bin (required)",
    )
    parser.add_argument(
        "-clang",
        default=DEFAULT_CLANG,
        help=f"clang++ executable path (default: {DEFAULT_CLANG})",
    )
    parser.add_argument(
        "-std",
        default=DEFAULT_CPP_STD,
        help=f"C++ standard for compilation (default: {DEFAULT_CPP_STD})",
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="Enable debug output",
    )
    return parser.parse_args()


def _to_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    return [str(value).strip()]


def _normalize_option(option_text: str) -> str:
    option_text = option_text.strip()
    if not option_text:
        return ""
    if option_text.startswith("-"):
        return option_text
    return f"-{option_text}"


def _contains_fdump_vtable_layouts(options: Sequence[str]) -> bool:
    for option in options:
        normalized = _normalize_option(option)
        if normalized and normalized.lstrip("-") == "fdump-vtable-layouts":
            return True
    return False


def _format_command(command: Sequence[str]) -> str:
    return subprocess.list2cmdline(list(command))


def _collect_process_output(result: subprocess.CompletedProcess) -> str:
    stdout_text = result.stdout.strip() if result.stdout else ""
    stderr_text = result.stderr.strip() if result.stderr else ""

    if stdout_text and stderr_text:
        return f"{stdout_text}\n{stderr_text}"
    if stdout_text:
        return stdout_text
    return stderr_text


def parse_config(config_path: Path) -> List[Dict[str, Any]]:
    """Load and validate cpp_tests from config.yaml."""
    try:
        with config_path.open("r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)
    except Exception as exc:
        print(f"Error: Failed to parse config file {config_path}: {exc}")
        sys.exit(1)

    cpp_tests = config.get("cpp_tests", [])
    if not isinstance(cpp_tests, list):
        print("Error: 'cpp_tests' in config.yaml must be a list")
        sys.exit(1)

    return cpp_tests


def get_default_target_triple(clang: str) -> str:
    """Run clang++ -print-target-triple and return the result."""
    command = [clang, "-print-target-triple"]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        output = _collect_process_output(result)
        print(f"Error: Failed to run `{_format_command(command)}`")
        if output:
            print(output)
        sys.exit(1)

    triple = (result.stdout or "").strip()
    if not triple:
        triple = (result.stderr or "").strip()
    if not triple:
        print("Error: clang++ -print-target-triple returned empty output")
        sys.exit(1)
    return triple


def probe_target_support(clang: str, target: str, cpp_std: str) -> Dict[str, Any]:
    """Probe whether clang can compile a minimal source with the given target triple."""
    with tempfile.TemporaryDirectory(prefix="cpp_target_probe_") as temp_dir:
        temp_dir_path = Path(temp_dir)
        source_file = temp_dir_path / "probe.cpp"
        object_file = temp_dir_path / "probe.o"
        source_file.write_text("int main() { return 0; }\n", encoding="utf-8")

        command = [
            clang,
            f"--target={target}",
            f"-std={cpp_std}",
            "-c",
            str(source_file),
            "-o",
            str(object_file),
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

    return {
        "target": target,
        "supported": result.returncode == 0,
        "command": command,
        "output": _collect_process_output(result),
    }


def build_compile_command(
    *,
    clang: str,
    cpp_std: str,
    target: str,
    cpp_file: Path,
    object_file: Path,
    include_directories: Sequence[Path],
    defines: Sequence[str],
    additional_options: Sequence[str],
) -> List[str]:
    """Construct clang++ compile command for one cpp test item."""
    command = [
        clang,
        f"--target={target}",
        f"-std={cpp_std}",
        "-c",
        str(cpp_file),
        "-o",
        str(object_file),
    ]

    for include_dir in include_directories:
        command.extend(["-I", str(include_dir)])

    for define in defines:
        command.append(f"-D{define}")

    for option in additional_options:
        normalized_option = _normalize_option(option)
        if normalized_option:
            command.append(normalized_option)

    return command


def run_one_test(
    *,
    test_item: Dict[str, Any],
    args: argparse.Namespace,
    config_dir: Path,
    bindir: Path,
) -> Dict[str, Any]:
    """Compile and (optionally) compare one cpp test item."""
    test_name = str(test_item.get("name", "unnamed_test"))
    symbol = str(test_item.get("symbol", "")).strip()
    cpp_rel_path = str(test_item.get("cpp", "")).strip()
    target = str(test_item.get("target", "")).strip()

    if not symbol or not cpp_rel_path or not target:
        return {
            "name": test_name,
            "status": "invalid",
            "message": "Missing required fields: symbol/cpp/target",
        }

    cpp_file = Path(cpp_rel_path)
    if not cpp_file.is_absolute():
        cpp_file = (config_dir / cpp_file).resolve()

    if not cpp_file.is_file():
        return {
            "name": test_name,
            "status": "invalid",
            "message": f"CPP file not found: {cpp_file}",
        }

    include_directories: List[Path] = []
    for include_rel in _to_list(test_item.get("include_directories")):
        include_path = Path(include_rel)
        if not include_path.is_absolute():
            include_path = (config_dir / include_path).resolve()
        include_directories.append(include_path)

    defines = _to_list(test_item.get("defines"))

    additional_options = _to_list(test_item.get("additional_compiler_options"))
    if not additional_options:
        # Keep compatibility with alternate field naming.
        additional_options = _to_list(test_item.get("additional_compile_options"))

    should_parse_vtable = _contains_fdump_vtable_layouts(additional_options)

    with tempfile.TemporaryDirectory(prefix=f"cpp_test_{test_name}_") as temp_dir:
        temp_dir_path = Path(temp_dir)
        object_file = temp_dir_path / f"{test_name}.o"
        command = build_compile_command(
            clang=args.clang,
            cpp_std=args.std,
            target=target,
            cpp_file=cpp_file,
            object_file=object_file,
            include_directories=include_directories,
            defines=defines,
            additional_options=additional_options,
        )
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

    compile_output = _collect_process_output(result)
    if result.returncode != 0:
        return {
            "name": test_name,
            "status": "compile_failed",
            "command": command,
            "output": compile_output,
        }

    compare_report = None
    if should_parse_vtable:
        platform = map_target_triple_to_platform(target)
        if platform is None:
            compare_report = {
                "class_name": symbol,
                "platform": "unknown",
                "compiler_found": False,
                "reference_found": False,
                "differences": [],
                "notes": [
                    f"Cannot map target triple '{target}' to yaml platform; vtable compare skipped."
                ],
            }
        else:
            reference_modules = _to_list(test_item.get("reference_modules"))
            compare_report = compare_compiler_vtable_with_yaml(
                class_name=symbol,
                compiler_output=compile_output,
                bindir=bindir,
                gamever=args.gamever,
                platform=platform,
                reference_modules=reference_modules,
                pointer_size=pointer_size_from_target_triple(target),
            )

    return {
        "name": test_name,
        "status": "ok",
        "command": command,
        "output": compile_output,
        "compare_report": compare_report,
    }


def main():
    args = parse_args()
    config_path = Path(args.configyaml).resolve()
    config_dir = config_path.parent
    bindir = Path(args.bindir).resolve()

    cpp_tests = parse_config(config_path)
    if not cpp_tests:
        print("No cpp_tests defined in config.yaml")
        return 0

    print("=== clang++ target triple detection ===")
    default_target_triple = get_default_target_triple(args.clang)
    print(f"clang++ -print-target-triple => {default_target_triple}")

    configured_targets = sorted(
        {
            str(item.get("target", "")).strip()
            for item in cpp_tests
            if str(item.get("target", "")).strip()
        }
    )

    if not configured_targets:
        print("No target triples found in cpp_tests config")
        return 1

    print("=== target support probe (from configured targets) ===")
    target_support: Dict[str, bool] = {}
    for target in configured_targets:
        probe = probe_target_support(args.clang, target, args.std)
        target_support[target] = bool(probe["supported"])
        status_text = "SUPPORTED" if probe["supported"] else "UNSUPPORTED"
        print(f"[{status_text}] {target}")
        if args.debug and probe["output"]:
            print(probe["output"])

    runnable_tests = []
    skipped_tests = []
    for test_item in cpp_tests:
        target = str(test_item.get("target", "")).strip()
        if target and target_support.get(target):
            runnable_tests.append(test_item)
        else:
            skipped_tests.append(test_item)

    print("=== test selection summary ===")
    print(f"Total tests in config: {len(cpp_tests)}")
    print(f"Runnable tests: {len(runnable_tests)}")
    print(f"Skipped tests (unsupported target): {len(skipped_tests)}")
    for skipped in skipped_tests:
        print(
            f"- skip: {skipped.get('name', 'unnamed_test')} "
            f"(target={skipped.get('target', '')})"
        )

    if not runnable_tests:
        print("No runnable tests for current clang++ environment.")
        return 0

    print("=== running cpp_tests ===")
    compile_failed_count = 0
    invalid_count = 0
    compare_diff_count = 0
    compare_run_count = 0

    for test_item in runnable_tests:
        test_name = str(test_item.get("name", "unnamed_test"))
        print(f"[RUN ] {test_name}")

        result = run_one_test(
            test_item=test_item,
            args=args,
            config_dir=config_dir,
            bindir=bindir,
        )

        if result["status"] == "invalid":
            invalid_count += 1
            print(f"[FAIL] {test_name}: {result['message']}")
            continue

        if result["status"] == "compile_failed":
            compile_failed_count += 1
            print(f"[FAIL] {test_name}: compile failed")
            if args.debug:
                print(f"Command: {_format_command(result['command'])}")
            if result.get("output"):
                print(result["output"])
            continue

        print(f"[PASS] {test_name}: compile succeeded")
        if args.debug:
            print(f"Command: {_format_command(result['command'])}")

        compare_report = result.get("compare_report")
        if compare_report is not None:
            compare_run_count += 1
            lines = format_vtable_compare_report(compare_report)
            for line in lines:
                print(f"  {line}")
            if compare_report.get("differences"):
                compare_diff_count += 1
        elif args.debug and result.get("output"):
            print("  (Compiler output)")
            print(result["output"])

    print("=== done ===")
    print(f"Compile failures: {compile_failed_count}")
    print(f"Invalid test items: {invalid_count}")
    print(f"VTable compares run: {compare_run_count}")
    print(f"VTable compares with differences: {compare_diff_count}")

    if compile_failed_count > 0 or invalid_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
