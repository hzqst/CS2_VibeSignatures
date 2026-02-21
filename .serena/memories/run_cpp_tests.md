# run_cpp_tests

## Overview
`run_cpp_tests.py` is a C++ compile-test driver based on `config.yaml`: it first probes clang target-triple support, then runs runnable test items, and when `-fdump-vtable-layouts` is enabled, compares compiler vtable output against YAML references.

## Responsibilities
- Parse CLI arguments (config path, bin dir, game version, clang path, C++ standard, debug flag).
- Load and validate the `cpp_tests` list in `config.yaml`.
- Detect clang default target triple and probe support for configured target triples.
- Execute only tests whose target triples are supported; classify invalid and compile-failed items.
- Build clang compile commands per test item (includes, defines, additional compiler options).
- Run vtable comparison when conditions are met and print formatted reports.
- Print final summary and return process exit code (`1` on failures, `0` on success).

## Involved Files (no line numbers)
- run_cpp_tests.py
- cpp_tests_util.py
- config.yaml
- bin/<gamever>/*.yaml

## Architecture
Core flow (function call chain):
- `main`
  - `parse_args`
  - `parse_config`
  - `get_default_target_triple`
  - `probe_target_support` (per target)
  - `run_one_test` (per runnable test)
    - `_to_list` / `_contains_fdump_vtable_layouts`
    - `build_compile_command`
    - (conditional) `map_target_triple_to_platform` + `pointer_size_from_target_triple` + `compare_compiler_vtable_with_yaml`
  - `format_vtable_compare_report` (print compare output)

Data-flow highlights:
- Input: `cpp_tests` from `config.yaml`, local clang environment, and reference YAML files under `bin/<gamever>`.
- Intermediate: each test uses its own temporary directory and object file; compile command and compiler output are collected.
- Output: terminal logs (probe/run/compare/summary) and process exit code.

## Dependencies
- Python stdlib: `argparse`, `subprocess`, `tempfile`, `pathlib`, `typing`, `sys`.
- Third-party: `PyYAML` (missing dependency causes immediate error and exit).
- External tool: `clang++` (must support `-print-target-triple` and target compilation).
- Internal module: `cpp_tests_util` (platform mapping, pointer-size inference, vtable compare, report formatting).
- Config/resources: `config.yaml` and reference YAML data under `bin/<gamever>`.

## Notes
- Vtable comparison runs only when additional options contain `fdump-vtable-layouts` (with or without a leading `-`). Otherwise it acts as compile-only validation.
- Test items with unsupported target triples are skipped (counted as skipped), not treated as failures.
- Missing required fields (`symbol/cpp/target`) or missing cpp file marks the item as `invalid` and contributes to final failure exit code.
- If a target triple cannot be mapped to a YAML platform, compile can still pass; compare is skipped with an explanatory note.
- Both option field names are supported: `additional_compiler_options` and `additional_compile_options`.
- Front-loaded failures (e.g., config parse errors, clang probe errors) call `sys.exit(1)`, so this script is CLI-oriented rather than library-oriented.

## Callers (optional)
- CLI entrypoint: `python run_cpp_tests.py ...` via `if __name__ == "__main__": sys.exit(main())`.