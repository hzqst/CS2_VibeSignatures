# Quality Guidelines

> Code quality standards and validation practices for this project.

---

## Overview

This project prioritizes **correctness of binary analysis output** above all else. A wrong signature means a game mod crashes at runtime. Quality standards revolve around ensuring signatures are accurate, reproducible, and properly validated.

---

## Code Standards

### Python Style

- Python 3.10+ syntax is expected.
- Use `argparse` for all CLI scripts — not `sys.argv` manual parsing.
- Use `pathlib.Path` for path manipulation when convenient, but `os.path` is also acceptable.
- Use `yaml.safe_load` / `yaml.safe_dump` exclusively — never `yaml.load` (security risk).
- Use type hints for function signatures in utility modules. CLI scripts may omit them.
- Docstrings: Required for all public functions in utility modules. Use Google-style format.

```python
def convert_sig_to_css(sig):
    """
    Convert YAML signature to CounterStrikeSharp format.

    YAML: "48 89 5C 24 ?? 48 8B D9"
    CSS:  "48 89 5C 24 ? 48 8B D9"

    Args:
        sig: Signature string from YAML

    Returns:
        Converted signature string
    """
    return sig.replace("??", "?")
```

### Async Conventions

- Use `async/await` for MCP communication and any I/O-bound operations interacting with IDA.
- Use `httpx.AsyncClient` (not `requests`) for async HTTP.
- Always set explicit timeouts on async operations.

### Constants

- Define at module level with `UPPER_SNAKE_CASE`.
- Group related constants together with a comment.

```python
DEFAULT_CONFIG_FILE = "config.yaml"
DEFAULT_BIN_DIR = "bin"
DEFAULT_PLATFORM = "windows,linux"

MCP_STARTUP_TIMEOUT = 1200  # seconds
SKILL_TIMEOUT = 1200        # 10 minutes per skill
```

---

## Forbidden Patterns

| Pattern | Why It Is Forbidden |
|---------|-------------------|
| `yaml.load()` without `Loader` | Security risk — arbitrary code execution |
| Bare `except:` | Masks errors, makes debugging impossible |
| Hardcoded game version paths | Use `{gamever}` and `{platform}` placeholders |
| `sort_keys=True` in `yaml.safe_dump` | Destroys intended field order in output YAML |
| Mutable default arguments | Standard Python footgun |
| `requests` in async code | Use `httpx.AsyncClient` for async contexts |

---

## Required Patterns

| Pattern | Where |
|---------|-------|
| Import guard with `uv sync` hint | Top of every CLI script |
| `yaml.safe_dump(data, default_flow_style=False, sort_keys=False)` | All YAML output |
| Hex values as quoted strings | All YAML output: `'0x8e9750'` not `0x8e9750` |
| `{platform}` placeholder in config paths | `config.yaml` expected_output/expected_input |
| Topological sort for skill ordering | `ida_analyze_bin.py` — never hardcode execution order |

---

## Signature Validation Rules

Signatures are the core output of this project. They must meet these criteria:

1. **Format**: Uppercase hex bytes separated by single spaces. Wildcards are `??`.
   - Correct: `48 89 5C 24 ?? 48 8B D9`
   - Wrong: `48 89 5c 24 ?? 48 8b d9` (lowercase)
   - Wrong: `488954C24??488BD9` (no spaces)
   - Wrong: `48 89 5C 24 ? 48 8B D9` (single `?` — that is CSS format, not YAML)

2. **Uniqueness**: A signature must uniquely identify a single function in the binary. If the signature matches multiple locations, it is invalid.

3. **Stability**: Prefer signatures from the function prologue (first bytes). These are less likely to change between game updates.

4. **Length**: Signatures should be long enough to be unique but not unnecessarily long. Typically 20-60 bytes.

---

## Testing

### C++ Header Validation (`run_cpp_tests.py`)

The project validates C++ headers by compiling them with clang and comparing vtable layouts against YAML reference data:

1. Compile headers with `clang++ -fdump-vtable-layouts`.
2. Parse the vtable layout from compiler output.
3. Compare against vtable YAML files in `bin/`.
4. If mismatches are found, invoke the `vtable-fixer` agent for automated correction.

### Gamedata Validation

`update_gamedata.py` prints summary statistics after each run:
- `Updated: N` — signatures that were written or changed.
- `Skipped: N` — signatures that were unchanged.
- `Missing: N` — symbols defined in config but not found in YAML.

A high `Missing` count indicates analysis failures that need investigation.

---

## Preprocessor Script Standards

Each preprocessor script in `ida_preprocessor_scripts/` must:

1. Export a single async function: `preprocess_skill(session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False)`.
2. Return a list of preprocessed outputs or `None` on failure.
3. Use `preprocess_common_skill()` from `ida_analyze_util` for standard function/vtable lookups.
4. Only implement custom logic if the standard helper is insufficient.

```python
# Minimal preprocessor script pattern
from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CBaseEntity_Use"]

async def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map,
                          new_binary_dir, platform, image_base, debug=False):
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        debug=debug,
    )
```

---

## Gamedata Module Standards

Each gamedata module in `dist/{framework}/gamedata.py` must:

1. Export an `update()` function matching the expected interface.
2. Handle missing symbols gracefully (skip, do not crash).
3. Use converter functions from `gamedata_utils.py` for signature format conversion — never do inline conversion.
4. Preserve existing file content that is not managed by this project (e.g., manually added entries).
