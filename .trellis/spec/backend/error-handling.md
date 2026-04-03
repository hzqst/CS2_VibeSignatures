# Error Handling

> How errors are handled in this project's Python scripts.

---

## Overview

This project uses **simple, direct error handling** with `try/except` blocks. There are no custom exception classes. The pattern is: catch specific exceptions, print a human-readable message, and either continue gracefully or exit with a non-zero code.

---

## Error Handling Patterns

### Pattern 1: Import Guard at Module Load

Every CLI script guards its third-party imports at the top of the file. This is the **first thing** after stdlib imports.

```python
try:
    import yaml
    import requests
except ImportError as e:
    print(f"Error: Missing required dependency: {e.name}")
    print("Please install required dependencies with: uv sync")
    sys.exit(1)
```

**Rules:**
- Always catch `ImportError` specifically, not bare `except`.
- Always print the missing package name via `e.name`.
- Always suggest the fix: `uv sync`.
- Always `sys.exit(1)` — the script cannot function without dependencies.

### Pattern 2: Graceful Degradation on Non-Critical Failure

When a single operation fails but the pipeline can continue, print a warning and proceed.

```python
try:
    response = requests.get(url, timeout=120)
    response.raise_for_status()
except requests.exceptions.RequestException as e:
    print(f"  Warning: Failed to download {url}: {e}")
    return False
```

**Rules:**
- Use `Warning:` prefix (not `Error:`) for non-fatal issues.
- Return a failure indicator (`False`, `None`) to let the caller decide.
- Never silently swallow exceptions — always print something.

### Pattern 3: Exit on Critical Configuration Error

When the script cannot proceed without valid configuration, exit immediately.

```python
if not os.path.exists(config_path):
    print(f"Error: Configuration file not found: {config_path}")
    sys.exit(1)

with open(config_path, 'r') as f:
    config = yaml.safe_load(f)

if not config or "modules" not in config:
    print("Error: Invalid config.yaml — missing 'modules' key")
    sys.exit(1)
```

**Rules:**
- Check file existence before reading.
- Validate required structure after parsing.
- Use `Error:` prefix for fatal issues.
- `sys.exit(1)` after printing the error — never raise exceptions to the user.

### Pattern 4: Subprocess Timeout Handling

External processes (IDA MCP, agent CLI) have explicit timeouts.

```python
MCP_STARTUP_TIMEOUT = 1200  # seconds
SKILL_TIMEOUT = 1200        # 10 minutes per skill

try:
    result = await asyncio.wait_for(some_operation(), timeout=SKILL_TIMEOUT)
except asyncio.TimeoutError:
    print(f"  Error: Skill timed out after {SKILL_TIMEOUT}s")
```

**Rules:**
- Define timeout constants at module level with `UPPER_SNAKE_CASE`.
- Always handle `asyncio.TimeoutError` for async operations.
- Always handle `subprocess.TimeoutExpired` for subprocess calls.
- Print the timeout value in the error message so the user knows what to adjust.

### Pattern 5: Retry with Limited Attempts

Skills that interact with IDA MCP may fail transiently. The pipeline retries with a configurable limit.

```python
max_retries = skill.get("max_retries", 3)
for attempt in range(max_retries):
    success = await run_skill(...)
    if success:
        break
    print(f"  Retry {attempt + 1}/{max_retries}...")
```

**Rules:**
- Default retry count is 3, overridable per-skill in `config.yaml`.
- Print the attempt number so the user can see progress.
- After all retries exhausted, continue to the next skill (do not abort the entire pipeline).

---

## What NOT to Do

1. **Do not define custom exception classes** — the project uses standard Python exceptions. Adding custom exceptions adds complexity without benefit for CLI scripts.
2. **Do not use bare `except:`** — always catch specific exception types.
3. **Do not raise exceptions to the user** — print a message and `sys.exit(1)` for fatal errors, or return a failure indicator for non-fatal ones.
4. **Do not suppress errors silently** — every `except` block must print something.
5. **Do not use `logging` module for error output** — the project uses `print()` consistently (see Logging Guidelines).
