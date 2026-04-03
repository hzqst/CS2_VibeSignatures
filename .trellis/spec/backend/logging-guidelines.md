# Logging Guidelines

> How output and diagnostic information is communicated in this project.

---

## Overview

This project uses **`print()` exclusively** for all output. There is no `logging` module, no structured logging, and no log files. Output goes to stdout/stderr and is designed to be read by a human watching the terminal.

---

## Output Levels via Indentation

The project uses a consistent **indentation-based hierarchy** to communicate operation depth:

| Level | Indent | Usage | Example |
|-------|--------|-------|---------|
| Top-level | None | Major operations, configuration summary | `Config file: config.yaml` |
| Module/step | 2 spaces | Per-module or per-step operations | `  Downloading: engine2.dll` |
| Detail | 4 spaces | Sub-operations within a step | `    Preprocess: find-CNetworkGameServer_vtable` |
| Deep detail | 6 spaces | Rarely used, for nested sub-operations | `      Reusing old signature from 14141b` |

### Examples from the Codebase

```python
# Top-level: summarize the run
print(f"Config file: {config_path}")
print(f"Found {len(modules)} enabled modules")

# Module-level: one per module being processed
print(f"  Downloading: {module_name}")
print(f"  Analyzing module: {module_name} ({platform})")

# Detail-level: one per skill or sub-operation
print(f"    Skill: {skill_name}")
print(f"    Preprocess: {skill_name} -> skip (all outputs exist)")

# Status summary
print(f"  Updated: {updated}, Skipped: {skipped}, Missing: {missing}")
```

---

## Message Prefixes

| Prefix | Meaning | Action Required |
|--------|---------|-----------------|
| `Error:` | Fatal — script cannot continue | Script will `sys.exit(1)` |
| `Warning:` | Non-fatal — operation failed but pipeline continues | Human should review |
| (no prefix) | Informational — normal progress | No action needed |

```python
print(f"Error: Configuration file not found: {config_path}")     # Fatal
print(f"  Warning: Failed to download {url}: {e}")               # Non-fatal
print(f"  Analyzing module: {module_name}")                       # Informational
```

---

## Debug Output

Debug output is controlled by a `-debug` CLI flag and a `debug` parameter passed through function calls.

```python
if debug:
    print(f"    Debug: MCP response: {response}")
    print(f"    Debug: Resolved skill order: {sorted_skills}")
```

**Rules:**
- Debug messages use `Debug:` prefix.
- Debug messages follow the same indentation hierarchy.
- Never print debug output without checking the `debug` flag.
- Debug output can be verbose — hex dumps, full responses, intermediate state.

---

## Summary Lines

At the end of a batch operation, print a single summary line with counts:

```python
print(f"  Updated: {updated}, Skipped: {skipped}, Missing: {missing}")
print(f"Analysis complete: {success_count}/{total_count} skills succeeded")
```

---

## What NOT to Do

1. **Do not use the `logging` module** — the project uses `print()` consistently. Introducing `logging` would create inconsistency.
2. **Do not use `\t` for indentation** — use spaces (2-space increments).
3. **Do not print without context** — always include what operation is being performed, not just "Done" or "Failed".
4. **Do not add timestamps** — the terminal provides sufficient context; timestamps add noise for interactive CLI usage.
5. **Do not use color codes or ANSI escapes** — keep output plain for compatibility with piping and log capture.
