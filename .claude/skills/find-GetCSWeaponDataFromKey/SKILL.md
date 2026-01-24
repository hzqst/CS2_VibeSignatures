---
name: find-GetCSWeaponDataFromKey
description: |
  IDA Pro string analysis and function reverse engineering workflow. Connect to IDA Pro via ida-pro-mcp for binary analysis to locate the GetCSWeaponDataFromKey function.
  Use cases:
  (1) Search for specific strings in binary files
  (2) Find cross-references (xrefs) to strings
  (3) Decompile functions that reference strings and view pseudocode
  (4) Locate specific code segments in pseudocode
  (5) Rename functions and variables to improve readability
  (6) Analyze function call relationships and data flow
  Trigger: GetCSWeaponDataFromKey
---

# IDA Pro String Analysis Workflow

## Prerequisites

- IDA Pro has the target binary file open
- ida-pro-mcp service is connected

## Workflow

### 1. Search for Strings

Use `mcp__ida-pro-mcp__find_regex` to search for target strings:

```
find_regex(pattern="target_string")
```

Results include matching strings and their addresses. Select the exact match from the results.

### 2. Find Cross-References

Use `mcp__ida-pro-mcp__xrefs_to` to find all references to a string:

```
xrefs_to(addrs="0xADDRESS")
```

Returns all locations that reference the string, including:
- Reference address
- Reference type (data/code)
- Containing function name and address

### 3. Decompile Function

Use `mcp__ida-pro-mcp__decompile` to get pseudocode:

```
decompile(addr="0xFUNC_ADDR")
```

Comments at the end of each line in pseudocode `/*0xXXXXXX*/` indicate the corresponding address.

### 4. Locate Code Segments

When searching for target code in pseudocode:
- Use address comments `/*0xXXXXXX*/` for precise location
- Focus on function call parameter types and values
- Identify key conditional branches and data flow

### 5. Rename Functions/Variables

Use `mcp__ida-pro-mcp__rename` for renaming:

**Rename function:**
```
rename(batch={"func": {"addr": "0xADDR", "name": "NewFuncName"}})
```

**Rename local variable:**
```
rename(batch={"local": {"func_addr": "0xFUNC", "old": "v1", "new": "newName"}})
```

**Rename global variable:**
```
rename(batch={"data": {"old": "dword_XXX", "new": "g_newName"}})
```

## Quick Reference

| Task | Tool | Key Parameters |
|------|------|----------------|
| Search strings | `find_regex` | pattern |
| Search bytes | `find_bytes` | patterns (supports ?? wildcards) |
| Cross-references | `xrefs_to` | addrs |
| Decompile | `decompile` | addr |
| Disassemble | `disasm` | addr |
| List functions | `list_funcs` | filter, count, offset |
| Call graph | `callgraph` | roots, max_depth |
| Called functions | `callees` | addrs |
| Rename | `rename` | batch |
| Set type | `set_type` | edits |
| Add comments | `set_comments` | items |

## Analysis Tips

### Identifying String Usage

Common string purposes:
- Entity class names (e.g., `smokegrenade_projectile`)
- Source file paths (e.g., `../../game/shared/xxx.cpp`)
- Debug information and error messages
- Configuration key names

### Function Parameter Analysis

Focus on:
- Which parameter position the string is passed as
- How the return value is used
- Conditional branch logic

### Offset Analysis

Offsets in pseudocode (e.g., `*(v11 + 3584)`) typically correspond to structure fields. Use `set_type` to apply structure definitions.
