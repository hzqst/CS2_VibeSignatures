---
name: find-CCSItemIconGeneratorGameSystem_ClientUpdate
description: |
  Find and identify CCSItemIconGeneratorGameSystem_ClientUpdate function in CS2 client binary using IDA Pro MCP.
  CCSItemIconGeneratorGameSystem_ClientUpdate is located via the "ICONGEN - Starting request for %s" string reference.
  It is a virtual function in the CCSItemIconGeneratorGameSystem vtable.
  Trigger: CCSItemIconGeneratorGameSystem_ClientUpdate, ClientUpdate, ICONGEN
disable-model-invocation: true
---

# CCSItemIconGeneratorGameSystem_ClientUpdate Location Workflow

## Overview

Locate the virtual function `CCSItemIconGeneratorGameSystem_ClientUpdate` in CS2 client binary.
This function references the string "ICONGEN - Starting request for %s" and is a virtual function in the CCSItemIconGeneratorGameSystem vtable.

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the `ICONGEN - Starting request for %s` string:

```
mcp__ida-pro-mcp__find_regex(pattern="ICONGEN - Starting request for %s")
```

### 2. Find CCSItemIconGeneratorGameSystem_ClientUpdate via Cross-References

Use `xrefs_to` on the string address to find the function that references it:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

The function referencing this string is `CCSItemIconGeneratorGameSystem_ClientUpdate`.

### 3. Rename CCSItemIconGeneratorGameSystem_ClientUpdate

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<ClientUpdate_addr>", "name": "CCSItemIconGeneratorGameSystem_ClientUpdate"}})
```

### 4. Load CCSItemIconGeneratorGameSystem VTable and Get VTable Index

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CCSItemIconGeneratorGameSystem`

If the skill returns an error, **STOP** and report to user.

Find `CCSItemIconGeneratorGameSystem_ClientUpdate` address in `vtable_entries` to determine `vfunc_index`.

### 5. Generate Signature

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CCSItemIconGeneratorGameSystem_ClientUpdate`.

### 6. Write YAML Output

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for `CCSItemIconGeneratorGameSystem_ClientUpdate`.

Required parameters:
- `func_name`: `CCSItemIconGeneratorGameSystem_ClientUpdate`
- `func_addr`: The function address from step 2
- `func_sig`: The validated signature from step 5

VTable parameters:
- `vtable_name`: `CCSItemIconGeneratorGameSystem`
- `vfunc_offset`: calculated from vfunc_index * 8
- `vfunc_index`: from step 4

## Function Characteristics

### CCSItemIconGeneratorGameSystem_ClientUpdate

- Virtual function in CCSItemIconGeneratorGameSystem vtable
- References the string `ICONGEN - Starting request for %s`
- Handles icon generation request processing during client update

## Output YAML Files

- `CCSItemIconGeneratorGameSystem_ClientUpdate.windows.yaml` / `.linux.yaml`
