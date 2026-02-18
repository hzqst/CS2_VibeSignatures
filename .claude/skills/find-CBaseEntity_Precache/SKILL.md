---
name: find-CBaseEntity_Precache
description: |
  IDA Pro string analysis and function reverse engineering workflow. Connect to IDA Pro via ida-pro-mcp for binary analysis to locate the CBaseEntity_Precache function.
  Use cases:
  (1) Search for specific strings in binary files
  (2) Find cross-references (xrefs) to strings
  (3) Decompile functions that reference strings and view pseudocode
  (4) Locate specific code segments in pseudocode
  (5) Rename functions and variables to improve readability
  (6) Analyze function call relationships and data flow
  Trigger: CBaseEntity_Precache
disable-model-invocation: true
---

# CBaseEntity_Precache Function Location Workflow

## Overview

This workflow is used to locate the `CBaseEntity_Precache` function in CS2 server binary files. This function is a virtual function on `CBaseEntity` responsible for precaching resources. It can be identified by finding a small wrapper function that calls it with the `"bloodspray"` string argument.

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the `bloodspray` string:

```
mcp__ida-pro-mcp__find_regex(pattern="bloodspray")
```

Expected result: Find string address (e.g., `0x18170ac18` for Windows, varies by version)

### 2. Find Cross-References

Use `xrefs_to` to find locations that reference this string:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

Expected result: Find multiple functions referencing the string. Look for the **smallest** function (size ~0x19) — this is the wrapper that calls `CBaseEntity_Precache`.

### 3. Decompile the Small Wrapper

Decompile the small wrapper function to identify the `CBaseEntity_Precache` call:

```
mcp__ida-pro-mcp__decompile(addr="<small_wrapper_addr>")
```

Expected pseudocode pattern:
```c
__int64 __fastcall sub_XXXXXXXX(__int64 a1, __int64 *a2)
{
  sub_YYYYYYYY(a1, a2);       // <-- This is CBaseEntity_Precache
  return sub_ZZZZZZZZ("bloodspray");
}
```

The first call (`sub_YYYYYYYY`) that takes `(a1, a2)` as arguments is `CBaseEntity_Precache`.

### 4. Rename Function

Use `rename` to give the function a meaningful name:

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<CBaseEntity_Precache_addr>", "name": "CBaseEntity_Precache"}})
```

### 5. Find VTable and Calculate Offset

  **ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.

  VTable class name: `CBaseEntity`

### 6. Generate and Validate Unique Signature

  **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CBaseEntity_Precache`.

### 7. Write IDA analysis output as YAML beside the binary

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CBaseEntity_Precache`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 6

VTable parameters:
- `vtable_name`: `CBaseEntity`
- `vfunc_offset`: The offset from step 5
- `vfunc_index`: The index from step 5

## Function Characteristics

The `CBaseEntity_Precache` function is identified indirectly through a small wrapper function that:
1. Calls `CBaseEntity_Precache(a1, a2)` as its first statement
2. Then calls another function with the `"bloodspray"` string literal

Key identification points:
- `bloodspray` - The string used in the wrapper to locate `CBaseEntity_Precache`
- The wrapper function is very small (~0x19 bytes)
- `CBaseEntity_Precache` itself is a larger function (~0x1B1 bytes on Windows)

## VTable Information

- **VTable Name**: `CBaseEntity`
- **VTable Mangled Name**:
  - Windows: `??_7CBaseEntity@@6B@`
  - Linux: `_ZTV11CBaseEntity`
- **VTable Offset**: `0x30` (may change with game updates)
- **VTable Index**: `6` (may change with game updates)

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBaseEntity_Precache.windows.yaml`
- `server.so` / `libserver.so` → `CBaseEntity_Precache.linux.yaml`
