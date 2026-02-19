---
name: find-CBuildCubemapsGameSystem_ClientPostRender
description: |
  Find and identify CBuildCubemapsGameSystem_ClientPostRender function in CS2 client binary using IDA Pro MCP.
  CBuildCubemapsGameSystem_ClientPostRender is located via the "ICONGEN - Starting request for %s" string reference.
  It is a virtual function in the CBuildCubemapsGameSystem vtable.
  Trigger: CBuildCubemapsGameSystem_ClientPostRender, ClientPostRender, ICONGEN
disable-model-invocation: true
---

# CBuildCubemapsGameSystem_ClientPostRender Location Workflow

## Overview

Locate the virtual function `CBuildCubemapsGameSystem_ClientPostRender` in CS2 client binary.
This function references the string "ICONGEN - Starting request for %s" and is a virtual function in the CBuildCubemapsGameSystem vtable.

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the `Writing cubemaps to %s` string:

```
mcp__ida-pro-mcp__find_regex(pattern="Writing cubemaps to %s")
```

### 2. Find CBuildCubemapsGameSystem_ClientPostRender via Cross-References

Use `xrefs_to` on the string address to find the function that references it:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

The function referencing this string is `CBuildCubemapsGameSystem_ClientPostRender`.

### 3. Rename CBuildCubemapsGameSystem_ClientPostRender

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<ClientPostRender_addr>", "name": "CBuildCubemapsGameSystem_ClientPostRender"}})
```

### 4. Load CBuildCubemapsGameSystem VTable and Get VTable Index

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CBuildCubemapsGameSystem`

If the skill returns an error, **STOP** and report to user.

Find `CBuildCubemapsGameSystem_ClientPostRender` address in `vtable_entries` to determine `vfunc_index`.

### 5. Generate Signature

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CBuildCubemapsGameSystem_ClientPostRender`.

### 6. Write YAML Output

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for `CBuildCubemapsGameSystem_ClientPostRender`.

Required parameters:
- `func_name`: `CBuildCubemapsGameSystem_ClientPostRender`
- `func_addr`: The function address from step 2
- `func_sig`: The validated signature from step 5

VTable parameters:
- `vtable_name`: `CBuildCubemapsGameSystem`
- `vfunc_offset`: calculated from vfunc_index * 8
- `vfunc_index`: from step 4

## Function Characteristics

### CBuildCubemapsGameSystem_ClientPostRender

- Virtual function in CBuildCubemapsGameSystem vtable
- References the string `ICONGEN - Starting request for %s`
- Handles cubemap build icon generation during client post-render

## Output YAML Files

- `CBuildCubemapsGameSystem_ClientPostRender.windows.yaml` / `.linux.yaml`
