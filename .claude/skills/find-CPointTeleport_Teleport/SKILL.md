---
name: find-CPointTeleport_Teleport
description: |
  Find and identify the CPointTeleport_Teleport virtual function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the teleport handler function for point_teleport entities.
  Triggers: CPointTeleport_Teleport, point_teleport, teleport entity, can't teleport object
---

# CPointTeleport_Teleport Function Location Workflow

## Overview

Locate the `CPointTeleport_Teleport` virtual function in CS2 server binary. This function handles teleportation logic for `point_teleport` entities, including parent object validation and target resolution.

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the teleport error string:

```
mcp__ida-pro-mcp__find_regex(pattern="can't teleport object.*as it has a parent")
```

Expected result: Find string like `ERROR: (%s) can't teleport object (%s) as it has a parent (%s)!\n`

### 2. Find Cross-References

Use `xrefs_to` to find locations that reference this string:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

Expected result: Find 1-2 functions referencing the string. The smaller function (~0x1d0 bytes) is `CPointTeleport_Teleport`.

### 3. Rename Function

Use `rename` to give the function a meaningful name:

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<function_addr>", "name": "CPointTeleport_Teleport"}})
```

### 4. Get VTable Information

- **ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CPointTeleport`.

  If the skill returns an error, **STOP** and report to user.

  Otherwise, extract these values for subsequent steps:
  - `vtable_va`: The vtable start address (use as `<VTABLE_START>`)
  - `vtable_numvfunc`: The valid vtable entry count (last valid index = count - 1)
  - `vtable_entries`: An array of virtual functions starting from vtable[0]

### 5. Find VTable Index

- **ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.

  VTable class name: `CPointTeleport`

### 6. Generate and Validate Unique Signature

- **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CPointTeleport_Teleport`.

### 7. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results of `CPointTeleport_Teleport`.

Required parameters:
- `func_name`: `CPointTeleport_Teleport`
- `func_addr`: The function address from step 2
- `func_sig`: The validated signature from step 6

VTable parameters:
- `vtable_name`: `CPointTeleport`
- `vfunc_offset`: The offset from step 5
- `vfunc_index`: The index from step 5

## Function Characteristics

The `CPointTeleport_Teleport` function contains:

- Error string: `ERROR: (%s) can't teleport object (%s) as it has a parent (%s)!\n`
- Error string: `ERROR: (%s) target '%s' not found. Deleting.\n`
- Position/rotation data handling via helper functions
- Parent object validation logic
- Target entity resolution

## VTable Information

- **VTable Name**: `CPointTeleport`
- **VTable Mangled Name**:
  - Windows: `??_7CPointTeleport@@6B@`
  - Linux: `_ZTV15CPointTeleport`
- **VTable Offset**: `0x60` (may change with game updates)
- **VTable Index**: `12` (may change with game updates)

## Output YAML Format

The output YAML filename of CPointTeleport_Teleport depends on the platform:
- `server.dll` → `CPointTeleport_Teleport.windows.yaml`
- `server.so` / `libserver.so` → `CPointTeleport_Teleport.linux.yaml`