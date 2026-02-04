---
name: find-CBaseEntity_SetStateChanged
description: |
  Find and identify the CBaseEntity_SetStateChanged virtual function in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 server.dll or server.so to locate the SetStateChanged function,
  which handles network state change notifications for entities.
  Trigger: CBaseEntity_SetStateChanged, SetStateChanged, NetworkStateChanged callback, state change handler
---

# CBaseEntity_SetStateChanged Function Location Workflow

## Overview

Locate the `CBaseEntity::SetStateChanged` virtual function in CS2 server binary. This function handles network state change notifications and is called when entity properties are modified and need to be synchronized across the network.

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the `CNetworkTransmitComponent::StateChanged` string:

```
mcp__ida-pro-mcp__find_regex(pattern="CNetworkTransmitComponent::StateChanged\\(%s\\)")
```

Expected result: Find string address containing `CNetworkTransmitComponent::StateChanged(%s) @%s:%d`

### 2. Find Cross-References

Use `xrefs_to` to find locations that reference this string:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

Expected result: Find the function that references the string

### 3. Rename Function

Use `rename` to give the function a meaningful name:

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<function_addr>", "name": "CBaseEntity_SetStateChanged"}})
```

### 4. Find VTable Index for CBaseEntity_SetStateChanged

**ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function `CBaseEntity_SetStateChanged`.

VTable class name: `CBaseEntity`

### 5. Generate and Validate Unique Signature for CBaseEntity_SetStateChanged

**DO NOT** use `find_bytes` as it won't work for function.
**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 7. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for `CBaseEntity_SetStateChanged`.

Required parameters:
- `func_name`: `CBaseEntity_SetStateChanged`
- `func_addr`: The function address from step 2
- `func_sig`: The validated signature from step 6

VTable parameters:
- `vtable_name`: `CBaseEntity`
- `vfunc_offset`: The offset from step 5
- `vfunc_index`: The index from step 5

## Function Characteristics

The `CBaseEntity::SetStateChanged` function contains the following signature string:

- `CNetworkTransmitComponent::StateChanged(%s) @%s:%d` - Debug logging for state changes

### Function Behavior

1. If the first parameter's DWORD value is non-zero, calls a sub-function with adjusted `this` pointer
2. Otherwise, checks entity flags and logs state change information
3. Updates internal state tracking fields

## VTable Information

- **VTable Name**: `CBaseEntity`
- **VTable Mangled Name**:
  - Windows: `??_7CBaseEntity@@6B@`
  - Linux: `_ZTV11CBaseEntity`
- **VTable Offset**: `0xD8` (may change with game updates)
- **VTable Index**: `27` (may change with game updates)

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBaseEntity_SetStateChanged.windows.yaml`
- `server.so` / `libserver.so` → `CBaseEntity_SetStateChanged.linux.yaml`

```yaml
func_va: 0x180168DC0     # Virtual address - changes with game updates
func_rva: 0x168DC0       # Relative virtual address (VA - image base) - changes with game updates
func_size: 0x142         # Function size in bytes - changes with game updates
func_sig: 48 8B C4 56 48 81 EC 40 01 00 00 83 3A 00 48 8B F1 48 89 68 10 48 8B EA 48 89 78 18 74 ?? 4C 8B C2 48 8B D1 48 83 C1 40 E8 ?? ?? ?? ??
vtable_name: CBaseEntity
vfunc_offset: 0xD8       # Offset from vtable start - changes with game updates
vfunc_index: 27          # vtable index - changes with game updates
```

## Related Functions

- `CNetworkTransmitComponent::StateChanged` - Internal state change handler
- `NetworkStateChanged` - Higher-level network state notification
