---
name: find-CCSPlayerPawnBase_PostThink
description: |
  IDA Pro string analysis and function reverse engineering workflow. Connect to IDA Pro via ida-pro-mcp for binary analysis to locate the CCSPlayerPawnBase_PostThink function.
  Use cases:
  (1) Search for specific strings in binary files
  (2) Find cross-references (xrefs) to strings
  (3) Decompile functions that reference strings and view pseudocode
  (4) Locate specific code segments in pseudocode
  (5) Rename functions and variables to improve readability
  (6) Analyze function call relationships and data flow
  Trigger: CCSPlayerPawnBase_PostThink
---

# CCSPlayerPawnBase_PostThink Function Location Workflow

## Overview

This workflow is used to locate the `CCSPlayerPawnBase_PostThink` function in CS2 server binary files. This function is the PostThink handler for player Pawns, responsible for handling enter/exit events for buy zones, bomb zones, and rescue zones.

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the `enter_buyzone` string:

```
mcp__ida-pro-mcp__find_regex(pattern="enter_buyzone")
```

Expected result: Find string address (e.g., `0x86ebfd` for Linux, varies by version)

### 2. Find Cross-References

Use `xrefs_to` to find locations that reference this string:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

Expected result: Find the function that references the string (e.g., `sub_A58DE0`)

### 3. Rename Function

Use `rename` to give the function a meaningful name:

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<function_addr>", "name": "CCSPlayerPawnBase_PostThink"}})
```

### 4. Decompile to View Pseudocode

Use `decompile` to view the function pseudocode and get function size:

```
mcp__ida-pro-mcp__decompile(addr="<function_addr>")
```

### 5. Find VTable and Calculate Offset

  **ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.

### 6. Generate and Validate Unique Signature

  **DO NOT** use `find_bytes` as it won't work for function.
  **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 7. Write IDA analysis output as YAML beside the binary

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CCSPlayerPawnBase_PostThink`
- `func_addr`: The function address from step 2
- `func_sig`: The validated signature from step 6

VTable parameters (when this is a virtual function):
- `vtable_name`: `CCSPlayerPawn`
- `vtable_mangled_name`: `??_7CCSPlayerPawn@@6B@` (Windows) or `_ZTV13CCSPlayerPawn` (Linux)
- `vfunc_offset`: The offset from step 5
- `vfunc_index`: The index from step 5

## Function Characteristics

The `CCSPlayerPawnBase_PostThink` function contains the following signature strings:

- `enter_buyzone` / `exit_buyzone` - Buy zone events
- `enter_bombzone` / `exit_bombzone` - Bomb zone events
- `enter_rescue_zone` / `exit_rescue_zone` - Rescue zone events
- `weapon_c4` - C4 bomb detection
- `SpottedLooseBomb` - AFK player dropped bomb notification
- `isplanted` - Bomb planted state check

## VTable Information

- **VTable Name**: `CCSPlayerPawn`
- **VTable Mangled Name**:
  - Windows: `??_7CCSPlayerPawn@@6B@`
  - Linux: `_ZTV13CCSPlayerPawn`
- **VTable Offset**: `0xB98` (may change with game updates)
- **VTable Index**: `371` (may change with game updates)

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSPlayerPawnBase_PostThink.windows.yaml`
- `server.so` / `libserver.so` → `CCSPlayerPawnBase_PostThink.linux.yaml`

```yaml
func_va: 0xA58DE0        # Virtual address of the function - changes with game updates
func_rva: 0xA58DE0       # Relative virtual address (VA - image base) - changes with game updates
func_size: 0x86A         # Function size in bytes - changes with game updates
func_sig: XX XX XX XX XX # Unique byte signature for pattern scanning - changes with game updates
vtable_name: CCSPlayerPawn
vtable_mangled_name: _ZTV13CCSPlayerPawn  # Use ??_7CCSPlayerPawn@@6B@ for Windows
vfunc_offset: 0xB98      # Offset from vtable start - changes with game updates
vfunc_index: 371         # vtable index - changes with game updates
```

## Related Functions

- `sub_1387560` - Check if in buy zone
- `sub_1390A80` - Check if can purchase
- `sub_15A47B0` - Find specified weapon (e.g., "weapon_c4")
- `qword_257FF40` - Game event manager
