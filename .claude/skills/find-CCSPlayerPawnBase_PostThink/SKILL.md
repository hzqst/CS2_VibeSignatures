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

### 5. Find VTable Information

Get xrefs to the function to find data references:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<function_addr>")
```

Find the data reference - this is the vtable entry location.

### 6. List VTable Globals

Search for CCSPlayerPawn vtable:

```
mcp__ida-pro-mcp__list_globals(queries={"filter": "*CCSPlayerPawn*"})
```

Look for:
- Windows: `??_7CCSPlayerPawn@@6B@` - the vtable
- Linux: `_ZTV13CCSPlayerPawn` - the vtable

### 7. Calculate VTable Offset and Index

- `vfunc_offset = data_ref_addr - vtable_addr`
- `vfunc_index = vfunc_offset / 8`

Note: For Linux `server.so`, the first 16 bytes of vtable are for RTTI metadata. The real vtable starts at `_ZTV13CCSPlayerPawn + 0x10`.

### 8. Get Image Base and Write YAML

Get binary information:

```python
mcp__ida-pro-mcp__py_eval(code="""
import ida_nalt
import ida_ida
file_path = ida_nalt.get_input_file_path()
image_base = ida_ida.inf_get_min_ea()
print(f"File: {file_path}")
print(f"Base: {hex(image_base)}")
""")
```

Calculate `func_rva = func_va - image_base`

Write the YAML file beside the binary using the Write tool:
- `server.dll` → `CCSPlayerPawnBase_PostThink.windows.yaml`
- `server.so` / `libserver.so` → `CCSPlayerPawnBase_PostThink.linux.yaml`

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
vfunc_name: CCSPlayerPawn
vfunc_mangled_name: _ZTV13CCSPlayerPawn  # Use ??_7CCSPlayerPawn@@6B@ for Windows
vfunc_offset: 0xB98      # Offset from vtable start - changes with game updates
vfunc_index: 371         # vtable index - changes with game updates
```

## Related Functions

- `sub_1387560` - Check if in buy zone
- `sub_1390A80` - Check if can purchase
- `sub_15A47B0` - Find specified weapon (e.g., "weapon_c4")
- `qword_257FF40` - Game event manager
