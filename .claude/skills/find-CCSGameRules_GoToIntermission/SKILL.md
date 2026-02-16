---
name: find-CCSGameRules_GoToIntermission
description: Find and identify the CCSGameRules_GoToIntermission function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the GoToIntermission function by searching for the "Going to intermission..." string reference.
---

# Find CCSGameRules_GoToIntermission

Locate `CCSGameRules_GoToIntermission` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Search for Reference String

Search for the string `"Going to intermission..."`:

```
mcp__ida-pro-mcp__find_regex pattern="Going to intermission"
```

Note the string address.

### 2. Find Cross-Reference and Containing Function

Get xrefs to the string address:

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_address>"
```

This will lead to `CCSGameRules_GoToIntermission`. Rename it:

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSGameRules_GoToIntermission"}]}
```

### 3. Get VTable Index

**ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function `CCSGameRules_GoToIntermission`.

VTable class name: `CCSGameRules`

### 4. Generate Signature

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CCSGameRules_GoToIntermission`.

### 5. Write Analysis Results as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for `CCSGameRules_GoToIntermission`.

Required parameters:
- `func_name`: `CCSGameRules_GoToIntermission`
- `func_addr`: The function address from step 2
- `func_sig`: The signature from step 4

VTable parameters:
- `vtable_name`: `CCSGameRules`
- `vfunc_index`: The vtable index from step 3
- `vfunc_offset`: The vtable offset from step 3

## VTable Information

- **VTable Name**: `CCSGameRules::`vftable'`
- **VTable Mangled Name (Windows)**: `??_7CCSGameRules@@6B@`
- **VTable Mangled Name (Linux)**: `_ZTV12CCSGameRules`
- **VTable Index**: 128 - This can change when game updates.
- **VTable Offset**: 0x400 (128 * 8 = 1024) - This can change when game updates.

* Note that for `server.so`, the first 16 bytes of "vftable" are for RTTI. The real vftable = `_ZTV12CCSGameRules` + `0x10`.

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSGameRules_GoToIntermission.windows.yaml`
- `server.so` → `CCSGameRules_GoToIntermission.linux.yaml`

```yaml
func_name: CCSGameRules_GoToIntermission
func_va: 0x18087eba0
func_rva: 0x87eba0
func_size: 0xe61
func_sig: 48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 4C 8B E1
vtable_name: CCSGameRules
vfunc_offset: 0x400
vfunc_index: 128
```

## Notes

- This function is called when a match ends and the game transitions to intermission.
- It sends `CCSUsrMsg_EndOfMatchAllPlayersData` and `CCSUsrMsg_ServerRankRevealAll` user messages.
- It fires the `cs_intermission` game event.
- It is a large function (~0xE61 bytes).
