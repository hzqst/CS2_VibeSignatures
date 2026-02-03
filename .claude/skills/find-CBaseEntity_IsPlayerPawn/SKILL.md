---
name: find-CBaseEntity_IsPlayerPawn
description: Find and identify the CBaseEntity_IsPlayerPawn virtual function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the IsPlayerPawn check function by analyzing the CBaseEntity vtable and identifying the simple boolean check pattern that returns whether a byte at offset ~1400 equals zero.
---

# Find CBaseEntity_IsPlayerPawn

Locate `CBaseEntity_IsPlayerPawn` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Search for Reference String

Search for the string `"Ignoring speaking bot %s at round end"`:

```
mcp__ida-pro-mcp__find_regex pattern="Ignoring speaking bot.*at round end"
```

Note the string address.

### 2. Find Cross-Reference and Containing Function

Get xrefs to the string address:

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_address>"
```

This will lead to function `CCSGameRules::Think`. rename it to `CCSGameRules_Think`

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSGameRules_Think"}]}
```

### 3. Decompile CCSGameRules_Think and look for certain code pattern

Decompile it and look for this code pattern:

```c
v81 = (const char *)(*(__int64 (__fastcall **)(_QWORD))(**(_QWORD **)(v78 + 24) + 1128LL))(*(_QWORD *)(v78 + 24));
Msg("Ignoring speaking bot %s at round end\n", v81);
...
sub_XXXXXXX((unsigned __int16 *)&v123);  // <-- This is the player iterator function
```

Note the address of `sub_XXXXXXX` (the function called after the Msg).

### 4. Decompile Player Iterator and Extract VTable Offset

Decompile the player iterator function:

```
mcp__ida-pro-mcp__decompile addr="<sub_XXXXXXX_address>"
```

Look for this code pattern:

```c
if ( (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)v3 + 1344LL))(v3)  // <-- 1344 is IsPlayerPawn vtable offset
    && (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)v4 + 3344LL))(v4)
    && (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)v4 + 3208LL))(v4) )
{
    if ( *(_BYTE *)(v4 + 6832) ? *(_QWORD *)(v4 + 6824) : 0LL )
      break;
}
```

Extract the **first vtable offset** from this pattern (e.g., `1344`). This is the `CBaseEntity::IsPlayerPawn` vtable offset.

Calculate:
- **VTable Offset**: The value from the pattern (e.g., 1344 = 0x540)
- **VTable Index**: offset / 8 (e.g., 1344 / 8 = **168**)

### 5. Write Analysis Results as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CBaseEntity_IsPlayerPawn`
- `func_addr`: Leave empty, because we don't need it
- `func_sig`: Leave empty, because we don't need it

VTable parameters:
- `vtable_name`: `CBaseEntity`
- `vfunc_index`: The vtable index from step 4 (e.g., 168)
- `vfunc_offset`: `vfunc_index * 8` (e.g., 1344)

## VTable Information

- **VTable Name**: `CBaseEntity::`vftable'`
- **VTable Mangled Name (Windows)**: `??_7CBaseEntity@@6B@`
- **VTable Mangled Name (Linux)**: `_ZTV11CBaseEntity`
- **VTable Index**: 168 - This can change when game updates.
- **VTable Offset**: 0x540 (168 * 8 = 1344) - This can change when game updates.

* Note that for `server.so`, the first 16 bytes of "vftable" are for RTTI. The real vftable = `_ZTV11CBaseEntity` + `0x10`.

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBaseEntity_IsPlayerPawn.windows.yaml`
- `server.so` → `CBaseEntity_IsPlayerPawn.linux.yaml`

```yaml
vtable_name: CBaseEntity
vfunc_index: 168
vfunc_offset: 1344
```

## Notes

- This is a simple virtual function that just return either true or false.
- There is no need to make a signature for it.