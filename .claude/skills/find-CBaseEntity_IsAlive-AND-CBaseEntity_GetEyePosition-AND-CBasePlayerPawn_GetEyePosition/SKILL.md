---
name: find-CBaseEntity_IsAlive-AND-CBaseEntity_GetEyePosition-AND-CBasePlayerPawn_GetEyePosition
description: |
  Find and identify the CBaseEntity_IsAlive, CBaseEntity_GetEyePosition and CBasePlayerPawn_GetEyePosition virtual functions in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 server.dll or server.so to locate these functions.
  CBaseEntity_IsAlive checks m_lifeState == 0 (LIFE_ALIVE).
  CBasePlayerPawn_GetEyePosition retrieves the player eye position via camera services.
  Trigger: CBaseEntity_IsAlive, CBasePlayerPawn_GetEyePosition, IsAlive, GetEyePosition
disable-model-invocation: true
---

# CBaseEntity_IsAlive & CBaseEntity_GetEyePosition & CBasePlayerPawn_GetEyePosition Function Location Workflow

## Overview

This workflow locates two virtual functions in CS2 server binary files:

1. **CBaseEntity_IsAlive** - Returns whether an entity is alive by checking `m_lifeState == 0` (offset `0x2E0`).
2. **CBasePlayerPawn_GetEyePosition** - Retrieves the player's eye position, delegating to camera services when available.

Both are virtual functions on the `CBasePlayerPawn` vtable and can be found by locating `CCSBot::Upkeep` which calls them at known vtable offsets.

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the `CCSBot::Upkeep` string:

```
mcp__ida-pro-mcp__find_regex(pattern="CCSBot::Upkeep")
```

Expected result: Find string address (varies by version)

### 2. Find Cross-References

Use `xrefs_to` to find the function that references this string:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

Expected result: Find the `CCSBot::Upkeep` function (e.g., `sub_1802D3400`)

### 3. Decompile and Identify VFunc Calls

Use `decompile` on the function found in step 2:

```
mcp__ida-pro-mcp__decompile(addr="<function_addr>")
```

Look for the following code pattern in the decompiled output:

```c
v2 = (__int64 (*)(void))VProfScopeHelper<0,0>::EnterScopeInternalBudgetFlags("CCSBot::Upkeep", ...);
if ( !(*(unsigned __int8 (__fastcall **)(_QWORD))(**(_QWORD **)(a1 + 24) + <OFFSET_A>))(*(_QWORD *)(a1 + 24)) )
    return v2();
```

And further down:

```c
(*(void (__fastcall **)(_QWORD, __int128 *))(**(_QWORD **)(a1 + 24) + <OFFSET_B>))(*(_QWORD *)(a1 + 24), &v26);
```

Or alternatively (Linux pattern):

```c
v7 = *(unsigned __int8 (**)(void))(*(_QWORD *)v5 + <OFFSET_A>);
if ( (char *)v7 == (char *)sub_XXXXXX )
{
    if ( v5[YYYY] )
        return v6();
}
else if ( !v7() )
{
    return v6();
}
```

Where:
- `<OFFSET_A>` is the vtable offset for `CBaseEntity_IsAlive` (the alive check, called first, returns early if false)
- `<OFFSET_B>` is the vtable offset for `CBasePlayerPawn_GetEyePosition` (called with an output Vector pointer)

### 4. Generate vfunc offset signatures for CBaseEntity_IsAlive and CBasePlayerPawn_GetEyePosition

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CBaseEntity_IsAlive` and `CBasePlayerPawn_GetEyePosition`, with `inst_addr` and `vfunc_offset` from step 3

### 5. Load CBasePlayerPawn VTable, and CBaseEntity VTable

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CBasePlayerPawn` and with `class_name=CBaseEntity`

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `vtable_va`, `vtable_numvfunc` and `vtable_entries` for subsequent steps.

### 6. Calculate VTable Indices and resolve vfunc addresses

From the offsets found in step 3, calculate vtable indices:

- `CBaseEntity_IsAlive`: index = `<OFFSET_A>` / 8
- `CBaseEntity_GetEyePosition`: index = `<OFFSET_B>` / 8

Look up the function addresses from : `CBaseEntity vtable_entries[index]`

- `CBasePlayerPawn_GetEyePosition`: index = `<OFFSET_B>` / 8

Look up the function addresses from : `CBasePlayerPawn vtable_entries[index]`

### 7. Verify Functions

Decompile both functions to verify:

**CBaseEntity_IsAlive** should look like:
```c
bool __fastcall CBaseEntity_IsAlive(__int64 a1)
{
  return *(_BYTE *)(a1 + 736) == 0;  // 736 == 0x2E0 == m_lifeState
}
```

**CBasePlayerPawn_GetEyePosition** should look like:
```c
__int64 __fastcall CBasePlayerPawn_GetEyePosition(__int64 a1, __int64 a2)
{
  v4 = *(_QWORD *)(a1 + <camera_services_offset>);
  if ( v4 && (v5 = vtable_call(v4, +152)) != 0 )
    vtable_call(v5, +<some_offset>, a2);  // delegates to camera GetEyePosition
  else
    fallback_GetAbsOrigin(a1, a2);        // fallback position
  return a2;
}
```

### 8. Rename Functions

```
mcp__ida-pro-mcp__rename(batch={"func": [
  {"addr": "<CBaseEntity_IsAlive_addr>", "name": "CBaseEntity_IsAlive"},
  {"addr": "<CBaseEntity_GetEyePosition_addr>", "name": "CBaseEntity_GetEyePosition"}
  {"addr": "<CBasePlayerPawn_GetEyePosition_addr>", "name": "CBasePlayerPawn_GetEyePosition"}
]})
```

### 9. Generate Signature for CBasePlayerPawn_GetEyePosition

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CBasePlayerPawn_GetEyePosition`.

Note: `CBaseEntity_IsAlive` does NOT need a function signature (it is too small/generic).

Note: `CBaseEntity_GetEyePosition` does NOT need a function signature (it is too small/generic).

### 10. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for BOTH functions.

**CBaseEntity_IsAlive** (no signature):
- `func_name`: `CBaseEntity_IsAlive`
- `func_addr`: The function address from step 6
- `func_sig`: `None` (omit — function is too small for a unique signature)
- `vtable_name`: `CBaseEntity`
- `vfunc_offset`: `<OFFSET_A>` from step 3
- `vfunc_index`: `<OFFSET_A> / 8` from step 6
- `vfunc_sig`: CBaseEntity_IsAlive's `<vfunc_sig>` from step 4

**CBaseEntity_GetEyePosition** (with signature):
- `func_name`: `CBaseEntity_GetEyePosition`
- `func_addr`: The function address from step 6
- `func_sig`: `None` (omit — function is too small for a unique signature)
- `vtable_name`: `CBaseEntity`
- `vfunc_offset`: `<OFFSET_B>` from step 3
- `vfunc_index`: `<OFFSET_B> / 8` from step 6
- `vfunc_sig`: CBaseEntity_GetEyePosition's `<vfunc_sig>` from step 4

**CBasePlayerPawn_GetEyePosition** (with signature):
- `func_name`: `CBasePlayerPawn_GetEyePosition`
- `func_addr`: The function address from step 6
- `func_sig`: The validated signature from step 9
- `vtable_name`: `CBasePlayerPawn`
- `vfunc_offset`: `<OFFSET_B>` from step 3
- `vfunc_index`: `<OFFSET_B> / 8` from step 6

## Function Characteristics

### CBaseEntity_IsAlive
- Checks `m_lifeState` (offset `0x2E0`) equals 0 (`LIFE_ALIVE`)
- Very small function (~11 bytes on Windows)
- Virtual function is on both `CBaseEntity` and `CBasePlayerPawn` vtable

### CBasePlayerPawn_GetEyePosition
- Retrieves player eye position via camera services
- Takes output Vector pointer as second parameter
- Falls back to base position calculation if no camera services
- Virtual function on `CBasePlayerPawn` vtable

## VTable Information

- **VTable Name**: `CBasePlayerPawn`
- **VTable Mangled Name**:
  - Windows: `??_7CBasePlayerPawn@@6B@`
  - Linux: `_ZTV16CBasePlayerPawn`

### CBaseEntity_IsAlive
- **VTable Offset**: `0x538` (may change with game updates)
- **VTable Index**: `167` (may change with game updates)

### CBasePlayerPawn_GetEyePosition
- **VTable Offset**: `0x5D0` (may change with game updates)
- **VTable Index**: `186` (may change with game updates)

## Output YAML Format

Output YAML filenames depend on the platform:

- `server.dll` → `CBaseEntity_IsAlive.windows.yaml`, `CBaseEntity_GetEyePosition.windows.yaml`, `CBasePlayerPawn_GetEyePosition.windows.yaml`

- `server.so` / `libserver.so` → `CBaseEntity_IsAlive.linux.yaml`, `CBaseEntity_GetEyePosition.linux.yaml`, `CBasePlayerPawn_GetEyePosition.linux.yaml`
