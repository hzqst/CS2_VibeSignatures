---
name: find-CBaseEntity_IsPlayerPawn-AND-CBaseEntity_IsPlayerController
description: Find and identify the CBaseEntity_IsPlayerPawn and CBaseEntity_IsPlayerController virtual functions in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate both vfuncs by decompiling ShowHudHint, following its first callee, and extracting the vtable offsets for IsPlayerPawn and IsPlayerController.
disable-model-invocation: true
---

# Find CBaseEntity_IsPlayerPawn and CBaseEntity_IsPlayerController

Locate both `CBaseEntity_IsPlayerPawn` and `CBaseEntity_IsPlayerController` in CS2 server.dll or server.so using IDA Pro MCP tools.

Both virtual functions are found by decompiling `ShowHudHint` and analyzing its first callee.

## Prerequisite

`ShowHudHint` must already be identified. Use SKILL `/find-ShowHudHint` first if needed.

## Method

### Part A: Locate both vfunc offsets

#### 1. Get ShowHudHint address from YAML

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=ShowHudHint` to load the function address.

#### 2. Decompile ShowHudHint

```
mcp__ida-pro-mcp__decompile addr="<ShowHudHint_addr>"
```

The decompiled code looks like:

```c
void __fastcall ShowHudHint(__int64 a1, _DWORD **a2)
{
  _DWORD *v3; // rcx
  char *v4; // rdx

  v3 = sub_XXXXXXXX(*a2);    // <-- first callee, decompile this
  if ( !v3 )
    v3 = (_DWORD *)sub_YYYYYYYY();
  ...
}
```

Note the address of the first callee (`sub_XXXXXXXX`).

#### 3. Decompile the first callee

```
mcp__ida-pro-mcp__decompile addr="<first_callee_addr>"
```

Look for this code pattern with two vfunc calls:

```c
while ( 1 )
{
  v3 = (*(__int64 (__fastcall **)(_DWORD *))(*(_QWORD *)v1 + <OFFSET_A>))(v1); // <-- CBaseEntity_IsPlayerController
  v4 = *(_QWORD *)v1;
  if ( v3 )
    break;
  if ( (*(unsigned __int8 (__fastcall **)(_DWORD *))(v4 + <OFFSET_B>))(v1) )   // <-- CBaseEntity_IsPlayerPawn
  {
    ...
  }
```

Extract:
- **OFFSET_A** (the larger offset, e.g. 1352): This is `CBaseEntity_IsPlayerController` vtable offset
- **OFFSET_B** (the smaller offset, e.g. 1344): This is `CBaseEntity_IsPlayerPawn` vtable offset

Note the instruction addresses for both vfunc calls.

---

### Part B: CBaseEntity_IsPlayerPawn

#### 4. Generate vfunc offset signature for CBaseEntity_IsPlayerPawn

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CBaseEntity_IsPlayerPawn`, with `inst_addr` = the instruction address of the OFFSET_B vfunc call and `vfunc_offset` = OFFSET_B.

#### 5. Write analysis results as YAML for CBaseEntity_IsPlayerPawn

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CBaseEntity_IsPlayerPawn`
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `CBaseEntity`
- `vfunc_index`: OFFSET_B / 8 (e.g., 1344 / 8 = 168)
- `vfunc_offset`: OFFSET_B (e.g., 1344)

---

### Part C: CBaseEntity_IsPlayerController

#### 6. Generate vfunc offset signature for CBaseEntity_IsPlayerController

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CBaseEntity_IsPlayerController`, with `inst_addr` = the instruction address of the OFFSET_A vfunc call and `vfunc_offset` = OFFSET_A.

#### 7. Write analysis results as YAML for CBaseEntity_IsPlayerController

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CBaseEntity_IsPlayerController`
- `vfunc_sig`: The validated signature from step 6

VTable parameters:
- `vtable_name`: `CBaseEntity`
- `vfunc_index`: OFFSET_A / 8 (e.g., 1352 / 8 = 169)
- `vfunc_offset`: OFFSET_A (e.g., 1352)

## VTable Information

- **VTable Name**: `CBaseEntity::`vftable'`
- **VTable Mangled Name (Windows)**: `??_7CBaseEntity@@6B@`
- **VTable Mangled Name (Linux)**: `_ZTV11CBaseEntity`

### CBaseEntity_IsPlayerPawn
- **VTable Index**: 168 - This can change when game updates.
- **VTable Offset**: 0x540 (168 * 8 = 1344) - This can change when game updates.

### CBaseEntity_IsPlayerController
- **VTable Index**: 169 - This can change when game updates.
- **VTable Offset**: 0x548 (169 * 8 = 1352) - This can change when game updates.

* Note that for `server.so`, the first 16 bytes of "vftable" are for RTTI. The real vftable = `_ZTV11CBaseEntity` + `0x10`.

## Output YAML Format

The output YAML filenames depend on the platform:
- `server.dll` → `CBaseEntity_IsPlayerPawn.windows.yaml`, `CBaseEntity_IsPlayerController.windows.yaml`
- `server.so` / `libserver.so` → `CBaseEntity_IsPlayerPawn.linux.yaml`, `CBaseEntity_IsPlayerController.linux.yaml`

## Notes

- Both are simple virtual functions that return a boolean.
- `CBaseEntity_IsPlayerPawn` returns whether the entity is a player pawn.
- `CBaseEntity_IsPlayerController` returns whether the entity is a player controller.
