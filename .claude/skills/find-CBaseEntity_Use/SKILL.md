---
name: find-CBaseEntity_Use
description: |
  Find and identify the CBaseEntity_Use virtual function in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 server.dll or server.so to locate the Use function.
  CBaseEntity_Use is a virtual function on CBaseEntity, resolved via vtable offset found in the function
  that references both "Radio.YouTakeThePoint" and "#Cstrike_TitlesTXT_Game_afk_bomb_drop".
  Trigger: CBaseEntity_Use, Use
---

# Find CBaseEntity_Use

Locate the `CBaseEntity_Use` virtual function in CS2 server binary using IDA Pro MCP tools.

## Overview

`CBaseEntity_Use` is a virtual function on `CBaseEntity`. It is identified by finding the function that references both `Radio.YouTakeThePoint` and `#Cstrike_TitlesTXT_Game_afk_bomb_drop`, then locating the vtable call at the bottom of that function.

## Prerequisites

- `CBaseEntity` vtable must already be identified (vtable YAML must exist)

If missing, run `/write-vtable-as-yaml` with `class_name=CBaseEntity` first.

## Method

### 1. Search for Signature Strings

Use `find_regex` to search for both strings:

```
mcp__ida-pro-mcp__find_regex(pattern="Radio\\.YouTakeThePoint")
mcp__ida-pro-mcp__find_regex(pattern="#Cstrike_TitlesTXT_Game_afk_bomb_drop")
```

### 2. Find Cross-References and Identify Common Function

Use `xrefs_to` on both string addresses:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr_1>")
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr_2>")
```

Find the function that appears in both xref results. This is the containing function (the AFK bomb drop / player use handler).

### 3. Decompile and Locate CBaseEntity_Use Call

Decompile the common function and look for the following code pattern near the bottom:

Windows binary:
```c
  if ( v74 && ((*(__int64 (__fastcall **)(_QWORD *))(*v17 + <USE_OFFSET_WIN>))(v17) & 4) != 0 )
  {
    v28 = sub_XXXXXXXX(a1);
    *(_QWORD *)&v70 = sub_XXXXXXXX(a1);
    v71 = 0LL;
LABEL_117:
    v66 = *v17;
    *((_QWORD *)&v70 + 1) = v28;
    (*(void (__fastcall **)(_QWORD *, __int128 *))(v66 + <USE_OFFSET_WIN>))(v17, &v70); // CBaseEntity_Use
  }
```

Linux binary:
```c
  if ( v74 && ((*(__int64 (__fastcall **)(_QWORD *))(*v17 + <USE_OFFSET_LIN>))(v17) & 4) != 0 )
  {
    v28 = sub_XXXXXXXX(a1);
    *(_QWORD *)&v70 = sub_XXXXXXXX(a1);
    v71 = 0LL;
LABEL_117:
    v66 = *v17;
    *((_QWORD *)&v70 + 1) = v28;
    (*(void (__fastcall **)(_QWORD *, __int128 *))(v66 + <USE_OFFSET_LIN>))(v17, &v70); // CBaseEntity_Use
  }
```

Key identification:
- The vtable call at `LABEL_117` is `CBaseEntity_Use`
- Record the vtable offset from the call instruction (e.g. `1152` = `0x480`)
- Calculate vtable index: offset / 8

### 4. Generate VFunc-Offset Signature

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CBaseEntity_Use`.

Use the instruction address of the `(*(v66 + <USE_OFFSET>))(v17, &v70)` call as the target instruction, and the vtable offset as the expected vfunc offset.

### 5. Get CBaseEntity VTable Info and Resolve Address

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CBaseEntity`.

If the skill returns an error, stop and report to user.
Otherwise, use `vtable_entries` to look up the entry at the calculated vtable index from step 3. The address at that index is `CBaseEntity_Use`.

### 6. Rename CBaseEntity_Use

Verify the function name at the resolved address. If not already renamed:

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<resolved_addr>", "name": "CBaseEntity_Use"}})
```

### 7. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CBaseEntity_Use`
- `func_addr`: The resolved function address from step 5
- `func_sig`: `None` (function body is too small for a unique signature)
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `CBaseEntity`
- `vfunc_offset`: The offset from step 3
- `vfunc_index`: The index from step 3

## Function Characteristics

- **VTable Class**: `CBaseEntity`
- **Parameters**: `(CBaseEntity* this, CBaseEntity* activator, CBaseEntity* caller, USE_TYPE useType)`
- **Purpose**: Called when an entity is "used" (e.g. player pressing +use on a door, button, or other interactive entity)
- **Identified via**: The function containing both `Radio.YouTakeThePoint` and `#Cstrike_TitlesTXT_Game_afk_bomb_drop` strings

The containing function also references:
- `weapon_c4` - C4 bomb detection
- `CCSPlayer_ItemServices_DropPlayerWeapon` - Dropping the bomb
- `Radio.YouTakeThePoint` / `#Cstrike_TitlesTXT_Game_afk_bomb_drop` - AFK bomb drop notification

## VTable Information

- **VTable Name**: `CBaseEntity`
- **VTable Mangled Name**:
  - Windows: `??_7CBaseEntity@@6B@`
  - Linux: `_ZTV11CBaseEntity`
- **VTable Offset**: `0x480` (Windows) — may change with game updates
- **VTable Index**: `144` (Windows) — may change with game updates

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `CBaseEntity_Use.windows.yaml`
- `server.so` / `libserver.so` -> `CBaseEntity_Use.linux.yaml`

## Troubleshooting

**If CBaseEntity vtable YAML not found:**
- Run `/write-vtable-as-yaml` with `class_name=CBaseEntity` first

**If the vtable offset differs from expected:**
- The vtable layout may have changed in a game update
- Look for the vtable call at `LABEL_117` near the bottom of the containing function
- The pattern is: check flags with `& 4`, then call through vtable with `(v17, &v70)` arguments
