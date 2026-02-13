---
name: find-CBaseEntity_SetOwner
description: |
  Find and identify the CBaseEntity_SetOwner virtual function in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 server.dll or server.so to locate the SetOwner function.
  CBaseEntity_SetOwner is a virtual function on CBaseEntity, resolved via vtable offset in CCSPlayer_WeaponServices_EquipWeapon.
  Trigger: CBaseEntity_SetOwner, SetOwner
---

# Find CBaseEntity_SetOwner

Locate the `CBaseEntity_SetOwner` virtual function in CS2 server binary using IDA Pro MCP tools.

## Overview

`CBaseEntity_SetOwner` is a virtual function on `CBaseEntity`. It is identified by decompiling `CCSPlayer_WeaponServices_EquipWeapon` and resolving the vtable call at offset `416` (Windows) / `408` (Linux) from the weapon entity's vtable pointer.

## Prerequisites

- `CCSPlayer_WeaponServices_EquipWeapon` must already be identified (YAML must exist)
- `CBaseEntity` vtable must already be identified (vtable YAML must exist)

If either is missing, run the corresponding skill first:
- `/find-CCSPlayer_WeaponServices_PickupItem-AND-CCSPlayer_WeaponServices_EquipWeapon`
- `/write-vtable-as-yaml` with `class_name=CBaseEntity`

## Method

### 1. Get CCSPlayer_WeaponServices_EquipWeapon Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CCSPlayer_WeaponServices_EquipWeapon`.

If the skill returns an error, stop and report to user.
Otherwise, extract `func_va` for subsequent steps.

### 2. Get CBaseEntity VTable Info

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CBaseEntity`.

If the skill returns an error, stop and report to user.
Otherwise, extract `vtable_va`, `vtable_numvfunc` and `vtable_entries` for subsequent steps.

### 3. Decompile CCSPlayer_WeaponServices_EquipWeapon and Locate SetOwner Call

Decompile the function at `func_va` from step 1 and look for the following code pattern:

Windows binary:
```c
  sub_XXXXXXXX((__int64)(a2 + 182));
  v7 = *(void (__fastcall **)(_QWORD *, _QWORD))(*a2 + 416LL); // <-- CBaseEntity_SetOwner
  if ( !*(_QWORD *)(a1 + 56) )
    nullsub_XXX(a1);
  v7(a2, *(_QWORD *)(a1 + 56));
  sub_YYYYYYYY(a1, a2);
  v8 = *(void (__fastcall **)(_QWORD *, _QWORD))(*a2 + 816LL);
```

Linux binary:
```c
  sub_XXXXXXXX(a2 + 274);
  v9 = *(void (__fastcall **)(_QWORD *, double, double, double))(*a2 + 408LL); // <-- CBaseEntity_SetOwner
  if ( !*(_QWORD *)(a1 + 56) )
    nullsub_XXXX();
  v9(a2, ...);
  sub_YYYYYYYY(a1, a2);
  v10 = *(void (__fastcall **)(_QWORD *, _QWORD))(*a2 + 808LL);
```

Key identification:
- Windows: vtable offset `416` (`0x1A0`), vtable index = 416 / 8 = **52**
- Linux: vtable offset `408` (`0x198`), vtable index = 408 / 8 = **51**

### 4. Resolve VTable Entry

Using the vtable entries from step 2, look up the entry at the platform-specific index:
- Windows: `vtable_entries[52]`
- Linux: `vtable_entries[51]`

The address at that index is `CBaseEntity_SetOwner`.

### 5. Rename CBaseEntity_SetOwner

Verify the function name at the resolved address. If not already renamed:

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<resolved_addr>", "name": "CBaseEntity_SetOwner"}})
```

### 6. Generate and Validate Unique Signature

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CBaseEntity_SetOwner`.

### 7. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CBaseEntity_SetOwner`
- `func_addr`: The resolved function address from step 4
- `func_sig`: The validated signature from step 6

VTable parameters:
- `vtable_name`: `CBaseEntity`
- `vfunc_offset`: `0x1A0` (Windows) / `0x198` (Linux) — may change with game updates
- `vfunc_index`: `52` (Windows) / `51` (Linux) — may change with game updates

## Function Characteristics

- **VTable Class**: `CBaseEntity`
- **Parameters**: `(CBaseEntity* this, CBaseEntity* owner)`
- **Purpose**: Sets the owner entity for a given entity (e.g., assigning weapon ownership to a player pawn during equip)
- **Called from**: `CCSPlayer_WeaponServices_EquipWeapon` — called with the player's pawn as the owner argument

## VTable Information

- **VTable Name**: `CBaseEntity`
- **VTable Mangled Name**:
  - Windows: `??_7CBaseEntity@@6B@`
  - Linux: `_ZTV11CBaseEntity`
- **VTable Offset**: `0x1A0` (Windows) / `0x198` (Linux) — may change with game updates
- **VTable Index**: `52` (Windows) / `51` (Linux) — may change with game updates

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBaseEntity_SetOwner.windows.yaml`
- `server.so` / `libserver.so` → `CBaseEntity_SetOwner.linux.yaml`

## Troubleshooting

**If CCSPlayer_WeaponServices_EquipWeapon YAML not found:**
- Run `/find-CCSPlayer_WeaponServices_PickupItem-AND-CCSPlayer_WeaponServices_EquipWeapon` first

**If CBaseEntity vtable YAML not found:**
- Run `/write-vtable-as-yaml` with `class_name=CBaseEntity` first

**If the vtable offset differs from expected:**
- The vtable layout may have changed in a game update
- Look for the first vtable call after `sub_XXXXXXXX(a2 + 182)` / `sub_XXXXXXXX(a2 + 274)` in the decompiled output
- The call passes `*(_QWORD *)(a1 + 56)` (the player pawn) as the second argument — this is the distinguishing pattern
