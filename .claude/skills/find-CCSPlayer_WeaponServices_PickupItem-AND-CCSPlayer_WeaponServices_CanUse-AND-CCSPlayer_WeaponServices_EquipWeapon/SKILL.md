---
name: find-CCSPlayer_WeaponServices_PickupItem-AND-CCSPlayer_WeaponServices_CanUse-AND-CCSPlayer_WeaponServices_EquipWeapon
description: |
  Find and identify CCSPlayer_WeaponServices_PickupItem , CCSPlayer_WeaponServices_CanUse and CCSPlayer_WeaponServices_EquipWeapon functions in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the weapon pickup functions. CCSPlayer_WeaponServices_PickupItem is a virtual function on CCSPlayer_WeaponServices found via "Player.PickupGrenadeAudible" string xref. CCSPlayer_WeaponServices_EquipWeapon is called within PickupItem.
  Trigger: CCSPlayer_WeaponServices_PickupItem, CCSPlayer_WeaponServices_EquipWeapon, PickupItem, EquipWeapon, Player.PickupGrenadeAudible, item_pickup
---

# Find CCSPlayer_WeaponServices_PickupItem, CCSPlayer_WeaponServices_CanUse and CCSPlayer_WeaponServices_EquipWeapon

Locate the weapon pickup functions in CS2 server.dll or server.so using IDA Pro MCP tools.

## Overview

This skill identifies two functions:

1. **CCSPlayer_WeaponServices_PickupItem** — A large virtual function on `CCSPlayer_WeaponServices` that handles weapon pickup logic, fires `item_pickup` game event, and plays pickup sounds
2. **CCSPlayer_WeaponServices_EquipWeapon** — Called within PickupItem to equip the picked-up weapon

The entry point is found via the `"Player.PickupGrenadeAudible"` string.

## Method

### 1. Search for "Player.PickupGrenadeAudible" String

```
mcp__ida-pro-mcp__find_regex(pattern="Player\\.PickupGrenadeAudible")
```

Expected result: Find string address (e.g., `0x1816be780` for Windows, varies by version)

### 2. Find Cross-References to the String

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

Expected result: A data xref inside a large function (~0xC99 bytes). This function is `CCSPlayer_WeaponServices_PickupItem`.

### 3. Rename CCSPlayer_WeaponServices_PickupItem

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<func_addr>", "name": "CCSPlayer_WeaponServices_PickupItem"}})
```

### 4. Find CCSPlayer_WeaponServices_EquipWeapon, CCSPlayer_WeaponServices_CanUse in CCSPlayer_WeaponServices_PickupItem

Decompile `CCSPlayer_WeaponServices_PickupItem` and locate the virtual func call to `CCSPlayer_WeaponServices_EquipWeapon` near the beginning of the function. Look for this pattern:

Windows:
```c
  if ( *(_BYTE *)(a1 + 220) )
  {
    if ( v4 )
      goto LABEL_12;
    sub_XXXXXXXX(a2 + 182);
    sub_YYYYYYYY((_QWORD *)a1, a2);  // <-- This is CCSPlayer_WeaponServices_EquipWeapon
    return 1LL;
  }
```

Linux:
```c
  if ( *(_BYTE *)(a1 + <offset>) )
  {
    if ( v4 )
      goto LABEL_XX;
    sub_XXXXXXXX(a2 + <offset>);
    sub_YYYYYYYY((_QWORD *)a1, a2);  // <-- This is CCSPlayer_WeaponServices_EquipWeapon
    return 1LL;
  }
```

The function `sub_YYYYYYYY` takes `(CCSPlayer_WeaponServices* this, CBasePlayerWeapon* weapon)` and is called in the early `m_bIsRescuing` branch as well as at the end of the main pickup flow. It appears twice in the decompiled output — both calls target the same function.

locate the virtual func call to `CCSPlayer_WeaponServices_CanUse`

Windows binary:

```c
  if ( sub_18093B520(v5) || !(*(unsigned __int8 (__fastcall **)(__int64, _QWORD *))(*(_QWORD *)a1 + 184LL))(a1, v5) ) //184LL = vfunc_offset for CCSPlayer_WeaponServices_CanUse, aka  this->CanUse(v5)
  {
    if ( (unsigned __int8)sub_18088B0E0(qword_XXXXXXXX) )
    {
      sub_180B409C0((__int64)v5);
      return 2LL;
    }
    return 0LL;
  }
```

Linux binary:

```c
if ( !sub_12B6690(v7) && (*(unsigned __int8 (__fastcall **)(__int64, char *))(*(_QWORD *)v2 + 192LL))(v2, v7) ) //192LL = vfunc_offset for CCSPlayer_WeaponServices_CanUse, aka  this->CanUse(v5)
```

### 5. Rename CCSPlayer_WeaponServices_EquipWeapon

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<CCSPlayer_WeaponServices_EquipWeapon_addr>", "name": "CCSPlayer_WeaponServices_EquipWeapon"}})
```

### 6. Get CCSPlayer_WeaponServices vtable information from yaml

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CCSPlayer_WeaponServices` and with `class_name=CBaseEntity`

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `vtable_va`, `vtable_numvfunc` and `vtable_entries` for subsequent steps.

### 7. Resolve vfunc address for CCSPlayer_WeaponServices_CanUse, Resolve vtable index for CCSPlayer_WeaponServices_PickupItem

Using the vtable entries from step 6, look up `CCSPlayer_WeaponServices vtable_entries[index]` to resolve the actual function address of `CCSPlayer_WeaponServices_CanUse`.

Rename them:

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<CCSPlayer_WeaponServices_CanUse_function_addr>", "name": "CCSPlayer_WeaponServices_CanUse"}})
```

Find `CCSPlayer_WeaponServices_PickupItem`'s vtable index by looking up `CCSPlayer_WeaponServices_PickupItem`'s func addr in `CCSPlayer_WeaponServices vtable_entries`, The `vtable_index` for `CCSPlayer_WeaponServices_PickupItem` will be used later.

### 8. Generate Signatures for CCSPlayer_WeaponServices_PickupItem, CCSPlayer_WeaponServices_EquipWeapon and CCSPlayer_WeaponServices_CanUse

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate robust signatures for both functions:

For `CCSPlayer_WeaponServices_PickupItem`:

```
/generate-signature-for-function addr=<CCSPlayer_WeaponServices_PickupItem_addr>
```

For `CCSPlayer_WeaponServices_EquipWeapon`:

```
/generate-signature-for-function addr=<CCSPlayer_WeaponServices_EquipWeapon_addr>
```

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CCSPlayer_WeaponServices_CanUse`.

Use the instruction address of the `(*(unsigned __int8 (__fastcall **)(__int64, _QWORD *))(*(_QWORD *)a1 + 184LL))(a1, v5)` call as the target instruction, and the vtable offset as the expected vfunc offset.

### 9. Write Analysis Results as YAML

#### For CCSPlayer_WeaponServices_PickupItem:

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:

Required parameters:
- `func_name`: `CCSPlayer_WeaponServices_PickupItem`
- `func_addr`: The function address from step 2
- `func_sig`: The validated signature from step 8

VTable parameters:
- `vtable_name`: `CCSPlayer_WeaponServices`
- `vfunc_offset`: The offset from step 6
- `vfunc_index`: The index from step 6

#### For CCSPlayer_WeaponServices_EquipWeapon:

**ALWAYS** Use SKILL `/write-func-as-yaml` with:

Required parameters:
- `func_name`: `CCSPlayer_WeaponServices_EquipWeapon`
- `func_addr`: The function address from step 4
- `func_sig`: The validated signature from step 8

#### For CCSPlayer_WeaponServices_CanUse: 

  Required parameters:
  - `func_name`: `CCSPlayer_WeaponServices_CanUse`
  - `func_addr`: The function address from step 5
  - `vfunc_sig`: CCSPlayer_WeaponServices_CanUse's `<vfunc_sig>` from step 8

  VTable parameters:
  - `vtable_name`: `CBaseEntity`
  - `vfunc_offset`: `index * 8` (from step 4)
  - `vfunc_index`: The index from step 4

## Function Characteristics Summary

### CCSPlayer_WeaponServices_PickupItem

- **VTable Class**: `CCSPlayer_WeaponServices`
- **VTable Index**: 25 (may change with updates)
- **Size**: Large (~0xC99 bytes)
- **Parameters**: `(CCSPlayer_WeaponServices* this, CBasePlayerWeapon* weapon)`
- **Purpose**: Full weapon pickup handler — RTTI casts weapon to CCSWeaponBase, checks slot availability, fires `item_pickup` game event, plays pickup sounds, calls EquipWeapon
- **Key Strings**: `"Player.PickupGrenadeAudible"`, `"Player.PickupC4"`, `"Player.PickupWeaponAudible"`, `"item_pickup"`, `"weapon_c4"`
- **Key Features**:
  - RTTI dynamic cast from `CBasePlayerWeapon` to `CCSWeaponBase`
  - Checks `m_bIsRescuing` flag at `this + 220`
  - Fires `item_pickup` game event with fields: `defindex`, `userid`, `item`, `silent`, `priority`
  - Plays different sounds based on weapon type (grenade=9, c4=7, other)
  - Calls `CCSPlayer_WeaponServices_Weapon_GetSlot` for slot management

### CCSPlayer_WeaponServices_EquipWeapon

- **Type**: Regular function (not virtual)
- **Size**: Small (~0x17D bytes)
- **Parameters**: `(CCSPlayer_WeaponServices* this, CBasePlayerWeapon* weapon)`
- **Purpose**: Equips the weapon after pickup — called from within PickupItem

## VTable Information

### CCSPlayer_WeaponServices
- **Mangled Name**:
  - Windows: `??_7CCSPlayer_WeaponServices@@6B@`
  - Linux: `_ZTV25CCSPlayer_WeaponServices`
- **PickupItem Offset**: `0xC8` (may change with game updates)
- **PickupItem Index**: `25` (may change with game updates)

## Output YAML Files

This skill generates **two YAML files**:

**Platform-specific naming:**
- `server.dll` (Windows):
  - `CCSPlayer_WeaponServices_PickupItem.windows.yaml`
  - `CCSPlayer_WeaponServices_EquipWeapon.windows.yaml`
- `server.so` / `libserver.so` (Linux):
  - `CCSPlayer_WeaponServices_PickupItem.linux.yaml`
  - `CCSPlayer_WeaponServices_EquipWeapon.linux.yaml`

## Troubleshooting

**If "Player.PickupGrenadeAudible" string not found:**
- Verify the binary is a CS2 server binary (server.dll or server.so)
- The string may have been changed in a game update, indicate an error to user

**If the function structure differs:**
- Look for a large function that references both `"item_pickup"` and `"Player.PickupGrenadeAudible"`
- The RTTI cast from CBasePlayerWeapon to CCSWeaponBase is a strong identifier
