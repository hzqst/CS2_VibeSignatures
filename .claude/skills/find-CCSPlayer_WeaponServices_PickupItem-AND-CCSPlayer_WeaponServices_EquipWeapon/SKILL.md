---
name: find-CCSPlayer_WeaponServices_PickupItem-AND-CCSPlayer_WeaponServices_EquipWeapon
description: |
  Find and identify CCSPlayer_WeaponServices_PickupItem and CCSPlayer_WeaponServices_EquipWeapon functions in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the weapon pickup functions. CCSPlayer_WeaponServices_PickupItem is a virtual function on CCSPlayer_WeaponServices found via "Player.PickupGrenadeAudible" string xref. CCSPlayer_WeaponServices_EquipWeapon is called within PickupItem.
  Trigger: CCSPlayer_WeaponServices_PickupItem, CCSPlayer_WeaponServices_EquipWeapon, PickupItem, EquipWeapon, Player.PickupGrenadeAudible, item_pickup
---

# Find CCSPlayer_WeaponServices_PickupItem and CCSPlayer_WeaponServices_EquipWeapon

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

### 4. Decompile and Find CCSPlayer_WeaponServices_EquipWeapon

Decompile `CCSPlayer_WeaponServices_PickupItem` and locate the call to `CCSPlayer_WeaponServices_EquipWeapon` near the beginning of the function. Look for this pattern:

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

### 5. Rename CCSPlayer_WeaponServices_EquipWeapon

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<equip_func_addr>", "name": "CCSPlayer_WeaponServices_EquipWeapon"}})
```

### 6. Get VTable Index for CCSPlayer_WeaponServices_PickupItem

**ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for `CCSPlayer_WeaponServices_PickupItem` with:
- `class_name=CCSPlayer_WeaponServices`
- `func_addr=<CCSPlayer_WeaponServices_PickupItem_addr>`

### 7. Generate Signatures

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate robust signatures for both functions:

For CCSPlayer_WeaponServices_PickupItem:
```
/generate-signature-for-function addr=<CCSPlayer_WeaponServices_PickupItem_addr>
```

For CCSPlayer_WeaponServices_EquipWeapon:
```
/generate-signature-for-function addr=<CCSPlayer_WeaponServices_EquipWeapon_addr>
```

### 8. Write Analysis Results as YAML

#### For CCSPlayer_WeaponServices_PickupItem:

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:

Required parameters:
- `func_name`: `CCSPlayer_WeaponServices_PickupItem`
- `func_addr`: The function address from step 2
- `func_sig`: The validated signature from step 7

VTable parameters:
- `vtable_name`: `CCSPlayer_WeaponServices`
- `vfunc_offset`: The offset from step 6
- `vfunc_index`: The index from step 6

#### For CCSPlayer_WeaponServices_EquipWeapon:

**ALWAYS** Use SKILL `/write-func-as-yaml` with:

Required parameters:
- `func_name`: `CCSPlayer_WeaponServices_EquipWeapon`
- `func_addr`: The function address from step 4
- `func_sig`: The validated signature from step 7

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
- The string may have been changed in a game update

**If the function structure differs:**
- Look for a large function that references both `"item_pickup"` and `"Player.PickupGrenadeAudible"`
- The RTTI cast from CBasePlayerWeapon to CCSWeaponBase is a strong identifier

**If vtable YAML file is missing:**
- Run `/write-vtable-as-yaml` for `CCSPlayer_WeaponServices` first
