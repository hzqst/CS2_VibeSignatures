---
name: find-CCSPlayer_ItemServices_DropActivePlayerWeapon-AND-CCSPlayer_ItemServices_RemoveWeapons
description: Find and identify CCSPlayer_ItemServices_DropActivePlayerWeapon and CCSPlayer_ItemServices_RemoveWeapons functions in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate these ItemServices virtual functions by analyzing vtable entries and characteristic code patterns including SIMD operations, offset 3704 (0xE78) access, and inventory state management.
---

# Find CCSPlayer_ItemServices_DropActivePlayerWeapon and CCSPlayer_ItemServices_RemoveWeapons

Locate `CCSPlayer_ItemServices_DropActivePlayerWeapon` and `CCSPlayer_ItemServices_RemoveWeapons` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Overview

These are two critical virtual functions in the CCSPlayer_ItemServices vtable:

- **DropActivePlayerWeapon** (vtable index 23): Handles dropping the active weapon with velocity calculations
- **RemoveWeapons** (vtable index 24): Removes all weapons and resets inventory state

## Method

### 1. Get CCSPlayer_ItemServices VTable Address

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CCSPlayer_ItemServices`.

If the skill returns an error, stop and report to user that the vtable YAML must be generated first.

Extract these values from the output:
- `vtable_va`: The vtable virtual address
- `vtable_numvfunc`: Number of virtual functions
- `vtable_entries`: Array of virtual function addresses

### 2. Decompile Target Virtual Functions

Decompile virtual functions at indices 18-24 to analyze their characteristics:

```
mcp__ida-pro-mcp__decompile addr="<vtable_entries[18]>"
mcp__ida-pro-mcp__decompile addr="<vtable_entries[19]>"
mcp__ida-pro-mcp__decompile addr="<vtable_entries[20]>"
mcp__ida-pro-mcp__decompile addr="<vtable_entries[21]>"
mcp__ida-pro-mcp__decompile addr="<vtable_entries[22]>"
mcp__ida-pro-mcp__decompile addr="<vtable_entries[23]>"
mcp__ida-pro-mcp__decompile addr="<vtable_entries[24]>"
```

### 3. Identify DropActivePlayerWeapon (around vtable index 20 ~ 24)

Look for a function with following code pattern:

Windows:

```c
__int64 __fastcall sub_18099F240(__int64 a1, float *v)
{
  __int64 v4; // rdi
  __int64 result; // rax
  __int64 v6; // rsi
  __int64 v7; // rax
  float v8; // xmm0_4
  unsigned __int64 *v9; // r9
  float v10[3]; // xmm1_12
  unsigned int v11; // xmm2_4
  unsigned __int64 v12; // [rsp+20h] [rbp-18h] BYREF
  float v13; // [rsp+28h] [rbp-10h]

  nullsub_597();
  if ( !*(_QWORD *)(a1 + 56) )
    nullsub_604(a1);
  v4 = *(_QWORD *)(*(_QWORD *)(a1 + 56) + 0xB70LL);
  result = sub_180B84EF0(v4);
  v6 = result;
  if ( result )
  {
    if ( !*(_QWORD *)(a1 + 56) )
      nullsub_604(a1);
    if ( sub_1803CA0E0(*(_QWORD **)(a1 + 56), 0) )
    {
      if ( !*(_QWORD *)(a1 + 56) )
        nullsub_604(a1);
      v7 = sub_1803CA0E0(*(_QWORD **)(a1 + 56), 0);
      *(double *)&v8 = (*(double (__fastcall **)(__int64))(*(_QWORD *)v7 + 280LL))(v7);
      v9 = &v12;
      v10[0] = v8 * *v;
      *(float *)&v11 = v8 * v[1];
      v8 = v8 * v[2];
      v12 = __PAIR64__(v11, LODWORD(v10[0]));
      v13 = v8;
    }
    else
    {
      v9 = 0LL;
    }
    return (*(__int64 (__fastcall **)(__int64, __int64, _QWORD, unsigned __int64 *, unsigned __int64, float))(*(_QWORD *)v4 + 192LL))(
            v4,
            v6,
            0LL,
            v9,
            v12,
            COERCE_FLOAT(LODWORD(v13)));
  }
  return result;
}
```

Linux:

```c
  __int64 __fastcall sub_137CB20(__int64 a1, float *a2)
{
  __int64 v2; // rdx
  __m128 v3; // xmm0
  __int64 v5; // rax
  __int64 v6; // r14
  __int64 result; // rax
  __int64 v8; // r13
  __int64 v9; // rdi
  __int64 v10; // rdi
  __int64 v11; // rax
  __m128 v12; // xmm1
  __int64 v13; // [rsp+0h] [rbp-30h] BYREF
  float v14; // [rsp+8h] [rbp-28h]

  nullsub_1277(a1, a2, v2);
  v5 = *(_QWORD *)(a1 + 56);
  if ( !v5 )
  {
    nullsub_1293(a1);
    v5 = *(_QWORD *)(a1 + 56);
  }
  v6 = *(_QWORD *)(v5 + 3704);
  result = sub_15A6560(v6);
  v8 = result;
  if ( result )
  {
    v9 = *(_QWORD *)(a1 + 56);
    if ( !v9 )
    {
      nullsub_1293(a1);
      v9 = *(_QWORD *)(a1 + 56);
    }
    if ( sub_C73780(v9, 0LL) )
    {
      v10 = *(_QWORD *)(a1 + 56);
      if ( !v10 )
      {
        nullsub_1293(a1);
        v10 = *(_QWORD *)(a1 + 56);
      }
      v11 = sub_C73780(v10, 0LL);
      *(double *)v3.m128_u64 = (*(double (__fastcall **)(__int64))(*(_QWORD *)v11 + 280LL))(v11);
      v12 = (__m128)_mm_loadl_epi64((const __m128i *)a2);
      v14 = a2[2] * v3.m128_f32[0];
      _mm_storel_ps((double *)&v13, _mm_mul_ps((__m128)_mm_move_epi64((__m128i)_mm_moveldup_ps(v3)), v12));
      return (*(__int64 (__fastcall **)(__int64, __int64, _QWORD, __int64 *))(*(_QWORD *)v6 + 200LL))(v6, v8, 0LL, &v13);
    }
    else
    {
      return (*(__int64 (__fastcall **)(__int64, __int64, _QWORD, _QWORD))(*(_QWORD *)v6 + 200LL))(v6, v8, 0LL, 0LL);
    }
  }
  return result;
}
```

where `a2` is the momentum/velocity of dropped weapon.

### 4. Identify RemoveWeapons (around vtable index 20 ~ 24)

Windows:

```c
__int64 __fastcall sub_1809B7C20(__int64 a1, unsigned __int8 a2)
{
  __int64 v4; // rdi
  __int64 v5; // rdi

  if ( *(_BYTE *)(a1 + 72) )
    sub_1809B7FD0();
  if ( !*(_QWORD *)(a1 + 56) )
    nullsub_604(a1);
  *(_BYTE *)(*(_QWORD *)(*(_QWORD *)(a1 + 56) + 2928LL) + 222LL) = 0;
  if ( !*(_QWORD *)(a1 + 56) )
    nullsub_604(a1);
  *(_QWORD *)(*(_QWORD *)(a1 + 56) + 6896LL) = 0LL;
  if ( a2 )
  {
    if ( *(_BYTE *)(a1 + 73) )
    {
      sub_1801B7320(a1 + 73, 0xFFFFFFFFLL, 0xFFFFFFFFLL);
      *(_BYTE *)(a1 + 73) = 0;
    }
    if ( !*(_QWORD *)(a1 + 56) )
      nullsub_604(a1);
    v4 = *(_QWORD *)(a1 + 56);
    if ( *(_DWORD *)(v4 + 6876) )
    {
      sub_1801B71E0(v4 + 6876, 0xFFFFFFFFLL, 0xFFFFFFFFLL);
      *(_DWORD *)(v4 + 6876) = 0;
    }
    if ( !*(_QWORD *)(a1 + 56) )
      nullsub_604(a1);
    v5 = *(_QWORD *)(a1 + 56);
    if ( *(_DWORD *)(v5 + 6876) )
    {
      sub_1801B71E0(v5 + 6876, 0xFFFFFFFFLL, 0xFFFFFFFFLL);
      *(_DWORD *)(v5 + 6876) = 0;
    }
  }
  if ( !*(_QWORD *)(a1 + 56) )
    nullsub_604(a1);
  sub_180972470(*(_QWORD *)(*(_QWORD *)(a1 + 56) + 3728LL));
  return sub_180B73A40(a1, a2);
}
```

Linux:
```c
__int64 __fastcall sub_137C660(__int64 a1, unsigned __int8 a2)
{
  __int64 v2; // rax
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v6; // [rsp+0h] [rbp-60h] BYREF
  __int64 v7; // [rsp+8h] [rbp-58h] BYREF
  _QWORD v8[2]; // [rsp+10h] [rbp-50h] BYREF
  __int128 v9; // [rsp+20h] [rbp-40h]
  __int64 v10; // [rsp+30h] [rbp-30h]
  int v11; // [rsp+38h] [rbp-28h]
  __int16 v12; // [rsp+3Ch] [rbp-24h]

  if ( *(_BYTE *)(a1 + 72) )
  {
    v9 = 0LL;
    v12 = 0;
    v6 = 1LL;
    v7 = 0LL;
    v8[0] = 0LL;
    v8[1] = 0LL;
    v10 = -1LL;
    v11 = -1;
    sub_9F5D20(v8, 1LL);
    LODWORD(v7) = v7 + 1;
    *(_DWORD *)v8[0] = 72;
    sub_1D749F0(a1 + 8, &v6);
    sub_9BF4F0(&v7);
    *(_BYTE *)(a1 + 72) = 0;
    sub_1339E60(a1);
    v2 = *(_QWORD *)(a1 + 56);
    if ( v2 )
      goto LABEL_3;
  }
  else
  {
    v2 = *(_QWORD *)(a1 + 56);
    if ( v2 )
      goto LABEL_3;
  }
  nullsub_1293(a1);
  v2 = *(_QWORD *)(a1 + 56);
LABEL_3:
  *(_BYTE *)(*(_QWORD *)(v2 + 3704) + 222LL) = 0;
  v3 = *(_QWORD *)(a1 + 56);
  if ( !v3 )
  {
    nullsub_1293(a1);
    v3 = *(_QWORD *)(a1 + 56);
  }
  *(_QWORD *)(v3 + 7656) = 0LL;
  if ( a2 )
  {
    sub_1341410(a1);
    sub_1340900(a1);
    v4 = *(_QWORD *)(a1 + 56);
    if ( v4 )
      goto LABEL_7;
LABEL_11:
    nullsub_1293(a1);
    v4 = *(_QWORD *)(a1 + 56);
    goto LABEL_7;
  }
  v4 = *(_QWORD *)(a1 + 56);
  if ( !v4 )
    goto LABEL_11;
LABEL_7:
  sub_1318D90(*(_QWORD *)(v4 + 4488));
  return sub_1565440(a1, a2);
}
```

where `a2` can be something like a boolean

### 5. Rename Functions

Once identified, rename both functions:

```
mcp__ida-pro-mcp__rename batch={
  "func": [
    {"addr": "<drop_weapon_addr>", "name": "CCSPlayer_ItemServices_DropActivePlayerWeapon"},
    {"addr": "<remove_weapons_addr>", "name": "CCSPlayer_ItemServices_RemoveWeapons"}
  ]
}
```

### 6. Find VTable Indices

**ALWAYS** Use SKILL `/get-vtable-index` for each function to get vtable offset and index.

VTable class name: `CCSPlayer_ItemServices`

Run for both functions:
- DropActivePlayerWeapon (expected index: 20 ~ 24, can change on game update)
- RemoveWeapons (expected index: 20 ~ 24, can change on game update)

### 7. Generate Signatures

**DO NOT** use `find_bytes` as it won't work for functions.

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate robust signatures for both functions.

For DropActivePlayerWeapon:
```
/generate-signature-for-function addr=<drop_weapon_addr>
```

For RemoveWeapons:
```
/generate-signature-for-function addr=<remove_weapons_addr>
```

### 8. Write Analysis Results as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write analysis results for both functions.

For DropActivePlayerWeapon:

Required parameters:
- `func_name`: `CCSPlayer_ItemServices_DropActivePlayerWeapon`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 7

VTable parameters:
- `vtable_name`: `CCSPlayer_ItemServices`
- `vfunc_offset`: The offset from step 6
- `vfunc_index`: The index from step 6 (expected: 23)

For RemoveWeapons:

Required parameters:
- `func_name`: `CCSPlayer_ItemServices_RemoveWeapons`
- `func_addr`: The function address from step 4
- `func_sig`: The validated signature from step 7

VTable parameters:
- `vtable_name`: `CCSPlayer_ItemServices`
- `vfunc_offset`: The offset from step 6
- `vfunc_index`: The index from step 6 (expected: 24)

## Function Characteristics Summary

### CCSPlayer_ItemServices_DropActivePlayerWeapon

- **VTable Index**: 23 (may change with updates)
- **Parameters**: `(this, direction_vector, unk1, force_flag, velocity_scale)`
- **Purpose**: Drops the player's active weapon with calculated throw velocity
- **Key Features**:
  - SIMD vector math for 3D velocity calculations
  - Accesses weapon pointer at offset 3704
  - Calls drop logic twice with different parameters
  - Handles physics and velocity scaling

### CCSPlayer_ItemServices_RemoveWeapons

- **VTable Index**: 24 (may change with updates)
- **Parameters**: `(this, cleanup_flag)`
- **Purpose**: Removes all weapons and resets inventory state
- **Key Features**:
  - Checks and clears dirty flag at offset 72
  - Resets weapon service state fields
  - Clears inventory references
  - Optionally calls additional cleanup routines based on flag

## VTable Information

- **VTable Name**: `CCSPlayer_ItemServices::\`vftable'`
- **VTable Mangled Name**:
  - Windows: Not documented
  - Linux: `_ZTV24CCSPlayer_ItemServices`
- **VTable Indices**:
  - DropActivePlayerWeapon: 23 (may change with updates)
  - RemoveWeapons: 24 (may change with updates)

Note: For `server.so`, the first 16 bytes of "vftable" are for RTTI. The real vftable = `_ZTV24CCSPlayer_ItemServices` + `0x10`.

## Output YAML Files

This skill generates **two separate YAML files**, one for each function:

**Platform-specific naming:**
- `server.dll` (Windows):
  - `CCSPlayer_ItemServices_DropActivePlayerWeapon.windows.yaml`
  - `CCSPlayer_ItemServices_RemoveWeapons.windows.yaml`
- `server.so` (Linux):
  - `CCSPlayer_ItemServices_DropActivePlayerWeapon.linux.yaml`
  - `CCSPlayer_ItemServices_RemoveWeapons.linux.yaml`

### DropActivePlayerWeapon YAML:
```yaml
func_va: 0x137aaa0        # Virtual address - changes with updates
func_rva: 0x137aaa0       # Relative virtual address - changes with updates
func_size: 0xb2           # Function size in bytes - changes with updates
func_sig: 55 0F B6 C9 ... # Unique byte signature - changes with updates
vtable_name: CCSPlayer_ItemServices
vfunc_offset: 0xb8        # Offset from vtable start - changes with updates
vfunc_index: 23           # vtable[23] - changes with updates
```

### RemoveWeapons YAML:
```yaml
func_va: 0x137a5e0        # Virtual address - changes with updates
func_rva: 0x137a5e0       # Relative virtual address - changes with updates
func_size: 0x172          # Function size in bytes - changes with updates
func_sig: 55 48 89 E5 ... # Unique byte signature - changes with updates
vtable_name: CCSPlayer_ItemServices
vfunc_offset: 0xc0        # Offset from vtable start - changes with updates
vfunc_index: 24           # vtable[24] - changes with updates
```

## Common Offsets Reference

These offsets are characteristic of both functions and help in identification:

| Offset (Hex) | Offset (Dec) | Description |
|--------------|--------------|-------------|
| 0x38 | 56 | Pointer to player pawn (lazily initialized) |
| 0x48 | 72 | Dirty flag byte (RemoveWeapons) |
| 0xE78 | 3704 | Active weapon pointer offset |
| 0xDE | 222 | Weapon state flag offset (from weapon base) |
| 0x1DE8 | 7656 | Inventory reference field |
| 0x1188 | 4488 | Cleanup function pointer offset |
| 0xC8 | 200 | Drop virtual function offset in weapon vtable |

## Troubleshooting

**If vtable entries don't match expected indices:**
- Game update may have changed vtable layout
- Verify vtable_numvfunc matches expected count (25 for CCSPlayer_ItemServices)
- Look for functions with the characteristic patterns in nearby indices

**If signature validation fails:**
- Function may have been optimized differently
- Extend signature length to include more unique bytes
- Check for compiler differences between builds

**If functions not found in expected range:**
- Use characteristic offset patterns (3704, 72, 7656) to search
- Look for SIMD instructions for DropActivePlayerWeapon
- Search for byte flag operations for RemoveWeapons
