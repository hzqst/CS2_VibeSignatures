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

### 3. Identify DropActivePlayerWeapon (Index 23)

Look for a function with these characteristics:

**Pattern 1: Lazy initialization of this+56**
- Repeatedly checks `[this+56]` (0x38) for null
- Calls initialization function if null
- Pattern appears 3+ times in the function

**Pattern 2: Reads weapon pointer from offset 3704**
- Accesses `[rax+0xE78]` where 0xE78 = 3704 decimal
- This is the active weapon pointer offset

**Pattern 3: Dual virtual function calls**
- Calls the same vtable offset (0xC8 = 200 decimal) twice
- First call with scaled velocity vector
- Second call with null/zero parameters

**Pattern 4: SIMD vector-scaling math**
- Uses `__m128` parameter for velocity calculations
- SIMD instructions: `movsldup`, `mulps`, `movlps`, `movq`
- Scales a 3D direction vector with force multiplier

**Assembly signature pattern:**
```asm
mov     rax, [rbx+38h]      ; Read this+56
test    rax, rax
jz      <init_label>         ; Jump if null
mov     r14, [rax+0E78h]     ; Read weapon at offset 3704
...
movq    xmm1, qword ptr [r12]  ; Load vector
mulss   xmm2, xmm0             ; Scale Z
movsldup xmm0, xmm0            ; Duplicate scale
mulps   xmm0, xmm1             ; Vector multiply
...
call    qword ptr [rax+0C8h]   ; Virtual call offset 0xC8
```

### 4. Identify RemoveWeapons (Index 24)

Look for a function with these characteristics:

**Pattern 1: Byte flag check at offset 72**
- Checks `byte ptr [rdi+48h]` where 0x48 = 72 decimal
- This is a dirty flag
- Clears the flag later: `mov byte ptr [rbx+48h], 0`

**Pattern 2: Multiple lazy initializations**
- Checks `[this+56]` (0x38) multiple times
- Calls initialization function when null
- Pattern repeats 3+ times

**Pattern 3: Resets weapon state fields**
- Writes zero to `(*(this+56) + 3704 + 222)`: offset 0xE78 + 0xDE = offset 3926
- Writes zero to `(*(this+56) + 7656)`: offset 0x1DE8 = 7656 decimal

**Pattern 4: Cleanup calls and return**
- Calls function via `*(ptr + 4488)` where 0x1188 = 4488 decimal
- Ends with tail call to another function with (this, flag) parameters

**Assembly signature pattern:**
```asm
cmp     byte ptr [rdi+48h], 0  ; Check flag at offset 72
jnz     <special_path>
mov     rax, [rbx+38h]         ; Read this+56
test    rax, rax
jz      <init_label>
mov     rax, [rax+0E78h]       ; Offset 3704
mov     byte ptr [rax+0DEh], 0 ; Offset +222 = 3926
...
mov     qword ptr [rax+1DE8h], 0  ; Offset 7656
...
mov     rdi, [rax+1188h]       ; Offset 4488
call    <cleanup_func>
...
jmp     <final_call>           ; Tail call
```

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
- DropActivePlayerWeapon (expected index: 23)
- RemoveWeapons (expected index: 24)

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
