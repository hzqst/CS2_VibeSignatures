---
name: find-CCSPlayer_WeaponServices_CanUse
description: Find and identify the CCSPlayer_WeaponServices_CanUse function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CanUse weapon validation function by searching for the vtable, analyzing virtual function entries, and identifying by the "weapon_taser" string reference.
---

# Find CCSPlayer_WeaponServices_CanUse

Locate `CCSPlayer_WeaponServices_CanUse` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get CCSPlayer_WeaponServices VTable Address

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CCSPlayer_WeaponServices`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract these values for subsequent steps:
- `vtable_va`: The vtable start address (use as `<VTABLE_START>`)
- `vtable_numvfunc`: The valid vtable entry count (last valid index = count - 1)

### 2. Read VTable Entry at Index ~26

```python
mcp__ida-pro-mcp__py_eval code="""
import ida_bytes, ida_name

vtable_start = <VTABLE_ADDRESS>  # Use vtableAddress from step 1
ptr_size = 8

for i in range(24, 30):
    func_ptr = ida_bytes.get_qword(vtable_start + i * ptr_size)
    func_name = ida_name.get_name(func_ptr) or "unknown"
    print(f"vftable[{i}]: {hex(func_ptr)} -> {func_name}")
"""
```

### 3. Decompile and Verify by "weapon_taser" String

Decompile the function:
```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

Verify by searching for "weapon_taser" string reference in the decompiled code:
- The function should contain logic that references "weapon_taser"
- Look for pattern: `sub_XXXXXXX(&qword_XXXXXXX, "weapon_taser")`
- This is the key identifier for this function

### 4. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSPlayer_WeaponServices_CanUse"}]}
```

### 5. Find VTable Offset and Index

**ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.

VTable class name: `CCSPlayer_WeaponServices`

### 6. Generate and Validate Unique Signature

**DO NOT** use `find_bytes` as it won't work for function.
**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 7. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CCSPlayer_WeaponServices_CanUse`
- `func_addr`: The function address
- `func_sig`: The validated signature from step 6

VTable parameters:
- `vtable_name`: `CCSPlayer_WeaponServices`
- `vfunc_offset`: The offset from step 5
- `vfunc_index`: The index from step 5

## Signature Pattern

The function contains a string reference:
```
"weapon_taser"
```

This string is used to look up weapon data in a hash map/dictionary structure, as part of special validation logic for the Zeus x27 taser weapon.

## Function Characteristics

- **Purpose**: Validates whether a player can acquire/use a specific weapon
- **Parameters**: `(this, weapon_entity)` where `this` is CCSPlayer_WeaponServices pointer, `weapon_entity` is the weapon to validate
- **Returns**: Boolean-like (0 = cannot use, non-zero = can use)
- **Key Logic**:
  - Checks if player can pickup weapon
  - References `CBasePlayerWeapon` and `CCSWeaponBase` typeinfo
  - Has special validation logic for taser (weapon_taser) to prevent duplicate pickups
  - Validates weapon slots in player inventory

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSPlayer_WeaponServices_CanUse.windows.yaml`
- `server.so` → `CCSPlayer_WeaponServices_CanUse.linux.yaml`

```yaml
func_va: 0x13cc6a0           # Virtual address - changes with game updates
func_rva: 0x13cc6a0          # Relative virtual address - changes with game updates
func_size: 0x3af             # Function size in bytes - changes with game updates
func_sig: 55 48 8D 15 ?? ?? ?? ?? ...  # Unique byte signature - changes with game updates
vtable_name: CCSPlayer_WeaponServices
vfunc_offset: 0xd0           # Offset from vtable start - changes with game updates
vfunc_index: 26              # vtable[26] - changes with game updates
```
