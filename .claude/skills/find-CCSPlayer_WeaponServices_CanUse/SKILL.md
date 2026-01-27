---
name: find-CCSPlayer_WeaponServices_CanUse
description: Find and identify the CCSPlayer_WeaponServices_CanUse function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CanUse weapon validation function by searching for the vtable, analyzing virtual function entries, and identifying by the "weapon_taser" string reference.
---

# Find CCSPlayer_WeaponServices_CanUse

Locate `CCSPlayer_WeaponServices_CanUse` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the CCSPlayer_WeaponServices vtable:
   ```
   mcp__ida-pro-mcp__list_globals queries={"count": 50, "filter": "*CCSPlayer_WeaponServices*", "offset": 0}
   ```

   Look for `_ZTV24CCSPlayer_WeaponServices` (Linux) or similar vtable name.

2. Calculate vtable entry address for index 26:
   - Vtable index 26 = offset 0xD0 (26 * 8 bytes)
   - For Linux: Add 0x10 to vtable base for RTTI offset, then add 0xD0
   - Address = vtable_base + 0x10 + 0xD0

3. Read the function pointer at that vtable entry:
   ```
   mcp__ida-pro-mcp__get_int queries={"addr": "<calculated_address>", "ty": "u64le"}
   ```

4. Decompile the function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

5. Verify by searching for "weapon_taser" string reference in the decompiled code:
   - The function should contain logic that references "weapon_taser"
   - Look for pattern: `sub_191A840(&qword_256F7A8, "weapon_taser")`
   - This is the key identifier for this function

6. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSPlayer_WeaponServices_CanUse"}]}
   ```

7. Find VTable and Calculate Offset:

   **ALWAYS** Use SKILL `/get-vftable-index` to get vtable offset and index for the function.

   VTable class name to search for:
   - Windows: `??_7CCSPlayer_WeaponServices@@6B@`
   - Linux: `_ZTV24CCSPlayer_WeaponServices`

   Note: For Linux `server.so`, the first 16 bytes of vtable are for RTTI metadata. The real vtable starts at `_ZTV24CCSPlayer_WeaponServices + 0x10`.

8. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

9. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CCSPlayer_WeaponServices_CanUse`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 8

   VTable parameters (when this is a virtual function):
   - `vtable_name`: `CCSPlayer_WeaponServices`
   - `vtable_mangled_name`: `??_7CCSPlayer_WeaponServices@@6B@` (Windows) or `_ZTV24CCSPlayer_WeaponServices` (Linux)
   - `vfunc_offset`: The offset from step 7
   - `vfunc_index`: The index from step 7

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

## VTable Information

- **VTable Name**: `CCSPlayer_WeaponServices::\`vftable'`
- **VTable Mangled Name**:
  - Windows: `??_7CCSPlayer_WeaponServices@@6B@`
  - Linux: `_ZTV24CCSPlayer_WeaponServices`
- **VTable Index**: 26 - This can change when game updates.
- **VTable Offset**: 0xD0 (26 * 8 bytes) - This can change when game updates.

Note that for `server.so`, the first 16 bytes of "vftable" are for RTTI. The real vftable = `_ZTV24CCSPlayer_WeaponServices` + `0x10`.

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSPlayer_WeaponServices_CanUse.windows.yaml`
- `server.so` → `CCSPlayer_WeaponServices_CanUse.linux.yaml`

```yaml
func_va: 0x13cc6a0           # Virtual address of the function - This can change when game updates.
func_rva: 0x13cc6a0          # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0x3af             # Function size in bytes - This can change when game updates.
func_sig: 55 48 8D 15 ?? ?? ?? ?? 48 89 E5 41 55 41 54 49 89 FC 53 48 89 F3 48 83 EC 08 48 8B 07 48 8B 80 E8 00 00 00 48 39 D0 0F 85 ?? ?? ?? ?? 80 BF A8 00 00 00 00 0F 85 ?? ?? ?? ?? 48 8B 7F 38 48 85  # Unique byte signature - This can change when game updates.
vtable_name: CCSPlayer_WeaponServices
vtable_mangled_name: _ZTV24CCSPlayer_WeaponServices
vfunc_offset: 0xd0           # Offset from vtable start - This can change when game updates.
vfunc_index: 26              # vtable[26] - This can change when game updates.
```
