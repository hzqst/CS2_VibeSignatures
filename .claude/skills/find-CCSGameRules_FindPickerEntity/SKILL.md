---
name: find-CCSGameRules_FindPickerEntity
description: Find and identify the CCSGameRules_FindPickerEntity function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the FindPickerEntity function by searching for the CCSGameRules vtable and analyzing virtual function patterns.
---

# Find CCSGameRules_FindPickerEntity

Locate `CCSGameRules_FindPickerEntity` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the CCSGameRules vtable string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="vtable for.?CCSGameRules"
   ```

   Or search for CCSGameRules in globals:
   ```
   mcp__ida-pro-mcp__list_globals queries={"count": 100, "filter": "*CCSGameRules*", "offset": 0}
   ```

   Look for:
   - Windows: `??_7CCSGameRules@@6B@`
   - Linux: `_ZTV12CCSGameRules`

2. Get vtable address and read entries at index 21-30:

   For Linux server.so, the vtable structure is:
   - Offset 0x00: offset to this (8 bytes)
   - Offset 0x08: typeinfo pointer (8 bytes)
   - Offset 0x10: **Index 0 starts here**

   Calculate the address for index 21-30:
   - Index 21 is at vtable_base + 0x10 + (21 * 8) = vtable_base + 0xB8

   ```
   mcp__ida-pro-mcp__get_bytes regions={"addr": "<vtable_addr + 0xB8>", "size": 80}
   ```

   Then lookup the function pointers from the bytes.

3. Search for cross-references to nullsub_843 and nullsub_844:

   The target function has a distinctive pattern that checks two nullsubs:
   ```c
   v10 = *(void (**)(void))(*(_QWORD *)a1 + 192LL);  // vtable offset 0xC0, index 24
   if ( v10 != nullsub_843 )
       v10();

   // ... function logic ...

   v13 = *(__int64 (__fastcall **)())(*(_QWORD *)a1 + 200LL);  // vtable offset 0xC8, index 25
   if ( v13 != nullsub_844 )
       ((void (__fastcall *)(__int64))v13)(a1);
   ```

   Search for xrefs to both nullsubs:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs=["<nullsub_843_addr>", "<nullsub_844_addr>"]
   ```

   Find a function that references BOTH nullsubs - this is the target function.

4. Decompile the candidate function to verify the pattern:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

   Verify it contains:
   - Check for vtable offset +192 (0xC0) comparing to nullsub_843
   - Check for vtable offset +200 (0xC8) comparing to nullsub_844
   - References to CBasePlayerController type checking

5. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSGameRules_FindPickerEntity"}]}
   ```

6. Find VTable and Calculate Offset:

   **ALWAYS** Use SKILL `/get-vftable-index` to get vtable offset and index for the function.

   VTable class name to search for:
   - Windows: `??_7CCSGameRules@@6B@`
   - Linux: `_ZTV12CCSGameRules`

   Note: For Linux `server.so`, the first 16 bytes of vtable are for RTTI metadata. The real vtable starts at `_ZTV12CCSGameRules + 0x10`.

7. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

8. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CCSGameRules_FindPickerEntity`
   - `func_addr`: The function address from step 4
   - `func_sig`: The validated signature from step 7

   VTable parameters (when this is a virtual function):
   - `vtable_name`: `CCSGameRules`
   - `vtable_mangled_name`: `??_7CCSGameRules@@6B@` (Windows) or `_ZTV12CCSGameRules` (Linux)
   - `vfunc_offset`: The offset from step 6
   - `vfunc_index`: The index from step 6

## Function Characteristics

- **Parameters**: `(this, player_entity, target, ...)` where `this` is CCSGameRules pointer
- **Purpose**: Appears to handle player interaction/picking logic in the game rules
- **Pattern**: Distinctive nullsub checks at vtable offsets +192 and +200
- **Contains**: Type checking for CBasePlayerController, position/distance calculations

## VTable Information

- **VTable Name**: `CCSGameRules::`vftable'`
- **VTable Mangled Name (Windows)**: `??_7CCSGameRules@@6B@`
- **VTable Mangled Name (Linux)**: `_ZTV12CCSGameRules`
- **VTable Index**: 26 - This can change when game updates.
- **VTable Offset**: 0xE0 - This can change when game updates.

* Note that for `server.so`, the first 16 bytes of vtable are for RTTI. The real vtable = `_ZTV12CCSGameRules` + `0x10`.

## Related Nullsubs

The function checks these vtable entries:
- **Index 24** (offset 0xC0): `nullsub_843` - Pre-operation hook
- **Index 25** (offset 0xC8): `nullsub_844` - Post-operation hook

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSGameRules_FindPickerEntity.windows.yaml`
- `server.so` → `CCSGameRules_FindPickerEntity.linux.yaml`

```yaml
func_va: 0x16f8ca0       # Virtual address of the function - This can change when game updates.
func_rva: 0x16f8ca0      # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0x3a1         # Function size in bytes - This can change when game updates.
func_sig: 55 48 89 E5 41 57 41 56 41 55 49 89 D5 41 54 48 8D 15 ?? ?? ?? ?? 49 89 FC 53 48 89 F3 48 83 EC 78 48 8B 07 48 8B 80 C0 00 00 00 48 39 D0 0F 85 ?? ?? ?? ??  # Unique byte signature - This can change when game updates.
vtable_name: CCSGameRules
vtable_mangled_name: _ZTV12CCSGameRules
vfunc_offset: 0xe0       # Offset from vtable start - This can change when game updates.
vfunc_index: 26          # vtable[26] - This can change when game updates.
```
