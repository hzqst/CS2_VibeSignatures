---
name: find-CBaseEntity_IsPlayerPawn
description: Find and identify the CBaseEntity_IsPlayerPawn virtual function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the IsPlayerPawn check function by analyzing the CBaseEntity vtable and identifying the simple boolean check pattern that returns whether a byte at offset ~1400 equals zero.
---

# Find CBaseEntity_IsPlayerPawn

Locate `CBaseEntity_IsPlayerPawn` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Search for Reference String

Search for the string `"Ignoring speaking bot %s at round end"`:

```
mcp__ida-pro-mcp__find_regex pattern="Ignoring speaking bot.*at round end"
```

Note the string address.

### 2. Find Cross-Reference and Containing Function

Get xrefs to the string address:

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_address>"
```

This will lead to `CCSGameRules::Think` function. Decompile it and look for this code pattern:

```c
v81 = (const char *)(*(__int64 (__fastcall **)(_QWORD))(**(_QWORD **)(v78 + 24) + 1128LL))(*(_QWORD *)(v78 + 24));
Msg("Ignoring speaking bot %s at round end\n", v81);
...
sub_XXXXXXX((unsigned __int16 *)&v123);  // <-- This is the player iterator function
```

Note the address of `sub_XXXXXXX` (the function called after the Msg).

### 3. Decompile Player Iterator and Extract VTable Offset

Decompile the player iterator function:

```
mcp__ida-pro-mcp__decompile addr="<sub_XXXXXXX_address>"
```

Look for this code pattern:

```c
if ( (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)v3 + 1344LL))(v3)  // <-- 1344 is IsPlayerPawn vtable offset
    && (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)v4 + 3344LL))(v4)
    && (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)v4 + 3208LL))(v4) )
{
    if ( *(_BYTE *)(v4 + 6832) ? *(_QWORD *)(v4 + 6824) : 0LL )
      break;
}
```

Extract the **first vtable offset** from this pattern (e.g., `1344`). This is the `CBaseEntity::IsPlayerPawn` vtable offset.

Calculate:
- **VTable Offset**: The value from the pattern (e.g., 1344 = 0x540)
- **VTable Index**: offset / 8 (e.g., 1344 / 8 = **168**)

### 4. Get CBaseEntity VTable and Verify

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CBaseEntity`.

Get the function address at the calculated vtable index and decompile to verify:

```
mcp__ida-pro-mcp__decompile addr="<vtable_entries[168]>"
```

The function should match this pattern:
```c
bool __fastcall sub_XXXXXX(__int64 a1)
{
  return *(_BYTE *)(a1 + 1472) == 0;  // offset 0x5C0, can change on game update
}
```

### 5. Write Analysis Results as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CBaseEntity_IsPlayerPawn`
- `func_addr`: Leave empty
- `func_sig`: Leave empty

VTable parameters:
- `vtable_name`: `CBaseEntity`
- `vfunc_index`: The vtable index from step 3 (e.g., 168)
- `vfunc_offset`: `vfunc_index * 8` (e.g., 1344)

## Function Characteristics

- **Parameters**: `(this)` where `this` is CBaseEntity pointer
- **Return**: `bool` - Returns true if entity is a player pawn (byte at offset 1472 equals 0)
- **Size**: 11 bytes (0xB)
- **Offset Checked**: 1472 (0x5C0) - likely a flag or type indicator in CBaseEntity, this offset can change on game update.

## VTable Information

- **VTable Name**: `CBaseEntity::`vftable'`
- **VTable Mangled Name (Windows)**: `??_7CBaseEntity@@6B@`
- **VTable Mangled Name (Linux)**: `_ZTV11CBaseEntity`
- **VTable Index**: 168 - This can change when game updates.
- **VTable Offset**: 0x540 (168 * 8 = 1344) - This can change when game updates.

* Note that for `server.so`, the first 16 bytes of "vftable" are for RTTI. The real vftable = `_ZTV11CBaseEntity` + `0x10`.

## Expected Signature Pattern

The function has a very distinctive byte pattern:

**Bytes**: `80 BF C0 05 00 00 00 0F 94 C0 C3`

Breakdown:
- `80 BF C0 05 00 00` - `cmp byte ptr [rdi+5C0h], 0` (opcode + offset)
- `0F 94 C0` - `setz al` (set byte if zero)
- `C3` - `retn`

This signature is stable because:
- Struct offset (0x5C0/1472) is part of class layout
- Simple opcodes are deterministic
- No relocations or address references

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBaseEntity_IsPlayerPawn.windows.yaml`
- `server.so` → `CBaseEntity_IsPlayerPawn.linux.yaml`

```yaml
func_va: 0x9b58a0           # Virtual address - changes with game updates
func_rva: 0x9b58a0          # Relative virtual address (Linux: VA - 0) - changes with game updates
func_size: 0xb              # Function size (11 bytes) - changes with game updates
func_sig: 80 BF C0 05 00 00 00 0F 94 C0 C3  # Unique byte signature - may change with game updates
```

## Notes

- This is a simple virtual function that checks a flag/type byte in CBaseEntity
- The offset 1472 (0x5C0) appears to indicate whether the entity is a player pawn
- The function is purely a predicate with no side effects
- Being at vtable index 168 suggests it's part of the entity type/capability query interface
- The vtable offset 1344 (0x540) is commonly used in player iteration patterns to filter for player pawns
