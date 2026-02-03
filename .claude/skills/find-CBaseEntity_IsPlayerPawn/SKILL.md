---
name: find-CBaseEntity_IsPlayerPawn
description: Find and identify the CBaseEntity_IsPlayerPawn virtual function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the IsPlayerPawn check function by analyzing the CBaseEntity vtable and identifying the simple boolean check pattern that returns whether a byte at offset ~1400 equals zero.
---

# Find CBaseEntity_IsPlayerPawn

Locate `CBaseEntity_IsPlayerPawn` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get CBaseEntity VTable 

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CBaseEntity`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract these values for subsequent steps:
- `vtable_va`: The vtable start address (use as `<VTABLE_START>`)
- `vtable_numvfunc`: The valid vtable entry count (last valid index = count - 1)
- `vtable_entries`: An array of virtual functions starting from vtable[0]

### 2. Decompile Virtual Functions at Index 160-170

Based on analysis, the function is in range of vtable[160 ~ 170]. Decompile the virtual function in range to verify:

```
mcp__ida-pro-mcp__py_eval code="""
import ida_bytes

vtable_start = <VTABLE_START_ADDRESS>  # From step 1
ptr_size = 8

# Read function pointers for indices 160-170
for idx in range(160, 171):
    addr = vtable_start + (idx * ptr_size)
    ptr_value = ida_bytes.get_qword(addr)
    print(f"Index {idx}: {hex(ptr_value)}")
"""
```

Then decompile each function using:
```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

### 3. Identify the CBaseEntity_IsPlayerPawn

Look for a function matching ALL these criteria:
1. Takes exactly one pointer parameter (`__int64 a1`)
2. Performs exactly one byte-sized memory read from offset relative to that pointer
3. Returns boolean based solely on whether that byte equals zero
4. Contains no function calls, no loops, no side effects
5. Body consists only of: memory read → compare to zero → return

**Expected pattern:**
```c
bool __fastcall sub_XXXXXX(__int64 a1)
{
  return *(_BYTE *)(a1 + 1472) == 0;  // or offset 0x5C0, this offset can change on game update.
}
```

**Assembly pattern:**
```asm
cmp     byte ptr [rdi+5C0h], 0
setz    al
retn
```

### 4. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": {"addr": "<function_addr>", "name": "CBaseEntity_IsPlayerPawn"}}
```

### 5. Generate Signature

**DO NOT** use `find_bytes` as it won't work for function.

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature:

```
/generate-signature-for-function <function_addr>
```

### 6. Write Analysis Results as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CBaseEntity_IsPlayerPawn`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 5

VTable parameters:
- `vtable_name`: `CBaseEntity`
- `vfunc_index`: The vtable index from step 3
- `vfunc_offset`: `vfunc_offset = vfunc_index * 8`

## Function Characteristics

- **Parameters**: `(this)` where `this` is CBaseEntity pointer
- **Return**: `bool` - Returns true if entity is a player pawn (byte at offset 1472 equals 0)
- **Size**: 11 bytes (0xB)
- **Offset Checked**: 1472 (0x5C0) - likely a flag or type indicator in CBaseEntity, this offset can change on game update.

## VTable Information

- **VTable Name**: `CBaseEntity::`vftable'`
- **VTable Mangled Name (Windows)**: `??_7CBaseEntity@@6B@`
- **VTable Mangled Name (Linux)**: `_ZTV11CBaseEntity`
- **VTable Index**: 167 - This can change when game updates.
- **VTable Offset**: 0x538 (167 * 8) - This can change when game updates.

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
- Being at vtable index 167 suggests it's part of the entity type/capability query interface
