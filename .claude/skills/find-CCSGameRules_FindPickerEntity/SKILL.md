---
name: find-CCSGameRules_FindPickerEntity
description: Find and identify the CCSGameRules_FindPickerEntity function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the FindPickerEntity function by searching for the CCSGameRules vtable and analyzing virtual function patterns.
---

# Find CCSGameRules_FindPickerEntity

Locate `CCSGameRules_FindPickerEntity` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get CCSGameRules VTable Address

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CCSGameRules`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract these values for subsequent steps:
- `vtable_va`: The vtable start address (use as `<VTABLE_START>`)
- `vtable_numvfunc`: The valid vtable entry count (last valid index = count - 1)
- `vtable_entries`: An array of virtual functions starting from vtable[0]

### 2. Decompile virtual functions from vtable_entries[21-30]

Using `vtable_entries` from step 1, decompile virtual functions around indices 21-30:

```
  mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

### 3. Identify by Nullsub Pattern

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

### 4. Decompile and Verify

Decompile the candidate function:
```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

Verify it contains:
- Check for vtable offset +192 (0xC0) comparing to nullsub
- Check for vtable offset +200 (0xC8) comparing to nullsub
- References to CBasePlayerController type checking

### 5. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSGameRules_FindPickerEntity"}]}
```

### 6. Find VTable Offset and Index

**ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.

VTable class name: `CCSGameRules`

### 7. Generate and Validate Unique Signature

**DO NOT** use `find_bytes` as it won't work for function.
**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 8. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CCSGameRules_FindPickerEntity`
- `func_addr`: The function address
- `func_sig`: The validated signature from step 7

VTable parameters:
- `vtable_name`: `CCSGameRules`
- `vfunc_offset`: The offset from step 6
- `vfunc_index`: The index from step 6

## Function Characteristics

- **Parameters**: `(this, player_entity, target, ...)` where `this` is CCSGameRules pointer
- **Purpose**: Appears to handle player interaction/picking logic in the game rules
- **Pattern**: Distinctive nullsub checks at vtable offsets +192 and +200
- **Contains**: Type checking for CBasePlayerController, position/distance calculations

## Related Nullsubs

The function checks these vtable entries:
- **Index 24** (offset 0xC0): `nullsub_843` - Pre-operation hook
- **Index 25** (offset 0xC8): `nullsub_844` - Post-operation hook

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSGameRules_FindPickerEntity.windows.yaml`
- `server.so` → `CCSGameRules_FindPickerEntity.linux.yaml`

```yaml
func_va: 0x16f8ca0       # Virtual address - changes with game updates
func_rva: 0x16f8ca0      # Relative virtual address - changes with game updates
func_size: 0x3a1         # Function size in bytes - changes with game updates
func_sig: 55 48 89 E5 41 57 41 56 ...  # Unique byte signature - changes with game updates
vtable_name: CCSGameRules
vfunc_offset: 0xe0       # Offset from vtable start - changes with game updates
vfunc_index: 26          # vtable[26] - changes with game updates
```
