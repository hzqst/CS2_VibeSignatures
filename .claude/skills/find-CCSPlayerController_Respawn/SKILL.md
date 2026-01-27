---
name: find-CCSPlayerController_Respawn
description: Find and identify the CCSPlayerController_Respawn function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the Respawn function by searching for the characteristic pattern involving _InterlockedOr and network state changes.
---

# Find CCSPlayerController_Respawn

Locate `CCSPlayerController_Respawn` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Identify the Function by Characteristic Pattern

The function can be identified by this characteristic pattern in the decompiled pseudocode:

```c
_InterlockedOr((volatile signed __int32 *)(a1 + 792), 3u);
*(_WORD *)(a1 + 822) = 0;
```

This pattern appears within a network state change handler that logs:
```
"CNetworkTransmitComponent::StateChanged(%s) @%s:%d"
```

**Alternative identification method**: Search for vtable and read entries at index 274.

### 2. Search for the Function

#### Option A: Search by vtable (recommended)

Find CCSPlayerController vtable and read entry at index 274:

```
mcp__ida-pro-mcp__list_globals queries={"count": 100, "filter": "*CCSPlayerController*", "offset": 0}
```

Look for `vftable_CCSPlayerController` or `_ZTV19CCSPlayerController`.

Read vtable entry at index 274 (offset 0x890):
- Calculate address: vtable_base + (274 × 8) = vtable_base + 0x890
- Get bytes at that address to find function pointer

#### Option B: Search by pattern

Search for functions containing the characteristic pattern:

```
mcp__ida-pro-mcp__find_regex pattern="_InterlockedOr.*792.*822"
```

Then decompile candidate functions to verify the pattern.

### 3. Decompile and Verify

```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

Verify the function contains:
- The characteristic `_InterlockedOr((volatile signed __int32 *)(a1 + 792), 3u)` pattern
- Memory access to offsets: 0xBA9, 0xAFC, 0xAC8, 0xBAA, 0xBAC, 0xC3B, 0xC48
- Calls to sub_13F4740, sub_13E3130, sub_142E490
- Network state change logging

### 4. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSPlayerController_Respawn"}]}
```

### 5. Find VTable and Calculate Offset

**ALWAYS** Use SKILL `/get-vftable-index` to get vtable offset and index for the function.

VTable class name to search for:
- Windows: `??_7CCSPlayerController@@6B@`
- Linux: `_ZTV19CCSPlayerController`

Expected results:
- **VTable Index**: 274
- **VTable Offset**: 0x890

Note: For Linux `server.so`, the first 16 bytes of vtable are for RTTI metadata. The real vtable starts at `_ZTV19CCSPlayerController + 0x10`.

### 6. Generate and Validate Unique Signature

**DO NOT** use `find_bytes` as it won't work for function.

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

Expected signature characteristics:
- Length: ~75 bytes
- Contains distinctive memory offsets: 0xBA9, 0xAFC, 0xAC8, 0xBAA, 0xBAC, 0xC3B
- Wildcards for call offsets (E8 XX XX XX XX)

### 7. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CCSPlayerController_Respawn`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 6

VTable parameters (this is a virtual function):
- `vtable_name`: `CCSPlayerController`
- `vtable_mangled_name`: `??_7CCSPlayerController@@6B@` (Windows) or `_ZTV19CCSPlayerController` (Linux)
- `vfunc_offset`: The offset from step 5 (expected: 0x890)
- `vfunc_index`: The index from step 5 (expected: 274)

## Function Characteristics

- **Parameters**: `(__int64 a1)` where `a1` is CCSPlayerController pointer
- **Purpose**: Handles player respawn logic, resets player state, and manages network state changes
- **Key Operations**:
  - Resets byte flags at multiple offsets (0xAFC, 0xBAA, 0xC3B)
  - Clears counters at offsets (0xBAC, 0xC48)
  - Performs atomic OR operation on network flags (offset 0x318/792)
  - Calls inventory update and pawn management functions

## Signature Pattern

The function contains distinctive patterns:
1. Function prologue with multiple register saves: `push rbp; mov rbp, rsp; push r15/r14/r13/r12/rbx`
2. Stack allocation: `sub rsp, 158h`
3. Multiple memory writes to specific offsets (0xBA9, 0xAFC, 0xAC8, 0xBAA, 0xBAC, 0xC3B)
4. Network state change with atomic operation

## VTable Information

- **VTable Name**: `CCSPlayerController::\`vftable'`
- **VTable Mangled Name (Windows)**: `??_7CCSPlayerController@@6B@`
- **VTable Mangled Name (Linux)**: `_ZTV19CCSPlayerController`
- **VTable Index**: 274 - This can change when game updates.
- **VTable Offset**: 0x890 - This can change when game updates.

Note: For `server.so`, the first 16 bytes of vtable are for RTTI metadata. The real vtable starts at `_ZTV19CCSPlayerController + 0x10`.

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSPlayerController_Respawn.windows.yaml`
- `server.so` → `CCSPlayerController_Respawn.linux.yaml`

```yaml
func_va: 0x01340df0       # Virtual address of the function - This can change when game updates.
func_rva: 0x01340df0      # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0x2c3          # Function size in bytes - This can change when game updates.
func_sig: 55 48 89 E5 41 57 41 56 41 55 41 54 53 48 89 FB 48 81 EC 58 01 00 00 E8 ?? ?? ?? ?? 80 BB A9 0B 00 00 00 C6 83 FC 0A 00 00 00 75 74 48 8B BB C8 0A 00 00 C6 83 AA 0B 00 00 00 C7 83 AC 0B 00 00 00 00 00 00 C6 83 3B 0C 00 00 00  # Unique byte signature - This can change when game updates.
vtable_name: CCSPlayerController
vtable_mangled_name: _ZTV19CCSPlayerController
vfunc_offset: 0x890       # Offset from vtable start - This can change when game updates.
vfunc_index: 274          # vtable[274] - This can change when game updates.
```
