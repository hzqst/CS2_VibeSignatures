---
name: find-CCSPlayerController_Respawn
description: Find and identify the CCSPlayerController_Respawn function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the Respawn function by finding the CCSPlayerController vtable and analyzing virtual function patterns.
---

# Find CCSPlayerController_Respawn

Locate `CCSPlayerController_Respawn` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get CCSPlayerController VTable Address

**ALWAYS** Use SKILL `/get-vftable-address` to get vtable address and size.

Class name to search for: `CCSPlayerController`

This will return:
- `vtableAddress`: The vtable start address
- `numberOfVirtualFunctions`: Total count of virtual functions (last valid index = count - 1)

### 2. Decompile vtable[270 ~ last] and Search for Pattern

List virtual functions from index 270 to the last valid index:

```python
mcp__ida-pro-mcp__py_eval code="""
import ida_bytes, ida_name

vtable_start = <VTABLE_ADDRESS>  # Use vtableAddress from step 1
ptr_size = 8
start_index = 270
end_index = <LAST_VALID_INDEX>  # Use (numberOfVirtualFunctions - 1) from step 1

for i in range(start_index, end_index + 1):
    func_ptr = ida_bytes.get_qword(vtable_start + i * ptr_size)
    func_name = ida_name.get_name(func_ptr) or "unknown"
    print(f"vftable[{i}]: {hex(func_ptr)} -> {func_name}")
"""
```

Then decompile each function:
```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

### 3. Identify CCSPlayerController_Respawn by Code Pattern (Cross-Platform)

The function has **platform-specific differences** but shares a **common ending pattern**.

#### Common Pattern (Both Platforms) - MOST RELIABLE

The function ends with a **double GetPlayerPawn + vfunc forwarding** pattern:

```cpp
result = GetPlayerPawn(a1);  // Called once
if ( result )
{
    v6 = GetPlayerPawn(a1);  // Called again (same function)
    return (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v6 + PAWN_VFUNC_OFFSET))(v6);
}
return result;
```

| Platform | Pawn VFunc Offset | VFunc Index |
|----------|-------------------|-------------|
| Windows  | 3368 (0xD28)      | ~421        |
| Linux    | 3376 (0xD30)      | ~422        |

#### Windows-Specific Pattern

```cpp
v2 = GetCurrentTick(&v7, -1.0);
if ( CompareAndUpdate((float *)(a1 + OFFSET_A), v2) )
{
    NotifyChange(a1 + OFFSET_A, -1, -1);
    *(float *)(a1 + OFFSET_A) = *v2;
}
v3 = GetCurrentTick(&v7, -1.0);
SetThinkFunction(a1, ThinkFunc, *v3, MAGIC_NUMBER, 0LL);  // Magic: 0x760791F4
*(_BYTE *)(a1 + OFFSET_B) = 0;
// ... state resets ...
```

**Windows identifying features:**
- `GetCurrentTick` called twice with `-1.0` parameter
- `SetThinkFunction` with magic number `0x760791F4` (1980207604)
- Clean, simple code flow

#### Linux-Specific Pattern

```cpp
sub_XXXXXXXX();  // Initialization call at start
v2 = *(_BYTE *)(a1 + OFFSET_FLAG) == 0;
*(_BYTE *)(a1 + OFFSET_A) = 0;
if ( !v2 )
{
    // Complex StateChanged handling with string:
    // "CNetworkTransmitComponent::StateChanged(%s) @%s:%d"
    // ... network state management ...
}
// State resets at end before GetPlayerPawn pattern
v3 = *(_QWORD *)(a1 + OFFSET_PAWN_PTR);
*(_BYTE *)(a1 + OFFSET_B) = 0;
*(_DWORD *)(a1 + OFFSET_C) = 0;
*(_BYTE *)(a1 + OFFSET_D) = 0;
*(_DWORD *)(a1 + OFFSET_E) = 0;
// ... then common ending pattern ...
```

**Linux identifying features:**
- References `"CNetworkTransmitComponent::StateChanged(%s) @%s:%d"` string
- More complex code with network state handling
- Multiple consecutive state resets before GetPlayerPawn

#### State Reset Pattern (Both Platforms)

Both versions have multiple consecutive state field resets:

```cpp
*(_BYTE *)(a1 + offset1) = 0;
*(_DWORD *)(a1 + offset2) = 0;
*(_BYTE *)(a1 + offset3) = 0;
*(_DWORD *)(a1 + offset4) = 0;
```

**Key identifying characteristics (priority order):**
1. **[MOST RELIABLE]** Ends with double `GetPlayerPawn` call + pawn vfunc forwarding
2. **[Windows]** `SetThinkFunction` with magic number `0x760791F4`
3. **[Linux]** References `"CNetworkTransmitComponent::StateChanged"` string
4. **[Both]** Multiple consecutive byte/dword field resets to 0

### 4. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSPlayerController_Respawn"}]}
```

### 5. Find VTable Offset and Index

**ALWAYS** Use SKILL `/get-vftable-index` to get vtable offset and index for the function.

VTable class name: `CCSPlayerController`

### 6. Generate and Validate Unique Signature

**DO NOT** use `find_bytes` as it won't work for function.
**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 7. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CCSPlayerController_Respawn`
- `func_addr`: The function address
- `func_sig`: The validated signature from step 6

VTable parameters:
- `vtable_name`: `CCSPlayerController`
- `vtable_mangled_name`: `??_7CCSPlayerController@@6B@` (Windows) or `_ZTV19CCSPlayerController` (Linux)
- `vfunc_offset`: The offset from step 5
- `vfunc_index`: The index from step 5

## Function Characteristics

- **VTable Index**: ~272 (Windows) / ~274 (Linux) - **Index varies by platform and game version**
- **Parameters**: `(this)` where `this` is CCSPlayerController pointer
- **Purpose**: Handles player respawn logic, resetting various state flags and forwarding to pawn

### Platform Differences

| Aspect | Windows | Linux |
|--------|---------|-------|
| Code complexity | Simple, clean flow | Complex with network state handling |
| SetThink magic | `0x760791F4` visible | Not directly visible |
| String reference | None | `"CNetworkTransmitComponent::StateChanged..."` |
| Pawn vfunc offset | 3368 (0xD28) | 3376 (0xD30) |

### Distinguishing Features

| Feature | Windows | Linux |
|---------|---------|-------|
| **Double GetPlayerPawn + vfunc** | ✅ Present | ✅ Present |
| GetCurrentTick pattern | ✅ Twice with -1.0 | ❌ Not visible |
| SetThinkFunction magic | ✅ `0x760791F4` | ❌ Not visible |
| StateChanged string | ❌ None | ✅ Present |
| State reset pattern | ✅ Multiple resets | ✅ Multiple resets |

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSPlayerController_Respawn.windows.yaml`
- `server.so` → `CCSPlayerController_Respawn.linux.yaml`

### Windows Example

```yaml
func_va: 0x1809B8530       # Virtual address - changes with game updates
func_rva: 0x9B8530         # Relative virtual address - changes with game updates
func_size: 0x129           # Function size in bytes - changes with game updates
func_sig: XX XX XX XX XX   # Unique byte signature - changes with game updates
vtable_name: CCSPlayerController
vtable_mangled_name: ??_7CCSPlayerController@@6B@
vfunc_offset: 0x880        # Offset from vtable start - changes with game updates
vfunc_index: 272           # vtable index - changes with game updates
```

### Linux Example

```yaml
func_va: 0x1341230         # Virtual address - changes with game updates
func_rva: 0x1341230        # Relative virtual address - changes with game updates
func_size: 0x2B0           # Function size in bytes (larger due to inlining)
func_sig: XX XX XX XX XX   # Unique byte signature - changes with game updates
vtable_name: CCSPlayerController
vtable_mangled_name: _ZTV19CCSPlayerController
vfunc_offset: 0x890        # Offset from vtable start - changes with game updates
vfunc_index: 274           # vtable index - changes with game updates
```
