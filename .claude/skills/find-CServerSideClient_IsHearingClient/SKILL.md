---
name: find-CServerSideClient_IsHearingClient
description: Find and identify the CServerSideClient_IsHearingClient function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 engine2.dll or libengine2.so to locate the IsHearingClient function by searching for CServerSideClient vtable and analyzing virtual function patterns.
---

# Find CServerSideClient_IsHearingClient

Locate `CServerSideClient_IsHearingClient` in CS2 engine2.dll or libengine2.so using IDA Pro MCP tools.

## Method

### 1. Get CServerSideClient VTable Address

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CServerSideClient`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract these values for subsequent steps:
- `vtable_va`: The vtable start address (use as `<VTABLE_START>`)
- `vtable_numvfunc`: The valid vtable entry count (last valid index = count - 1)
- `vtable_entries`: An array of virtual functions starting from vtable[0]

### 2. Decompile virtual functions from vtable_entries[16-25]

Using `vtable_entries` from step 1, decompile virtual functions around indices 16-25:

```
  mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

### 3. Decompile and Identify by Pattern

Decompile virtual functions at indices 16-25:
```
mcp__ida-pro-mcp__decompile addr="<vfunc_addr>"
```

Identify the function by this characteristic pattern:
```c
if ( a2 == *(_DWORD *)(a1 + 72) )
  return *(_BYTE *)(a1 + 3824);
if ( a2 < 0 || (v4 = *(_QWORD *)(a1 + 80), a2 >= *(_DWORD *)(v4 + 592)) )
  v5 = 0LL;
else
  v5 = *(_QWORD **)(*(_QWORD *)(v4 + 600) + 8LL * a2);
```

Key code pattern to look for:
```c
v7 = *((_DWORD *)v5 + ((__int64)*(int *)(a1 + 72) >> 5) + 756);
return _bittest(&v7, *(_DWORD *)(a1 + 72) & 0x1F);
```

### 4. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CServerSideClient_IsHearingClient"}]}
```

### 5. Find VTable Offset and Index

**ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.

VTable class name: `CServerSideClient`

### 6. Generate and Validate Unique Signature

**DO NOT** use `find_bytes` as it won't work for function.
**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 7. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CServerSideClient_IsHearingClient`
- `func_addr`: The function address
- `func_sig`: The validated signature from step 6

VTable parameters:
- `vtable_name`: `CServerSideClient`
- `vfunc_offset`: The offset from step 5
- `vfunc_index`: The index from step 5

## Function Characteristics

- **Parameters**: `(this, client_index)` where `this` is CServerSideClient pointer, `client_index` is the target client slot
- **Return**: `unsigned __int8` (bool) - whether this client can hear the specified client
- **Key offsets**:
  - `+0x48`: Client slot index
  - `+0x50`: Server pointer
  - `+0xEF0`: Self hearing state (Windows)
  - `+0x250`: Max clients count (in server struct)
  - `+0x258`: Client array pointer (in server struct)

## Identification Pattern

The function checks:
1. If target client is self, return self hearing state
2. Get target client from server's client array
3. Check HLTV replay conditions
4. Return bit from hearing bitmask

## Output YAML Format

The output YAML filename depends on the platform:
- `engine2.dll` → `CServerSideClient_IsHearingClient.windows.yaml`
- `libengine2.so` → `CServerSideClient_IsHearingClient.linux.yaml`

```yaml
func_va: 0x1800c8c10      # Virtual address - changes with game updates
func_rva: 0xc8c10         # Relative virtual address (VA - image base) - changes with game updates
func_size: 0xd4           # Function size in bytes - changes with game updates
func_sig: 40 53 48 83 EC 20 48 8B D9 3B 51 48 75 ?? ...  # Unique byte signature
vtable_name: CServerSideClient
vfunc_offset: 0x98        # Offset from vtable start - changes with game updates
vfunc_index: 19           # vtable[19] - changes with game updates
```
