---
name: find-CServerSideClient_IsHearingClient
description: Find and identify the CServerSideClient_IsHearingClient function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 engine2.dll or libengine2.so to locate the IsHearingClient function by searching for CServerSideClient vtable and analyzing virtual function patterns.
---

# Find CServerSideClient_IsHearingClient

Locate `CServerSideClient_IsHearingClient` in CS2 engine2.dll or libengine2.so using IDA Pro MCP tools.

## Method

1. Search for CServerSideClient vtable:
   ```
   mcp__ida-pro-mcp__list_globals(queries={"filter": "*CServerSideClient*"})
   ```
   Look for:
   - Windows: `??_7CServerSideClient@@6B@`
   - Linux: `_ZTV19CServerSideClient`

2. Get vtable address and read entries at index 16-25:
   ```
   mcp__ida-pro-mcp__get_bytes regions={"addr": "<vtable_addr>", "size": 208}
   ```

3. Decompile virtual functions at indices 16-25 to find the pattern:
   ```
   mcp__ida-pro-mcp__decompile addr="<vfunc_addr>"
   ```

4. Identify the function by this characteristic pattern:
   ```c
   if ( a2 == *(_DWORD *)(a1 + 72) )
     return *(_BYTE *)(a1 + 3824);
   if ( a2 < 0 || (v4 = *(_QWORD *)(a1 + 80), a2 >= *(_DWORD *)(v4 + 592)) )
     v5 = 0LL;
   else
     v5 = *(_QWORD **)(*(_QWORD *)(v4 + 600) + 8LL * a2);
   ```

5. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CServerSideClient_IsHearingClient"}]}
   ```

6. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

7. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CServerSideClient_IsHearingClient`
   - `func_addr`: The function address from step 4
   - `func_sig`: The validated signature from step 6

   VTable parameters (this is a virtual function):
   - `vfunc_name`: `CServerSideClient`
   - `vfunc_mangled_name`: `??_7CServerSideClient@@6B@` (Windows) or `_ZTV19CServerSideClient` (Linux)
   - `vfunc_offset`: The offset from vtable (index * 8)
   - `vfunc_index`: The vtable index (typically 19)

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

Key code pattern to look for:
```c
v7 = *((_DWORD *)v5 + ((__int64)*(int *)(a1 + 72) >> 5) + 756);
return _bittest(&v7, *(_DWORD *)(a1 + 72) & 0x1F);
```

## VTable Information

- **VTable Name**: `CServerSideClient::\`vftable'`
- **VTable Mangled Name (Windows)**: `??_7CServerSideClient@@6B@`
- **VTable Mangled Name (Linux)**: `_ZTV19CServerSideClient`
- **VTable Index**: 19 - This can change when game updates.
- **VTable Offset**: 0x98 (19 * 8) - This can change when game updates.

Note: For Linux `libengine2.so`, the first 16 bytes of vtable are for RTTI metadata. The real vtable starts at `_ZTV19CServerSideClient + 0x10`.

## Output YAML Format

The output YAML filename depends on the platform:
- `engine2.dll` → `CServerSideClient_IsHearingClient.windows.yaml`
- `libengine2.so` → `CServerSideClient_IsHearingClient.linux.yaml`

```yaml
func_va: 0x1800c8c10      # Virtual address - changes with game updates
func_rva: 0xc8c10         # Relative virtual address (VA - image base) - changes with game updates
func_size: 0xd4           # Function size in bytes - changes with game updates
func_sig: 40 53 48 83 EC 20 48 8B D9 3B 51 48 75 ?? ...  # Unique byte signature
vfunc_name: CServerSideClient
vfunc_mangled_name: ??_7CServerSideClient@@6B@
vfunc_offset: 0x98        # Offset from vtable start - changes with game updates
vfunc_index: 19           # vtable[19] - changes with game updates
```
