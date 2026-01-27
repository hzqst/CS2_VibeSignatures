---
name: find-CGameRules_ClientSettingsChanged
description: Find and identify the CGameRules_ClientSettingsChanged function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the ClientSettingsChanged function by searching for the "fov_desired" string reference and analyzing cross-references.
---

# Find CGameRules_ClientSettingsChanged

Locate `CGameRules::ClientSettingsChanged` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="fov_desired"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing functions and look for this pattern:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

   The target function should contain code similar to:
   ```cpp
   if ( (_DWORD)PlayerInfo != -1 )
       v4 = (_DWORD)PlayerInfo - 1;
   v31 = (_BYTE *)v30(g_Source2EngineToServer, v4, "fov_desired");
   v23 = v22;
   if ( v22 && *v22 && (unsigned int)V_atoi(v22) )
   ```

   You should also see references to `oldname`, `newname` and `player_changename` within the function.

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CGameRules_ClientSettingsChanged"}]}
   ```

5. Find VTable and Calculate Offset:

   **ALWAYS** Use SKILL `/get-vftable-index` to get vtable offset and index for the function.

6. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

7. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-vfunc-ida-analysis-output-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CGameRules_ClientSettingsChanged`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 6

   VTable parameters (when this is a virtual function):
   - `vtable_name`: `CGameRules` or `CCSGameRules` (depending on which vtable contains it)
   - `vfunc_offset`: The offset from step 5
   - `vfunc_index`: The index from step 5

## Signature Pattern

The function contains a call to get the `fov_desired` convar value:
```cpp
v31 = (_BYTE *)v30(g_Source2EngineToServer, v4, "fov_desired");
```

And contains string references related to player name changes:
- `oldname`
- `newname`
- `player_changename`

## Function Characteristics

- **Prototype**: `bool CGameRules::ClientSettingsChanged(CGameRules *pGameRules, CBasePlayerController *pPlayerController)`
- **Parameters**:
  - `pGameRules`: Pointer to the CGameRules instance (this)
  - `pPlayerController`: Pointer to the player controller whose settings changed
- **Return**: `bool` indicating success/failure

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CGameRules_ClientSettingsChanged.windows.yaml`
- `server.so` → `CGameRules_ClientSettingsChanged.linux.yaml`

```yaml
func_va: 0x180XXXXXX      # Virtual address of the function - This can change when game updates.
func_rva: 0xXXXXXX        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xXXX          # Function size in bytes - This can change when game updates.
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - This can change when game updates.
vtable_name: CGameRules   # (if virtual function)
vfunc_offset: 0xXXX       # Offset from vtable start - This can change when game updates. (if virtual function)
vfunc_index: XX           # vtable[XX] - This can change when game updates. (if virtual function)
```
