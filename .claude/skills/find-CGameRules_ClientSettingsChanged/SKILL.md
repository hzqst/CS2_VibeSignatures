---
name: find-CGameRules_ClientSettingsChanged
description: Find and identify the CGameRules_ClientSettingsChanged function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the ClientSettingsChanged function by searching for the "fov_desired" string reference and analyzing cross-references.
disable-model-invocation: true
---

# Find CGameRules_ClientSettingsChanged

Locate `CGameRules::ClientSettingsChanged` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

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

   The target function sub_XXXXXXXX should contain code similar to:
   ```cpp
   if ( (_DWORD)PlayerInfo != -1 )
       v4 = (_DWORD)PlayerInfo - 1;
   v31 = (_BYTE *)v30(g_Source2EngineToServer, v4, "fov_desired");
   v23 = v22;
   if ( v22 && *v22 && (unsigned int)V_atoi(v22) )
   ```

   You should also see references to `oldname`, `newname` and `player_changename` within the function.

4. Rename the function sub_XXXXXXXX to CGameRules_ClientSettingsChanged:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CGameRules_ClientSettingsChanged"}]}
   ```

5. Find VTable and Calculate Offset:

   **ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.

6. Generate and validate unique signature:

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

- **DLL**: `server.dll` (Windows) / `libserver.so` (Linux)

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CGameRules_ClientSettingsChanged.windows.yaml`
- `libserver.so` → `CGameRules_ClientSettingsChanged.linux.yaml`
