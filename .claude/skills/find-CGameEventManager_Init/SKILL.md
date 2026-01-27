---
name: find-CGameEventManager_Init
description: Find and identify the CGameEventManager_Init function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the game event manager initialization function by searching for the "resource/core.gameevents" string reference and analyzing cross-references.
---

# Find CGameEventManager_Init

Locate `CGameEventManager_Init` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the resource string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="core\.gameevents"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CGameEventManager_Init"}]}
   ```

5. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CGameEventManager_Init`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

   Note: This is NOT a virtual function, so no vtable parameters are needed.

## Signature Pattern

The function loads three game event resource files in sequence:
```c
(*(void (__fastcall **)(__int64, const char *, _QWORD))(*(_QWORD *)a1 + 16LL))(a1, "resource/core.gameevents", 0);
(*(void (__fastcall **)(__int64, const char *, _QWORD))(*(_QWORD *)a1 + 16LL))(a1, "resource/game.gameevents", 0);
(*(void (__fastcall **)(__int64, const char *, __int64))(*(_QWORD *)a1 + 16LL))(a1, "resource/mod.gameevents", 1);
```

## Function Characteristics

- **Purpose**: Initializes the game event manager by loading event definitions from three resource files
- **Parameters**: `(this)` where `this` is a pointer to the game event manager object
- **Return**: Returns 1 (success)
- **Behavior**:
  - Calls vtable offset +24 (0x18) for initialization
  - Loads core game events (parameter 0)
  - Loads game-specific events (parameter 0)
  - Loads mod events (parameter 1)

## Resource Files Loaded

1. `resource/core.gameevents` - Core game event definitions
2. `resource/game.gameevents` - Game-specific event definitions
3. `resource/mod.gameevents` - Mod/custom event definitions

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CGameEventManager_Init.windows.yaml`
- `server.so` → `CGameEventManager_Init.linux.yaml`

```yaml
func_va: 0x14ff3e0         # Virtual address of the function - This can change when game updates.
func_rva: 0x14ff3e0        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0x56            # Function size in bytes - This can change when game updates.
func_sig: 55 48 89 e5 53 48 89 fb 48 83 ec 08 48 8b 07 ff 50 18 48 8b 03 48 89 df 31 d2 48 8d 35 ?? ?? ?? ?? ff 50 10 48 8b 03 48 89 df 31 d2 48 8d 35 ?? ?? ?? ?? ff 50 10  # Unique byte signature for pattern scanning - This can change when game updates.
```

## Platform Notes

This function works identically on both Windows (server.dll) and Linux (server.so):
- Both platforms use the same string references
- The function structure is consistent across platforms
- Signature patterns may vary slightly due to compiler differences
