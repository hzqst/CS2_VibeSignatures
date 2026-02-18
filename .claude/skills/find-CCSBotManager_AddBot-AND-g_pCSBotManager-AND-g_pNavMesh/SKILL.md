---
name: find-CCSBotManager_AddBot-AND-g_pCSBotManager-AND-g_pNavMesh
description: Find and identify the CCSBotManager_AddBot function, g_pCSBotManager and g_pNavMesh global variables in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the bot manager's AddBot function by searching for the "Error - cannot add bots after game is over." string reference and analyzing cross-references.
disable-model-invocation: true
---

# Find CCSBotManager_AddBot, g_pCSBotManager, g_pNavMesh

Locate `CCSBotManager_AddBot`, `g_pCSBotManager`, and `g_pNavMesh` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Search for the debug string

```
mcp__ida-pro-mcp__find_regex pattern="Error - cannot add bots after game is over"
```

### 2. Get cross-references to the string

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
```

### 3. Decompile the referencing function

```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

Verify the function contains the pattern:
```c
if ( !qword_XXXXXXXX || !*(_BYTE *)(qword_XXXXXXXX + 264) ) // qword_XXXXXXXX is g_pNavMesh
    return 0;
if ( byte_XXXXXXXX )
{
    if ( !a3 )
      Msg("Error - cannot add bots after game is over.\n");
    return 0;
}
```

### 4. Identify the global variables

#### Identify g_pNavMesh:

Inside `CCSBotManager_AddBot`, at the beginning of the function, there is a check:
```c
if ( !qword_XXXXXXXX || !*(_BYTE *)(qword_XXXXXXXX + 264) )
    return 0;
```

The `qword_XXXXXXXX` in this check is `g_pNavMesh`.

#### Identify g_pCSBotManager:

Get cross-references to `CCSBotManager_AddBot`:
```
mcp__ida-pro-mcp__xrefs_to addrs="<CCSBotManager_AddBot_addr>"
```

Decompile one of the callers. Look for:
```c
CCSBotManager_AddBot(g_pCSBotManager, v8, 0, v6, v5, v10);
```

The first argument is `g_pCSBotManager`.

### 5. Rename the function and global variables

#### Rename the function:
```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSBotManager_AddBot"}]}
```

#### Rename g_pNavMesh (if not already named):
```
mcp__ida-pro-mcp__rename batch={"data": {"old": "qword_XXXXXXXX", "new": "g_pNavMesh"}}
```

#### Rename g_pCSBotManager (if not already named):
```
mcp__ida-pro-mcp__rename batch={"data": {"old": "qword_XXXXXXXX", "new": "g_pCSBotManager"}}
```

### 6. Generate and validate unique signature for CCSBotManager_AddBot

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CCSBotManager_AddBot`.

### 7. Write IDA analysis output as YAML for CCSBotManager_AddBot

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results for `CCSBotManager_AddBot`.

Required parameters:
- `func_name`: `CCSBotManager_AddBot`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 6

### 8. Generate and validate unique signature for g_pCSBotManager and g_pNavMesh

**ALWAYS** Use SKILL `/generate-signature-for-globalvar` to generate a robust and unique signature for `g_pCSBotManager` and `g_pNavMesh`.

### 9. Write IDA analysis output for g_pCSBotManager and g_pNavMesh as YAML

**ALWAYS** Use SKILL `/write-globalvar-as-yaml` to write the analysis results for `g_pCSBotManager` and `g_pNavMesh`.

#### For `g_pCSBotManager`:

Required parameters:
- `gv_name`: `g_pCSBotManager`
- `gv_addr`: The global variable address from step 4
- `gv_sig`: The validated signature from step 8
- `gv_sig_va`: The virtual address that signature matches
- `gv_inst_offset`: Offset from signature start to GV-accessing instruction
- `gv_inst_length`: Length of the GV-accessing instruction
- `gv_inst_disp`: Displacement offset within the instruction

#### For `g_pNavMesh`:

Required parameters:
- `gv_name`: `g_pNavMesh`
- `gv_addr`: The global variable address from step 4
- `gv_sig`: The validated signature from step 8
- `gv_sig_va`: The virtual address that signature matches
- `gv_inst_offset`: Offset from signature start to GV-accessing instruction
- `gv_inst_length`: Length of the GV-accessing instruction
- `gv_inst_disp`: Displacement offset within the instruction

## Signature Pattern

The function contains a debug log call with format string:
```
Error - cannot add bots after game is over.
```

## Function / Global Variable Characteristics

### CCSBotManager_AddBot

- **Class**: `CCSBotManager`
- **Method**: `AddBot`
- **Parameters**: `(this, team_id, is_silent, name, difficulty, bot_type)` where `this` is CCSBotManager pointer
- **Return type**: `char` (returns 0 or 1)
- **Purpose**: Adds a bot to the game with specified team, difficulty, and profile
- **Behavior**:
  1. Checks if nav mesh is loaded (`g_pNavMesh` and `g_pNavMesh + 264` byte flag)
  2. Checks if game is over (`byte_XXXXXXXX` flag)
  3. Determines team assignment (T=2, CT=3, or auto-balance)
  4. Selects bot profile based on name/difficulty
  5. Checks team capacity and balance
  6. Calls `CreateBot()` to spawn the bot entity
- **Unique Identifier**: String "Error - cannot add bots after game is over.\n"

### g_pCSBotManager

- **Type**: Global pointer (`CCSBotManager*`)
- **Purpose**: Singleton pointer to the CS bot manager instance
- **Access Pattern**: Typically accessed via `mov rcx, cs:g_pCSBotManager` before calling bot manager methods
- **Usage**: Passed as first argument (`this`) to `CCSBotManager_AddBot` and other bot manager methods

### g_pNavMesh

- **Type**: Global pointer (`CNavMesh*`)
- **Purpose**: Pointer to the navigation mesh used for bot pathfinding
- **Access Pattern**: Checked at the beginning of `CCSBotManager_AddBot` to verify nav mesh is loaded
- **Validation**: Both the pointer itself and a byte at offset +264 must be non-zero

## Key Calls in Function

- `Msg()` - Output error/info messages
- `CreateBot()` - Create and spawn a bot entity
- `V_stricmp_fast()` - Case-insensitive string comparison for team/difficulty parsing

## Output YAML Format

The output YAML filename for CCSBotManager_AddBot depends on the platform:
- `server.dll` -> `CCSBotManager_AddBot.windows.yaml`
- `server.so` / `libserver.so` -> `CCSBotManager_AddBot.linux.yaml`

The output YAML filename for g_pCSBotManager depends on the platform:
- `server.dll` -> `g_pCSBotManager.windows.yaml`
- `server.so` / `libserver.so` -> `g_pCSBotManager.linux.yaml`

The output YAML filename for g_pNavMesh depends on the platform:
- `server.dll` -> `g_pNavMesh.windows.yaml`
- `server.so` / `libserver.so` -> `g_pNavMesh.linux.yaml`

## Related Globals

- `g_pCSBotManager` - Singleton pointer to the bot manager instance
- `g_pNavMesh` - Navigation mesh pointer, checked before adding bots
- `g_pGameRules` - Game rules pointer, used for team auto-balance decisions
