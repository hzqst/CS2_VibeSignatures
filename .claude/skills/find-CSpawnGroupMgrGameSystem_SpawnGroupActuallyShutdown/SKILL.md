---
name: find-CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown
description: Find and identify the CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the SpawnGroupActuallyShutdown function by searching for known format string references and analyzing cross-references.
disable-model-invocation: true
---

# Find CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown

Locate `CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

1. Search for the format string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="%s:  SpawnGroupActuallyShutdown - Precached?"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Identify `CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown` — the function that references the format string `"%s:  SpawnGroupActuallyShutdown - Precached? %i\n"` is the target function itself.

   This function can also be verified by decompiling `CSpawnGroupMgrGameSystem_SpawnGroupShutdown` — the last function call at the bottom of that function is `CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown`.

5. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown"}]}
   ```

6. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown`.

7. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results for `CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown`.

   Required parameters:
   - `func_name`: `CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown`
   - `func_addr`: The function address from step 5
   - `func_sig`: The validated signature from step 6

## Signature Pattern

The function directly references the format string:
```
%s:  SpawnGroupActuallyShutdown - Precached? %i\n
```
Source file: `game/server/spawngroupmgrgamesystem.cpp`

## Function Characteristics

- **Parameters**: `(this, spawn_group_handle)` where `this` is CSpawnGroupMgrGameSystem pointer, `spawn_group_handle` is an unsigned int identifying the spawn group
- **Purpose**: Performs the actual shutdown of a spawn group, fires PostSpawnGroupUnload game event, and cleans up entity references
- **Not a virtual function**: This is a regular member function, no vtable lookup needed

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown.windows.yaml`
- `libserver.so` → `CSpawnGroupMgrGameSystem_SpawnGroupActuallyShutdown.linux.yaml`
