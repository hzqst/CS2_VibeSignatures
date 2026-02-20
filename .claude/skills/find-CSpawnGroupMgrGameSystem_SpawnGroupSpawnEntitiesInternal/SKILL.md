---
name: find-CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal
description: Find and identify the CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the SpawnGroupSpawnEntitiesInternal function by searching for known format string references and analyzing cross-references.
disable-model-invocation: true
---

# Find CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal

Locate `CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

1. Search for the format string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="%s:  SpawnGroupSpawnEntities finished spawning %d entities"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Identify `CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal` — the function that references the format string `"%s:  SpawnGroupSpawnEntities finished spawning %d entities [%.3f msec]\n"` is the target function itself.

5. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal"}]}
   ```

6. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal`.

7. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results for `CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal`.

   Required parameters:
   - `func_name`: `CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal`
   - `func_addr`: The function address from step 5
   - `func_sig`: The validated signature from step 6

## Signature Pattern

The function directly references the format string:
```
%s:  SpawnGroupSpawnEntities finished spawning %d entities [%.3f msec]\n
```
Source file: `game/server/spawngroupmgrgamesystem.cpp`

## Function Characteristics

- **Parameters**: `(this, spawn_group_handle)` where `this` is CSpawnGroupMgrGameSystem pointer, `spawn_group_handle` is an int identifying the spawn group
- **Purpose**: Internal implementation of spawning entities within a spawn group, handling save/restore data, entity lump loading, and adjacent map transitions
- **Not a virtual function**: This is a regular member function, no vtable lookup needed

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal.windows.yaml`
- `libserver.so` → `CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal.linux.yaml`
