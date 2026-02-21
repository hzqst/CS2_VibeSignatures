---
name: find-CSpawnGroupMgrGameSystem_SpawnGroupShutdown
description: Find and identify the CSpawnGroupMgrGameSystem_SpawnGroupShutdown function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the SpawnGroupShutdown function by searching for known format string references and analyzing cross-references.
disable-model-invocation: true
---

# Find CSpawnGroupMgrGameSystem_SpawnGroupShutdown

Locate `CSpawnGroupMgrGameSystem_SpawnGroupShutdown` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

1. Search for the format string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="%s:  SpawnGroupShutdown: entities(%d)"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Identify `CSpawnGroupMgrGameSystem_SpawnGroupShutdown` — the function that references the format string `"%s:  SpawnGroupShutdown: entities(%d)\n"` is the target function itself.

5. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CSpawnGroupMgrGameSystem_SpawnGroupShutdown"}]}
   ```

6. Find VTable and Calculate Offset:

   **ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.

   VTable class name: `CSpawnGroupMgrGameSystem`

7. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CSpawnGroupMgrGameSystem_SpawnGroupShutdown`.

8. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CSpawnGroupMgrGameSystem_SpawnGroupShutdown`
   - `func_addr`: The function address from step 5
   - `func_sig`: The validated signature from step 7

   VTable parameters:
   - `vtable_name`: `CSpawnGroupMgrGameSystem`
   - `vfunc_offset`: The offset from step 6
   - `vfunc_index`: The index from step 6

## Signature Pattern

The function directly references the format string:
```
%s:  SpawnGroupShutdown: entities(%d)\n
```
Source file: `game/server/spawngroupmgrgamesystem.cpp`

## Function Characteristics

- **Parameters**: `(this, spawn_group_handle)` where `this` is CSpawnGroupMgrGameSystem pointer, `spawn_group_handle` is an unsigned int identifying the spawn group
- **Purpose**: Initiates shutdown of a spawn group, fires PreSpawnGroupUnload game event, then calls SpawnGroupActuallyShutdown at the end
- **Virtual function**: This is a virtual function on the CSpawnGroupMgrGameSystem vtable

## VTable Information

- **VTable Name**: `CSpawnGroupMgrGameSystem`
- **VTable Mangled Name**:
  - Windows: `??_7CSpawnGroupMgrGameSystem@@6B@`
  - Linux: `_ZTV26CSpawnGroupMgrGameSystem`

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CSpawnGroupMgrGameSystem_SpawnGroupShutdown.windows.yaml`
- `libserver.so` → `CSpawnGroupMgrGameSystem_SpawnGroupShutdown.linux.yaml`
