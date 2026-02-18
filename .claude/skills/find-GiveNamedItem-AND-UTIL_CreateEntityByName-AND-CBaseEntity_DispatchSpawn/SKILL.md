---
name: find-GiveNamedItem-AND-UTIL_CreateEntityByName-AND-CBaseEntity_DispatchSpawn
description: Find and identify the GiveNamedItem, UTIL_CreateEntityByName and CBaseEntity_DispatchSpawn functions in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate these related entity creation functions by searching for the "GiveNamedItem: interpreting" debug string and analyzing cross-references.
disable-model-invocation: true
---

# Find GiveNamedItem, UTIL_CreateEntityByName and CBaseEntity_DispatchSpawn

Locate `GiveNamedItem`, `UTIL_CreateEntityByName` and `CBaseEntity_DispatchSpawn` in CS2 `server.dll` or `server.so` using IDA Pro MCP tools.

## Method

### Part 1: Find GiveNamedItem

1. Search for the debug string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="GiveNamedItem: interpreting"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile and rename the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

   * The decompiled function is `GiveNamedItem`, and it needs to be renamed.

   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "GiveNamedItem"}]}
   ```

   - Key Behaviors of GiveNamedItem:

      1. Translates legacy weapon names to modern equivalents
      2. Handles special C4 weapon logic (triggers "player_given_c4" event)
      3. Calls `UTIL_CreateEntityByName` to create the entity
      4. Calls `CBaseEntity_DispatchSpawn` to initialize the created entity
      5. Returns the created entity pointer

4. In the decompiled code, look for the entity creation pattern:
   ```c
   EntityByName = UTIL_CreateEntityByName((int)a2, -1);
   v29 = (_QWORD *)EntityByName;
   if ( EntityByName )
   {
     CBaseEntity_DispatchSpawn(EntityByName, 0LL);
     goto LABEL_47;
   }
   ```

   Or similar pattern where:
   - `UTIL_CreateEntityByName` is called with the weapon name and -1
   - If successful, `CBaseEntity_DispatchSpawn` is called on the created entity

### Part 2: Identify UTIL_CreateEntityByName and CBaseEntity_DispatchSpawn

5. From the GiveNamedItem decompiled code, identify:
   - `UTIL_CreateEntityByName`: The function called to create the entity (takes classname and spawn group handle)
   - `CBaseEntity_DispatchSpawn`: The function called to spawn/initialize the entity (takes entity pointer and optional parameter)

6. Rename `UTIL_CreateEntityByName`:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<util_createentitybyname_addr>", "name": "UTIL_CreateEntityByName"}]}
   ```

7. Rename `CBaseEntity_DispatchSpawn`:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<cbaseentity_dispatchspawn_addr>", "name": "CBaseEntity_DispatchSpawn"}]}
   ```

### Part 3: Generate Signatures and Write YAML

8. Generate and validate unique signature for `GiveNamedItem`:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

9. Write IDA analysis output for `GiveNamedItem` as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `GiveNamedItem`
   - `func_addr`: The function address of `GiveNamedItem` from step 3
   - `func_sig`: The validated signature from step 8

   Note: This is NOT a virtual function, so no vtable parameters are needed.

10. Generate and validate unique signature for `UTIL_CreateEntityByName`:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

11. Write IDA analysis output for `UTIL_CreateEntityByName` as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `UTIL_CreateEntityByName`
   - `func_addr`: The function address of `UTIL_CreateEntityByName` from step 5
   - `func_sig`: The validated signature from step 10

   Note: This is NOT a virtual function, so no vtable parameters are needed.

12. Generate and validate unique signature for `CBaseEntity_DispatchSpawn`:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

13. Write IDA analysis output for `CBaseEntity_DispatchSpawn` as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CBaseEntity_DispatchSpawn`
   - `func_addr`: The function address of `CBaseEntity_DispatchSpawn` from step 5
   - `func_sig`: The validated signature from step 12

   Note: This is NOT a virtual function, so no vtable parameters are needed.

## Function Characteristics

### GiveNamedItem

- **Prototype**: `CBaseEntity* GiveNamedItem(CCSPlayer_ItemServices* pItemServices, const char* pszItem, int iSubType, CEconItemView* pScriptItem, bool bRemoveIfNotCarried, void* pReserved)`
- **Parameters**:
  - `pItemServices`: Player's item services component
  - `pszItem`: Item/weapon class name string
  - `iSubType`: Item subtype
  - `pScriptItem`: Economy item view (can be null)
  - `bRemoveIfNotCarried`: Whether to remove if player can't carry
  - `pReserved`: Reserved parameter
- **Return**: Pointer to the created entity, or null on failure
- **Purpose**: Gives a named item (weapon, equipment) to a player entity
- **Legacy weapon handling**: Translates legacy weapon names (e.g., "weapon_galil", "weapon_mp5navy") to modern equivalents

### UTIL_CreateEntityByName

- **Prototype**: `CBaseEntity* UTIL_CreateEntityByName(const char* classname, int spawnGroupHandle)`
- **Parameters**:
  - `classname`: Entity class name string
  - `spawnGroupHandle`: Spawn group handle (-1 for default)
- **Return**: Pointer to the created entity, or null on failure
- **Purpose**: Creates an entity by its class name string
- **Note**: This is a simple wrapper that calls the internal implementation with default parameters

### CBaseEntity_DispatchSpawn

- **Prototype**: `void CBaseEntity_DispatchSpawn(CBaseEntity* pEntity, CEntityKeyValues* pKeyValues)`
- **Parameters**:
  - `pEntity`: The entity to spawn/initialize
  - `pKeyValues`: Entity key values (can be null)
- **Purpose**: Dispatches the spawn event to initialize a newly created entity
- **Note**: Must be called after `UTIL_CreateEntityByName` to complete entity creation

## Relationship Between Functions

```
GiveNamedItem
    │
    ├── Translates weapon name if legacy
    │
    ├── UTIL_CreateEntityByName(weaponName, -1)
    │       │
    │       └── Creates entity instance
    │
    └── CBaseEntity_DispatchSpawn(entity, null)
            │
            └── Initializes/spawns the entity
```

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- All three are regular functions, NOT virtual functions
- `GiveNamedItem` is the entry point that orchestrates entity creation
- `UTIL_CreateEntityByName` creates the raw entity instance
- `CBaseEntity_DispatchSpawn` completes initialization by calling spawn handlers
- The error string `"nullptr Ent in GiveNamedItem: %s!\n"` is logged when entity creation fails

## Output YAML Format

The output YAML filenames depend on the platform:
- `server.dll` → `GiveNamedItem.windows.yaml`, `UTIL_CreateEntityByName.windows.yaml`, `CBaseEntity_DispatchSpawn.windows.yaml`
- `server.so` → `GiveNamedItem.linux.yaml`, `UTIL_CreateEntityByName.linux.yaml`, `CBaseEntity_DispatchSpawn.linux.yaml`
