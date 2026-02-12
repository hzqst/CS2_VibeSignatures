---
name: find-CBaseEntity_SetGroundEntity
description: Find and identify the CBaseEntity_SetGroundEntity function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the SetGroundEntity function by analyzing CTriggerPush_Touch's decompiled code for a specific call pattern within the spawnflags 0x80 branch.
---

# Find CBaseEntity_SetGroundEntity

Locate `CBaseEntity_SetGroundEntity` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get CTriggerPush_Touch Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CTriggerPush_Touch`.

If the skill returns an error, stop and report to user.
Otherwise, extract `func_va` for the next step.

### 2. Decompile CTriggerPush_Touch

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 3. Locate CBaseEntity_SetGroundEntity in the Decompiled Code

Find the following code pattern inside the `(spawnflags & 0x80) != 0` branch:

```c
if ( (*(_DWORD *)(a1 + <offset>) & 0x80) != 0 )
{
    // ... vector math and dot product calculation ...
    if ( v_dotproduct > 0.0 )
        sub_XXXXXXXX(a2, 0LL, 0LL);  // <-- This is CBaseEntity_SetGroundEntity
    sub_YYYYYYYY(a1);
}
```

**Identification criteria:**
- Inside the `& 0x80` spawnflags branch (NOT the else branch)
- Called with exactly 3 arguments: `(a2, 0, 0)` — the touched entity and two NULL pointers
- Immediately followed by another call that takes only `a1` (the trigger entity)
- Guarded by a `> 0.0` dot product check

Extract the address of this call target as the `CBaseEntity_SetGroundEntity` address.

### 4. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CBaseEntity_SetGroundEntity"}]}
```

### 5. Generate Signature

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 6. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CBaseEntity_SetGroundEntity`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 5

## Function Characteristics

- **Type**: Non-virtual (regular) function
- **Parameters**: `(entity, ground_entity, unknown)` — typically called as `(touched_entity, NULL, NULL)` to clear ground entity
- **Purpose**: Sets or clears the ground entity for a given entity, used in trigger push logic to unground a pushed entity

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBaseEntity_SetGroundEntity.windows.yaml`
- `server.so` / `libserver.so` → `CBaseEntity_SetGroundEntity.linux.yaml`
