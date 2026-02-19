---
name: find-CBaseEntity_SetMoveType
description: Find and identify the CBaseEntity_SetMoveType function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the SetMoveType function by searching for the "env_shake %s with" debug string and analyzing cross-references to find the matching code pattern.
disable-model-invocation: true
---

# Find CBaseEntity_SetMoveType

Locate `CBaseEntity_SetMoveType` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

### 1. Search for the Debug String

```
mcp__ida-pro-mcp__find_regex pattern="env_shake.*with"
```

### 2. Get Cross-References to the String

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
```

### 3. Decompile Referencing Functions and Identify the Target

Decompile all referencing functions and look for this specific code pattern:

```c
sub_XXXXXXXX();                    // some helper call
sub_YYYYYYYY(a1, 0LL, 0LL);       // <-- This is CBaseEntity_SetMoveType
v2 = *(_DWORD *)(a1 + <offset>);  // read spawnflags
if ( (v2 & 1) != 0 )
    *(_DWORD *)(a1 + <offset2>) = 0;
if ( (v2 & 0x20) != 0 && (v2 & 8) == 0 && (v2 & 0x10) == 0 )
{
    v3 = (const char *)sub_ZZZZZZZZ(*(_QWORD *)(a1 + 16));
    DevWarning("env_shake %s with ...", v3);
}
```

**Identification criteria:**
- The function matching the pattern has the `env_shake` DevWarning with exactly three flag checks: `& 0x20`, `& 8`, `& 0x10` (without an additional `& 0x100` check)
- `CBaseEntity_SetMoveType` is called with 3 arguments: `(a1, 0, 0)` — the entity and two zero/NULL parameters
- It is called immediately after a parameterless helper call and immediately before the spawnflags read
- If multiple functions reference the string, pick the one whose flag checks match `(v2 & 0x20) != 0 && (v2 & 8) == 0 && (v2 & 0x10) == 0` without extra conditions

Extract the address of `sub_YYYYYYYY` as the `CBaseEntity_SetMoveType` address.

### 4. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CBaseEntity_SetMoveType"}]}
```

### 5. Generate Signature

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 6. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CBaseEntity_SetMoveType`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 5

## Function Characteristics

- **Type**: Non-virtual (regular) function
- **Parameters**: `(entity, move_type, unknown)` — typically called as `(entity, 0, 0)` to clear move type
- **Purpose**: Sets the move type for an entity, used in env_shake activation logic

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBaseEntity_SetMoveType.windows.yaml`
- `libserver.so` / `libserver.so` → `CBaseEntity_SetMoveType.linux.yaml`
