---
name: find-CBaseModelEntity_SetModel-AND-CBaseEntity_SetGravityScale
description: Find and identify the CBaseModelEntity_SetModel and CBaseEntity_SetGravityScale functions in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate these functions by searching for the "weapons/models/grenade/flashbang/weapon_flashbang.vmdl" string reference and analyzing the flashbang grenade initializer function.
---

# Find CBaseModelEntity_SetModel and CBaseEntity_SetGravityScale

Locate `CBaseModelEntity_SetModel` and `CBaseEntity_SetGravityScale` in CS2 `server.dll` or `server.so` using IDA Pro MCP tools.

## Method

1. Search for the string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="weapons/models/grenade/flashbang/weapon_flashbang\.vmdl"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Identify the flashbang grenade initializer function among the xrefs:
   - Look for the smaller function (~0xEB size) that takes `(a1, a2)` parameters
   - NOT the large grenade resource registration table function
   - Decompile the candidate:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Match the characteristic code pattern in the decompiled function:

   The flashbang initializer has this call sequence:
   ```c
   sub_XXXXXXX(a1, "weapons/models/grenade/flashbang/weapon_flashbang.vmdl");  // <-- CBaseModelEntity_SetModel
   sub_XXXXXXX(a1);
   *(_QWORD *)(a1 + <offset>) = sub_XXXXXXX;
   sub_XXXXXXX(a1, ...);
   sub_XXXXXXX(&v, *(unsigned int *)(*(_QWORD *)(a1 + 16) + 56LL));
   sub_XXXXXXX(a1, v, 0LL);
   sub_XXXXXXX(a1, 0.40000001);  // <-- CBaseEntity_SetGravityScale (constant 0.4)
   sub_XXXXXXX(a1);
   ```

   Key identifiers:
   - `CBaseModelEntity_SetModel`: First call, takes `(a1, model_path_string)` — sets the entity's model
   - `CBaseEntity_SetGravityScale`: Call with float constant `0.40000001` — sets gravity scale

5. Check if the functions are already renamed:
   ```
   mcp__ida-pro-mcp__lookup_funcs queries="<CBaseModelEntity_SetModel_addr>"
   mcp__ida-pro-mcp__lookup_funcs queries="<CBaseEntity_SetGravityScale_addr>"
   ```

6. Rename them if still unnamed (`sub_` prefix):
   ```
   mcp__ida-pro-mcp__rename batch={"func": [
     {"addr": "<setmodel_addr>", "name": "CBaseModelEntity_SetModel"},
     {"addr": "<setgravityscale_addr>", "name": "CBaseEntity_SetGravityScale"}
   ]}
   ```

7. Generate and validate unique signature for `CBaseModelEntity_SetModel`:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for those functions:

   `CBaseModelEntity_SetModel`

   `CBaseEntity_SetGravityScale`

8. Write IDA analysis output for those functions as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results of `CBaseModelEntity_SetModel`, `CBaseEntity_SetGravityScale`.

   For `CBaseModelEntity_SetModel`:
    Required parameters:
    - `func_name`: `CBaseModelEntity_SetModel`
    - `func_addr`: The function address from step 4
    - `func_sig`: The validated signature from step 7

   For `CBaseEntity_SetGravityScale`:
    Required parameters:
    - `func_name`: `CBaseEntity_SetGravityScale`
    - `func_addr`: The function address from step 4
    - `func_sig`: The validated signature from step 7

   Note: Those are NOT virtual function, so no vtable parameters are needed.

## Function Characteristics

- **Prototype**: `void CBaseModelEntity_SetModel(CBaseModelEntity *pEntity, const char *pModelName)`
- **Parameters**:
  - `pEntity`: The entity to set the model on
  - `pModelName`: Path to the .vmdl model file

- **Prototype**: `void CBaseEntity_SetGravityScale(CBaseEntity *pEntity, float flGravityScale)`
- **Parameters**:
  - `pEntity`: The entity to set gravity on
  - `flGravityScale`: Gravity multiplier (e.g., 0.4 for flashbang)

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- Both are regular functions, NOT virtual functions
- The flashbang initializer is the primary anchor — it always contains both calls in sequence
- The large grenade resource table function also references the flashbang string but is NOT the target
- `CBaseEntity_SetGravityScale` is reliably identified by the `0.40000001` float constant in the flashbang context

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `CBaseModelEntity_SetModel.windows.yaml`, `CBaseEntity_SetGravityScale.windows.yaml`
- `server.so` -> `CBaseModelEntity_SetModel.linux.yaml`, `CBaseEntity_SetGravityScale.linux.yaml`
