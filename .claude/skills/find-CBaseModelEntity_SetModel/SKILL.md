---
name: find-CBaseModelEntity_SetModel
description: Find and identify the CBaseModelEntity_SetModel function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the SetModel function by searching for known model path string references like "weapons/models/defuser/defuser.vmdl" and analyzing cross-references.
---

# Find CBaseModelEntity_SetModel

Locate `CBaseModelEntity_SetModel` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for a known model path string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="weapons/models/defuser/defuser\.vmdl"
   ```

   * You should **ALWAYS** use single back-slash here instead of double back-slash(which means you should go with escaped dot).

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing functions to identify which one calls SetModel:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```
   Look for a function that takes `(this, model_path)` as parameters and is called early in entity initialization.

4. Identify the SetModel function from the decompiled code. It will be called like:
   ```c
   sub_XXXXXX(a1, "weapons/models/defuser/defuser.vmdl");
   ```
   The first argument is the entity pointer, second is the model path.

5. Get function info:
   ```
   mcp__ida-pro-mcp__lookup_funcs queries="<setmodel_func_addr>"
   ```

6. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": {"addr": "<function_addr>", "name": "CBaseModelEntity_SetModel"}}
   ```

7. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

8. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CBaseModelEntity_SetModel`
   - `func_addr`: The function address from step 5
   - `func_sig`: The validated signature from step 7

## Signature Pattern

The function is called with a model path string as the second parameter:
```c
CBaseModelEntity_SetModel(entity_ptr, "path/to/model.vmdl");
```

Common model paths that reference this function:
- `weapons/models/defuser/defuser.vmdl`
- Other `.vmdl` model paths in entity spawn/initialization code

## Function Characteristics

- **Parameters**: `(this, model_path)` where `this` is CBaseModelEntity pointer, `model_path` is the VMDL model path string
- **Purpose**: Sets the visual model for an entity
- **Called by**: Entity spawn functions, item drop functions, weapon equip functions

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBaseModelEntity_SetModel.windows.yaml`
- `server.so` → `CBaseModelEntity_SetModel.linux.yaml`
