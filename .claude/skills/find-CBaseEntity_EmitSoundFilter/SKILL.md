---
name: find-CBaseEntity_EmitSoundFilter
description: Find and identify the CBaseEntity_EmitSoundFilter function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the EmitSoundFilter function by searching for the "CT_Water.StepLeft" string reference and analyzing cross-references.
disable-model-invocation: true
---

# Find CBaseEntity_EmitSoundFilter

Locate `CBaseEntity_EmitSoundFilter` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

1. Search for the sound string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="CT_Water\.StepLeft"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Identify `CBaseEntity_EmitSoundFilter` from the decompiled code. Look for a function call pattern like:
   ```c
   v38[0] = "CT_Water.StepLeft";
   ...
   v30 = sub_XXXXXX(qword_YYYYYY, v29, &v32);
   ```
   The target function is called with a global variable, an entity pointer, and a sound parameter structure.

5. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": {"addr": "<function_addr>", "name": "CBaseEntity_EmitSoundFilter"}}
   ```

6. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

7. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CBaseEntity_EmitSoundFilter`
   - `func_addr`: The function address from step 4
   - `func_sig`: The validated signature from step 6

## Signature Pattern

The function is called in water footstep sound handling code with the string "CT_Water.StepLeft":
```c
v38[0] = "CT_Water.StepLeft";
v39 = v33;
v40 = v26;
v38[1] = v32;
v42 = v42 & 0xE7 | 0x10;
v30 = CBaseEntity_EmitSoundFilter(qword_XXXXXX, v29, &v32);
```

## Function Characteristics

- **Parameters**: `(filter_global, entity, sound_params)` where `filter_global` is a global sound filter pointer, `entity` is the entity emitting the sound, `sound_params` contains sound parameters
- **Purpose**: Emits a filtered sound from an entity
- **Called by**: Water footstep sound handler and other sound emission code

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBaseEntity_EmitSoundFilter.windows.yaml`
- `libserver.so` → `CBaseEntity_EmitSoundFilter.linux.yaml`