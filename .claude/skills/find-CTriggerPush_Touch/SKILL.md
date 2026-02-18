---
name: find-CTriggerPush_Touch
description: Find and identify the CTriggerPush_Touch (CTriggerPush::Touch) virtual function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CTriggerPush touch handler function by using vtable information and the inherited vtable index from CBaseEntity::Touch.
disable-model-invocation: true
---

# Find CTriggerPush_Touch

Locate `CTriggerPush_Touch` (`CTriggerPush::Touch`) virtual function in CS2 `server.dll` or `server.so` using IDA Pro MCP tools.

## Method

### 1. Load CTriggerPush VTable Information

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CTriggerPush`.

If the skill returns an error, stop and report to user.
Otherwise, extract `vtable_va`, `vtable_numvfunc` and `vtable_entries` for subsequent steps.

### 2. Load CBaseEntity_Touch VTable Index

Read the vtable index from the existing YAML file:

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi
import os

input_file = idaapi.get_input_file_path()
dir_path = os.path.dirname(input_file)
platform = 'windows' if input_file.endswith('.dll') else 'linux'

yaml_path = os.path.join(dir_path, f"CBaseEntity_Touch.{platform}.yaml")
print(f"=== CBaseEntity_Touch ===")
if os.path.exists(yaml_path):
    with open(yaml_path, 'r', encoding='utf-8') as f:
        print(f.read())
else:
    print(f"ERROR: {yaml_path} not found")
"""
```

Extract `vfunc_index` value (the `Touch_index`) from CBaseEntity_Touch YAML.

### 3. Get CTriggerPush_Touch Virtual Function Address

Using the vtable entries from step 1 and the index from step 2:
- `CTriggerPush_Touch` address = `vtable_entries[Touch_index]`

### 4. Rename Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<CTriggerPush_Touch_addr>", "name": "CTriggerPush_Touch"}]}
```

### 5. Generate Signature

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for CTriggerPush_Touch.

### 6. Write CTriggerPush_Touch as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CTriggerPush_Touch`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 5

VTable parameters:
- `vtable_name`: `CTriggerPush`
- `vfunc_offset`: `Touch_index * 8` (e.g., `0x4A0` for index 148)
- `vfunc_index`: `Touch_index` (e.g., `148`)

## Function Characteristics

### CTriggerPush_Touch

- **Class**: `CTriggerPush`
- **Inherited From**: `CBaseEntity::Touch` (overridden)
- **Prototype**: `void CTriggerPush::Touch(CBaseEntity* pOther)`
- **Parameters**:
  - `this`: Pointer to the CTriggerPush instance
  - `pOther`: Pointer to the entity touching the trigger
- **Behavior**:
  1. Validates the touching entity via vtable call (checks entity type)
  2. Retrieves push direction and speed parameters
  3. Applies push force to the touching entity
  4. Handles physics-based push calculations

## VTable Information

- **VTable Name**: `CTriggerPush`
- **Parent Class**: `CBaseEntity` (Touch is an inherited virtual function)
- **Touch VTable Index**: Same as `CBaseEntity::Touch` (typically 148, may change with updates)

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `CTriggerPush_Touch.windows.yaml`
- `server.so` -> `CTriggerPush_Touch.linux.yaml`

## Notes

- This is a virtual function inherited from `CBaseEntity::Touch` and overridden in `CTriggerPush`
- The vtable index is the same as in `CBaseEntity` since it is an inherited virtual function
- The actual function implementation is different from `CBaseEntity::Touch` (push-specific behavior)
- Always verify the prerequisite YAML files exist before running this skill
