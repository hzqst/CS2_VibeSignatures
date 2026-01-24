---
name: find-CBasePlayerController_SetPlayerName
description: Find and identify the CBasePlayerController_SetPlayerName function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the SetPlayerName function by searching for known string references and analyzing cross-references.
---

# Find CBasePlayerController_SetPlayerName

Locate `CBasePlayerController_SetPlayerName` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for strings `fov_desired` and `newname`:
   ```
   mcp__ida-pro-mcp__find_regex pattern="fov_desired"
   mcp__ida-pro-mcp__find_regex pattern="newname"
   ```

2. Get cross-references to both strings:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs=["<fov_desired_addr>", "<newname_addr>"]
   ```

3. Find the function that references **both** strings - this is the player info sync function.

4. Decompile that function and look for the call to `CBasePlayerController_SetPlayerName`:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

5. In the decompiled output, find the pattern:
   ```c
   CBasePlayerController_SetPlayerName(a2, v6);  // after name comparison and event firing
   ```

6. Rename if needed:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<target_addr>", "name": "CBasePlayerController_SetPlayerName"}]}
   ```

7. Get function details for YAML:
   ```
   mcp__ida-pro-mcp__lookup_funcs queries="<target_addr>"
   ```

8. Write YAML file beside the binary:
   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import idaapi
   import os

   input_file = idaapi.get_input_file_path()
   dir_path = os.path.dirname(input_file)

   # Determine platform from file extension
   if input_file.endswith('.dll'):
       platform = 'windows'
       image_base = 0x180000000
   else:
       platform = 'linux'
       image_base = 0x0

   func_va = <func_addr>
   func_size = <func_size>
   func_rva = func_va - image_base

   yaml_content = f'''func_va: {hex(func_va)}
   func_rva: {hex(func_rva)}
   func_size: {hex(func_size)}
   '''

   yaml_path = os.path.join(dir_path, f"CBasePlayerController_SetPlayerName.{platform}.yaml")
   with open(yaml_path, 'w', encoding='utf-8') as f:
       f.write(yaml_content)
   print(f"Written to: {yaml_path}")
   """
   ```

## Signature Pattern

The function is called after:
- Creating `CMsgPlayerInfo` message
- Firing `player_changename` event with `userid`, `oldname`, `newname` fields
- Comparing old and new player names

The surrounding function also handles `fov_desired` cvar (clamps FOV between 1-135).

## Function Characteristics

- **Type**: Regular member function (NOT virtual)
- **Parameters**: `(CBasePlayerController* this, const char* name)`
- **Behavior**:
  - Copies player name to `this + 0x510` using `V_strncpy` with max length 128
  - Calls network state change notification

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBasePlayerController_SetPlayerName.windows.yaml`
- `server.so` → `CBasePlayerController_SetPlayerName.linux.yaml`

```yaml
func_va: 0x180A8CA10   # Virtual address of the function - This can change when game updates.
func_rva: 0xA8CA10     # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0x3F        # Function size in bytes - This can change when game updates.
```

Note: This is NOT a virtual function, so there are no `vfunc_*` fields.
