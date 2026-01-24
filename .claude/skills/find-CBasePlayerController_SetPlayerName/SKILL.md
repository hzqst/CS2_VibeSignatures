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

8. Generate and validate unique signature:

   - Generate a hex signature for {FunctionName}, each byte divided with space, "??" for wildcard, keep it robust and relocation-safe, for example: 55 8B EC 11 22 33 44 55 66 77 88

   - Make sure our {FunctionName} is the **ONLY** function that can be found with your signature. If your signature turn out to be connected with multiple functions, try longer signature then.

   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import ida_bytes

   func_addr = <func_addr>

   # Get function bytes
   raw_bytes = ida_bytes.get_bytes(func_addr, 40)
   print("Function bytes:", ' '.join(f'{b:02X}' for b in raw_bytes))

   # Key signature pattern: mov r8d, 80h + lea rbx, [rcx+510h]
   # 41 B8 80 00 00 00 48 8D 99 10 05 00 00
   sig = bytes([0x41, 0xB8, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x99, 0x10, 0x05, 0x00, 0x00])

   # Search entire .text segment to verify uniqueness
   start = 0x180001000  # Windows .text start (adjust for Linux)
   end = 0x181511000    # Windows .text end (adjust for Linux)
   step = 0x200000
   matches = []

   for chunk_start in range(start, end, step):
       chunk_end = min(chunk_start + step + 64, end)
       data = ida_bytes.get_bytes(chunk_start, chunk_end - chunk_start)
       if data:
           pos = 0
           while True:
               idx = data.find(sig, pos)
               if idx == -1:
                   break
               matches.append(hex(chunk_start + idx))
               pos = idx + 1

   print(f"Signature matches: {len(matches)}")
   for m in matches:
       print(m)

   if len(matches) == 1:
       print("SUCCESS: Signature is unique!")
   else:
       print("WARNING: Signature is not unique, need longer pattern")
   """
   ```

   Tips for finding unique signatures:
   - Look for unique string references or immediate values
   - Find distinctive instruction sequences
   - Use wildcards (`??`) for bytes that may change (relocations, offsets)
   - Ensure the signature matches ONLY this function
   - **DO NOT** use `find_bytes` to validate signature as `find_bytes` does't work for function.

9. Write YAML file beside the binary:
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
   func_sig = "41 B8 80 00 00 00 48 8D 99 10 05 00 00"

   yaml_content = f'''func_va: {hex(func_va)}
func_rva: {hex(func_rva)}
func_size: {hex(func_size)}
func_sig: {func_sig}
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

## Hex Signature

| Bytes | Instruction | Description |
|-------|-------------|-------------|
| `41 B8 80 00 00 00` | `mov r8d, 80h` | 128 byte max name length (unique) |
| `48 8D 99 10 05 00 00` | `lea rbx, [rcx+510h]` | Name storage offset 0x510 (unique) |

**Final signature**: `41 B8 80 00 00 00 48 8D 99 10 05 00 00`

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBasePlayerController_SetPlayerName.windows.yaml`
- `server.so` → `CBasePlayerController_SetPlayerName.linux.yaml`

```yaml
func_va: 0x180A8CA10   # Virtual address of the function - This can change when game updates.
func_rva: 0xA8CA10     # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0x3F        # Function size in bytes - This can change when game updates.
func_sig: 41 B8 80 00 00 00 48 8D 99 10 05 00 00  # Unique byte signature for pattern scanning.
```

Note: This is NOT a virtual function, so there are no `vfunc_*` fields.
