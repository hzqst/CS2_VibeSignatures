---
name: find-CCSPlayerController_ChangeTeam
description: Find and identify the CCSPlayerController_ChangeTeam function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the ChangeTeam function by searching for known debug string references and analyzing cross-references.
---

# Find CCSPlayerController_ChangeTeam

Locate `CCSPlayerController_ChangeTeam` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the debug string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="ChangeTeam\(\) CTMDBG"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSPlayerController_ChangeTeam"}]}
   ```

5. Find vtable information:
   ```
   mcp__ida-pro-mcp__list_globals queries={"filter": "*CCSPlayerController*"}
   ```
   Look for `??_7CCSPlayerController@@6B@` - this is the vtable.

6. Get xrefs to the function to find data references:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<function_addr>"
   ```
   Find the data reference that falls within the vtable range.

7. Calculate vtable offset and index:
   - `vfunc_offset = data_ref_addr - vtable_addr`
   - `vfunc_index = vfunc_offset / 8`

8. Generate and validate unique signature:

   - Generate a hex signature for {FunctionName}, each byte divided with space, "??" for wildcard, keep it robust and relocation-safe, for example: 55 8B EC 11 22 33 44 55 66 77 88

   - Make sure our {FunctionName} is the **ONLY** function that can be found with your signature. If your signature turn out to be connected with multiple functions, try longer signature then.

   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import ida_bytes
   import ida_segment

   func_addr = <func_addr>

   # Get function bytes
   raw_bytes = ida_bytes.get_bytes(func_addr, 64)
   print("Function bytes:", ' '.join(f'{b:02X}' for b in raw_bytes))

   # Identify unique byte patterns in the function
   # Look for distinctive instruction sequences that are unlikely to appear elsewhere

   # Get .text segment bounds
   seg = ida_segment.get_segm_by_name(".text")
   start = seg.start_ea
   end = seg.end_ea

   # Test candidate signature - adjust based on function's unique characteristics
   # For example, look for unique immediate values, register combinations, or call patterns
   candidate_sig = raw_bytes[:16]  # Start with first 16 bytes as candidate

   step = 0x200000
   matches = []

   for chunk_start in range(start, end, step):
       chunk_end = min(chunk_start + step + 64, end)
       data = ida_bytes.get_bytes(chunk_start, chunk_end - chunk_start)
       if data:
           pos = 0
           while True:
               idx = data.find(candidate_sig, pos)
               if idx == -1:
                   break
               matches.append(hex(chunk_start + idx))
               pos = idx + 1

   print(f"Signature matches: {len(matches)}")
   for m in matches:
       print(m)

   if len(matches) == 1:
       print("SUCCESS: Signature is unique!")
       print("Signature:", ' '.join(f'{b:02X}' for b in candidate_sig))
   else:
       print("WARNING: Signature is not unique, need longer/different pattern")
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
   func_sig = "<unique_signature>"  # Replace with validated signature

   yaml_content = f'''func_va: {hex(func_va)}
func_rva: {hex(func_rva)}
func_size: {hex(func_size)}
func_sig: {func_sig}
vfunc_name: CCSPlayerController
vfunc_mangled_name: ??_7CCSPlayerController@@6B@
vfunc_offset: <vfunc_offset>
vfunc_index: <vfunc_index>
'''

   yaml_path = os.path.join(dir_path, f"CCSPlayerController_ChangeTeam.{platform}.yaml")
   with open(yaml_path, 'w', encoding='utf-8') as f:
       f.write(yaml_content)
   print(f"Written to: {yaml_path}")
   """
   ```

## Signature Pattern

The function contains a debug log call with format string:
```
"%s<%i><%s><%s>" ChangeTeam() CTMDBG , team %d, req team %d willSwitch %d, %.2f
```

## Function Characteristics

- **Parameters**: `(this, team_id)` where `this` is CCSPlayerController pointer, `team_id` is the target team

## Team IDs

- `0`: Unassigned
- `1`: Spectator
- `2`: Terrorist
- `3`: Counter-Terrorist

## VTable Information

- **VTable Name**: `CCSPlayerController::\`vftable'`
- **VTable Mangled Name**: `??_7CCSPlayerController@@6B@`
- **VTable Index**: 102 (0x66) - This can change when game updates.
- **VTable Offset**: 0x330  - This can change when game updates.

* Note that for `server.so`, The first 16 bytes of "vftable" are for RTTI. the real vftable =  `_ZTV19CCSPlayerController (0x221e390)` + `0x10` = `0x221e3A0`.

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSPlayerController_ChangeTeam.windows.yaml`
- `server.so` → `CCSPlayerController_ChangeTeam.linux.yaml`

```yaml
func_va: 0x180999830      # Virtual address of the function - This can change when game updates.
func_rva: 0x999830        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0x301          # Function size in bytes  - This can change when game updates.
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - This can change when game updates.
vfunc_name: CCSPlayerController
vfunc_mangled_name: ??_7CCSPlayerController@@6B@
vfunc_offset: 0x330       # Offset from vtable start - This can change when game updates.
vfunc_index: 102          # vtable[102] - This can change when game updates.
```
