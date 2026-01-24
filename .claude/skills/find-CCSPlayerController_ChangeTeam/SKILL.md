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

5. Find VTable and Calculate Offset:

   Search for the CCSPlayerController vtable and find the function's position within it:
   ```
   mcp__ida-pro-mcp__list_globals queries={"filter": "*CCSPlayerController*"}
   ```
   Look for:
   - Windows: `??_7CCSPlayerController@@6B@` - the vtable
   - Linux: `_ZTV19CCSPlayerController` - the vtable

   Then use this script to find the function pointer in vtable and calculate offset/index:
   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import ida_bytes

   func_addr = <func_addr>           # Target function address
   vtable_addr = <vtable_addr>       # VTable start address (from list_globals)

   # VTable is an array of function pointers (8 bytes each on 64-bit)
   # Iterate through vtable entries to find our function
   max_entries = 500
   found_offset = -1
   found_index = -1

   for i in range(max_entries):
       entry_addr = vtable_addr + i * 8           # Address of vtable[i]
       ptr = ida_bytes.get_qword(entry_addr)      # Read 8-byte pointer

       if ptr == func_addr:                       # Found our function!
           found_offset = i * 8                   # Offset = index * 8
           found_index = i
           print(f"Found at vtable offset: {hex(found_offset)}, index: {found_index}")
           break

   if found_index == -1:
       print("Function not found in vtable!")
   """
   ```

   **Memory layout explanation:**
   ```
   VTable @ vtable_addr:
   ┌─────────────────┬──────────────────────┐
   │ Offset   Index  │ Value (func pointer) │
   ├─────────────────┼──────────────────────┤
   │ 0x000    [0]    │ 0x180XXXXXX          │
   │ 0x008    [1]    │ 0x180XXXXXX          │
   │ ...      ...    │ ...                  │
   │ 0xNNN    [N]    │ func_addr  ← Found!  │
   └─────────────────┴──────────────────────┘
   ```

   **Formulas:**
   - `vfunc_offset = index × 8`
   - `vfunc_index = offset / 8`

   Note: For Linux `server.so`, the first 16 bytes of vtable are for RTTI metadata. The real vtable starts at `_ZTV19CCSPlayerController + 0x10`.

6. Generate and validate unique signature:

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

7. Write YAML file beside the binary:
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
