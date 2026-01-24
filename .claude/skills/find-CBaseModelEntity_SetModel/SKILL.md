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

8. Write YAML file beside the binary:
   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import idaapi
   import idc
   import os

   func_addr = <function_addr>  # Replace with actual address
   func = idaapi.get_func(func_addr)
   func_size = func.size()

   input_file = idaapi.get_input_file_path()
   dir_path = os.path.dirname(input_file)

   # Determine platform and calculate RVA
   if input_file.endswith('.dll'):
       platform = 'windows'
       image_base = idaapi.get_imagebase()
       func_rva = func_addr - image_base
   else:
       platform = 'linux'
       func_rva = func_addr  # For .so files, typically no rebase needed

   func_sig = "<unique_signature>"  # Replace with validated signature

   yaml_content = f'''func_va: {hex(func_addr)}
func_rva: {hex(func_rva)}
func_size: {hex(func_size)}
func_sig: {func_sig}
'''

   yaml_path = os.path.join(dir_path, f"CBaseModelEntity_SetModel.{platform}.yaml")
   with open(yaml_path, 'w', encoding='utf-8') as f:
       f.write(yaml_content)
   print(f"Written to: {yaml_path}")
   """
   ```

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

```yaml
func_va: 0x142de40       # Virtual address of the function - This can change when game updates.
func_rva: 0x142de40      # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0x3d          # Function size in bytes - This can change when game updates.
func_sig: XX XX XX XX XX # Unique byte signature for pattern scanning - This can change when game updates.
```
