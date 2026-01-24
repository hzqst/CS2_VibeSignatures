---
name: find-GetCSWeaponDataFromKey
description: Find and identify the GetCSWeaponDataFromKey function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the GetCSWeaponDataFromKey function by searching for known projectile string references and analyzing the characteristic code pattern.
---

# Find GetCSWeaponDataFromKey

Locate `GetCSWeaponDataFromKey` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for projectile string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="smokegrenade_projectile"
   ```

2. Get cross-references to the base string (not the .cpp path):
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile each referencing function and look for the characteristic pattern:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Identify `GetCSWeaponDataFromKey` by finding this code pattern:
   ```c
   v9 = sub_XXXXXXXX("smokegrenade_projectile", a1, a2, a5);
   v10 = sub_YYYYYYYY();
   v11 = a6;
   v12 = sub_ZZZZZZZZ(v10, (unsigned __int16)a6, 0LL, 0LL);
   if ( v12 )
   {
     v14 = sub_AAAAAAAA(v12);
     if ( v14 )
     {
       v15 = sub_BBBBBBBB(v33, "%d", *(unsigned __int16 *)(v14 + 16));
       v16 = *(_DWORD *)(v15 + 4);
       if ( (v16 & 0x40000000) != 0 )
       {
         v17 = (void *)(v15 + 8);
       }
       else if ( (v16 & 0x3FFFFFFF) != 0 )
       {
         v17 = *(void **)(v15 + 8);
       }
       else
       {
         v17 = &unk_XXXXXXXX;
       }
       v13 = sub_CCCCCCCC(1LL, v17);  // <-- This is GetCSWeaponDataFromKey
       CBufferString::Purge((CBufferString *)v33, 0);
     }
     ...
   }
   ```
   The function called with `(1LL, v17)` after the `CBufferString` formatting is `GetCSWeaponDataFromKey`.

5. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": {"addr": "<function_addr>", "name": "GetCSWeaponDataFromKey"}}
   ```

6. Get function details:
   ```
   mcp__ida-pro-mcp__lookup_funcs queries="GetCSWeaponDataFromKey"
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

8. Write YAML file beside the binary:
   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import idaapi
   import os

   input_file = idaapi.get_input_file_path()
   dir_path = os.path.dirname(input_file)
   image_base = idaapi.get_imagebase()

   # Determine platform from file extension
   if input_file.endswith('.dll'):
       platform = 'windows'
   else:
       platform = 'linux'

   func_va = <func_addr>
   func_size = <func_size>
   func_rva = func_va - image_base
   func_sig = "<unique_signature>"  # Replace with validated signature

   yaml_content = f'''func_va: {hex(func_va)}
func_rva: {hex(func_rva)}
func_size: {hex(func_size)}
func_sig: {func_sig}
'''

   yaml_path = os.path.join(dir_path, f"GetCSWeaponDataFromKey.{platform}.yaml")
   with open(yaml_path, 'w', encoding='utf-8') as f:
       f.write(yaml_content)
   print(f"Written to: {yaml_path}")
   """
   ```

## Function Characteristics

- **Signature**: `__int64 __fastcall GetCSWeaponDataFromKey(__int64 a1, void* key)`
- **First parameter**: Usually `1LL` (constant)
- **Second parameter**: A string key (weapon name like "smokegrenade_projectile")
- **Return value**: Pointer to weapon data structure or 0 if not found

## Identifying Strings

The function is referenced in projectile creation functions. Search for any of these strings:
- `smokegrenade_projectile`
- `flashbang_projectile`
- `hegrenade_projectile`
- `molotov_projectile`
- `decoy_projectile`

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `GetCSWeaponDataFromKey.windows.yaml`
- `server.so` → `GetCSWeaponDataFromKey.linux.yaml`

```yaml
func_va: 0x1804F8590   # Virtual address of the function - This can change when game updates.
func_rva: 0x4F8590     # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xB7        # Function size in bytes - This can change when game updates.
func_sig: XX XX XX XX  # Unique byte signature for pattern scanning - This can change when game updates.
```
