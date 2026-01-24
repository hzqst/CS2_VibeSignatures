---
name: find-CCSPlayerPawnBase_PostThink
description: |
  IDA Pro string analysis and function reverse engineering workflow. Connect to IDA Pro via ida-pro-mcp for binary analysis to locate the CCSPlayerPawnBase_PostThink function.
  Use cases:
  (1) Search for specific strings in binary files
  (2) Find cross-references (xrefs) to strings
  (3) Decompile functions that reference strings and view pseudocode
  (4) Locate specific code segments in pseudocode
  (5) Rename functions and variables to improve readability
  (6) Analyze function call relationships and data flow
  Trigger: CCSPlayerPawnBase_PostThink
---

# CCSPlayerPawnBase_PostThink Function Location Workflow

## Overview

This workflow is used to locate the `CCSPlayerPawnBase_PostThink` function in CS2 server binary files. This function is the PostThink handler for player Pawns, responsible for handling enter/exit events for buy zones, bomb zones, and rescue zones.

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the `enter_buyzone` string:

```
mcp__ida-pro-mcp__find_regex(pattern="enter_buyzone")
```

Expected result: Find string address (e.g., `0x86ebfd` for Linux, varies by version)

### 2. Find Cross-References

Use `xrefs_to` to find locations that reference this string:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

Expected result: Find the function that references the string (e.g., `sub_A58DE0`)

### 3. Rename Function

Use `rename` to give the function a meaningful name:

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<function_addr>", "name": "CCSPlayerPawnBase_PostThink"}})
```

### 4. Decompile to View Pseudocode

Use `decompile` to view the function pseudocode and get function size:

```
mcp__ida-pro-mcp__decompile(addr="<function_addr>")
```

### 5. Find VTable and Calculate Offset

Search for the CCSPlayerPawn vtable and find the function's position within it:

```
mcp__ida-pro-mcp__list_globals(queries={"filter": "*CCSPlayerPawn*"})
```

Look for:
- Windows: `??_7CCSPlayerPawn@@6B@` - the vtable
- Linux: `_ZTV13CCSPlayerPawn` - the vtable

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

Note: For Linux `server.so`, the first 16 bytes of vtable are for RTTI metadata. The real vtable starts at `_ZTV13CCSPlayerPawn + 0x10`.

### 6. Generate and Validate Unique Signature

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

### 7. Get Image Base and Write YAML

Get binary information:

```python
mcp__ida-pro-mcp__py_eval(code="""
import ida_nalt
import ida_ida
file_path = ida_nalt.get_input_file_path()
image_base = ida_ida.inf_get_min_ea()
print(f"File: {file_path}")
print(f"Base: {hex(image_base)}")
""")
```

Calculate `func_rva = func_va - image_base`

Write the YAML file beside the binary:

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
vfunc_name: CCSPlayerPawn
vfunc_mangled_name: _ZTV13CCSPlayerPawn
vfunc_offset: <vfunc_offset>
vfunc_index: <vfunc_index>
'''

yaml_path = os.path.join(dir_path, f"CCSPlayerPawnBase_PostThink.{platform}.yaml")
with open(yaml_path, 'w', encoding='utf-8') as f:
    f.write(yaml_content)
print(f"Written to: {yaml_path}")
"""
```

## Function Characteristics

The `CCSPlayerPawnBase_PostThink` function contains the following signature strings:

- `enter_buyzone` / `exit_buyzone` - Buy zone events
- `enter_bombzone` / `exit_bombzone` - Bomb zone events
- `enter_rescue_zone` / `exit_rescue_zone` - Rescue zone events
- `weapon_c4` - C4 bomb detection
- `SpottedLooseBomb` - AFK player dropped bomb notification
- `isplanted` - Bomb planted state check

## VTable Information

- **VTable Name**: `CCSPlayerPawn`
- **VTable Mangled Name**:
  - Windows: `??_7CCSPlayerPawn@@6B@`
  - Linux: `_ZTV13CCSPlayerPawn`
- **VTable Offset**: `0xB98` (may change with game updates)
- **VTable Index**: `371` (may change with game updates)

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSPlayerPawnBase_PostThink.windows.yaml`
- `server.so` / `libserver.so` → `CCSPlayerPawnBase_PostThink.linux.yaml`

```yaml
func_va: 0xA58DE0        # Virtual address of the function - changes with game updates
func_rva: 0xA58DE0       # Relative virtual address (VA - image base) - changes with game updates
func_size: 0x86A         # Function size in bytes - changes with game updates
func_sig: XX XX XX XX XX # Unique byte signature for pattern scanning - changes with game updates
vfunc_name: CCSPlayerPawn
vfunc_mangled_name: _ZTV13CCSPlayerPawn  # Use ??_7CCSPlayerPawn@@6B@ for Windows
vfunc_offset: 0xB98      # Offset from vtable start - changes with game updates
vfunc_index: 371         # vtable index - changes with game updates
```

## Related Functions

- `sub_1387560` - Check if in buy zone
- `sub_1390A80` - Check if can purchase
- `sub_15A47B0` - Find specified weapon (e.g., "weapon_c4")
- `qword_257FF40` - Game event manager
