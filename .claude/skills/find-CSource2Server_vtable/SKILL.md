---
name: find-CSource2Server_vtable
description: Find and identify the CSource2Server vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CSource2Server virtual function table by searching for the "Source2Server001" interface string and tracing through the interface registration pattern.
---

# Find CSource2Server_vtable

Locate `CSource2Server_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Search for Interface String

Search for the Source2Server interface identifier:

```
mcp__ida-pro-mcp__find_regex pattern="Source2Server001"
```

### 2. Get Cross-References to String

Find functions that reference this string:

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
```

Look for a small function (~0x1a bytes) that:
- Loads the interface string into r8
- Loads an implementation function into rdx
- Loads a global pointer into rcx
- Jumps to a registration function

### 3. Identify Interface Implementation Function

Decompile the small registration wrapper to find the interface implementation function:

```
mcp__ida-pro-mcp__decompile addr="<wrapper_func_addr>"
```

The implementation function (e.g., `sub_180CBCA50`) simply returns a pointer to the static instance.

### 4. Rename Interface Implementation

```
mcp__ida-pro-mcp__rename batch={"func": {"addr": "<impl_func_addr>", "name": "source2server"}}
```

### 5. Decompile to Find Static Instance

```
mcp__ida-pro-mcp__decompile addr="<impl_func_addr>"
```

The function returns `&s_Source2Server` - rename this global:

```
mcp__ida-pro-mcp__rename batch={"data": {"old": "<off_name>", "new": "s_Source2Server"}}
```

### 6. Find CSource2Server::Init via Debug String

Search for the debug string that identifies CSource2Server::Init:

```
mcp__ida-pro-mcp__find_regex pattern="gameeventmanager->Init"
```

Get xrefs to find the Init function:

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
```

### 7. Find VTable via Init Function Xrefs

Get cross-references to CSource2Server::Init:

```
mcp__ida-pro-mcp__xrefs_to addrs="<init_func_addr>"
```

The data references point to vtable entries. Analyze the addresses to find the vtable start.

### 8. Analyze VTable Structure

Read bytes around the vtable reference to identify the vtable start:

```
mcp__ida-pro-mcp__get_bytes regions={"addr": "<vtable_area>", "size": 64}
```

Parse the 64-bit pointers (little-endian) to identify function addresses and determine the vtable base.

### 9. Rename VTable

```
mcp__ida-pro-mcp__rename batch={"data": {"old": "<off_name>", "new": "CSource2Server_vtable"}}
```

### 10. Write VTable Info as YAML

Use IDA Python to write the vtable information:

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi
import os

vtable_class = "CSource2Server"
vtable_va = <vtable_addr>

input_file = idaapi.get_input_file_path()
dir_path = os.path.dirname(input_file)

if input_file.endswith('.dll'):
    platform = 'windows'
    image_base = idaapi.get_imagebase()
else:
    platform = 'linux'
    image_base = 0x0

vtable_rva = vtable_va - image_base

yaml_content = f'''vtable_class: {vtable_class}
vtable_va: {hex(vtable_va)}
vtable_rva: {hex(vtable_rva)}
'''

yaml_path = os.path.join(dir_path, f"{vtable_class}_vtable.{platform}.yaml")
with open(yaml_path, 'w', encoding='utf-8') as f:
    f.write(yaml_content)
print(f"Written to: {yaml_path}")
"""
```

## Interface Registration Pattern

The Source2Server interface follows this pattern:

```asm
lea     r8, aSource2server0  ; "Source2Server001"
lea     rdx, source2server   ; Interface implementation function
lea     rcx, s_Source2Server ; Static instance pointer
jmp     <registration_func>
```

## VTable Structure

The CSource2Server vtable contains virtual functions including:

| Offset | Function |
|--------|----------|
| +0x00 | Constructor/Destructor |
| +0x08 | ... |
| +0x18 | CSource2Server::Init |
| ... | ... |

## Key Globals

- `s_Source2Server` - Static instance pointer returned by `source2server()`
- `CSource2Server_vtable` - Virtual function table for CSource2Server class

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CSource2Server_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CSource2Server_vtable.linux.yaml`

```yaml
vtable_class: CSource2Server
vtable_va: 0x18171c170    # Virtual address - changes with game updates
vtable_rva: 0x171c170     # Relative virtual address - changes with game updates
```

## Platform Differences

### Windows (server.dll)
- Interface string: `Source2Server001`
- VTable mangled name pattern: Uses MSVC mangling

### Linux (server.so)
- Interface string: `Source2Server001`
- VTable mangled name pattern: `_ZTV14CSource2Server` (if present)
- Note: Linux vtables have 16 bytes of RTTI metadata before the actual function pointers
