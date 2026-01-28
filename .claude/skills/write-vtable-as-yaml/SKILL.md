---
name: write-vtable-as-yaml
description: Write vtable analysis results as YAML file beside the binary using IDA Pro MCP. Use this skill after locating a vtable to persist the results in a standardized YAML format.
---

# Write VTable as YAML

Persist vtable analysis results to a YAML file beside the binary using IDA Pro MCP.

## Prerequisites

Before using this skill, you should have:
1. Located the target vtable address
2. Identified the class name for the vtable

## Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `vtable_class` | Class name for the vtable | `CSource2Server` |
| `vtable_va` | Virtual address of the vtable | `0x182B8D9D8` |

## Method

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi
import ida_bytes
import ida_name
import os

# === REQUIRED: Replace these values ===
vtable_class = "<vtable_class>"     # e.g., "CSource2Server"
vtable_va = <vtable_va>             # e.g., 0x182B8D9D8
# ======================================

input_file = idaapi.get_input_file_path()
dir_path = os.path.dirname(input_file)

if input_file.endswith('.dll'):
    platform = 'windows'
    image_base = idaapi.get_imagebase()
else:
    platform = 'linux'
    image_base = 0x0

vtable_rva = vtable_va - image_base

# Handle Linux vtables (skip RTTI metadata)
vtable_name = ida_name.get_name(vtable_va) or ""
if vtable_name.startswith("_ZTV"):
    vtable_va = vtable_va + 0x10
    vtable_rva = vtable_va - image_base

# Determine pointer size and count virtual functions
ptr_size = 8 if idaapi.inf_is_64bit() else 4
count = 0

for i in range(1000):
    if ptr_size == 8:
        ptr_value = ida_bytes.get_qword(vtable_va + i * ptr_size)
    else:
        ptr_value = ida_bytes.get_dword(vtable_va + i * ptr_size)

    if ptr_value == 0 or ptr_value == 0xFFFFFFFFFFFFFFFF:
        break

    func = idaapi.get_func(ptr_value)
    if func is None:
        flags = ida_bytes.get_full_flags(ptr_value)
        if not ida_bytes.is_code(flags):
            break

    count += 1

vtable_size = count * ptr_size

yaml_content = f'''vtable_class: {vtable_class}
vtable_va: {hex(vtable_va)}
vtable_rva: {hex(vtable_rva)}
vtable_size: {hex(vtable_size)}
vtable_numvfunc: {count}
'''

yaml_path = os.path.join(dir_path, f"{vtable_class}_vtable.{platform}.yaml")
with open(yaml_path, 'w', encoding='utf-8') as f:
    f.write(yaml_content)
print(f"Written to: {yaml_path}")
"""
```

## Output File Naming Convention

The output YAML filename follows this pattern:
- `<vtable_class>_vtable.<platform>.yaml`

Examples:
- `server.dll` → `CSource2Server_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CSource2Server_vtable.linux.yaml`

## Output YAML Format

```yaml
vtable_class: CSource2Server
vtable_va: 0x182B8D9D8      # Virtual address - changes with game updates
vtable_rva: 0x2B8D9D8       # Relative virtual address (VA - image base) - changes with game updates
vtable_size: 0x2D8          # VTable size in bytes - changes with game updates
vtable_numvfunc: 91         # Number of virtual functions - changes with game updates
vtable_entries:
  - 0x180C87B20
  - 0x180C87FA0
  - 0x180C87FF0
```

## Platform Detection

The skill automatically detects the platform based on file extension:
- `.dll` → Windows (uses `idaapi.get_imagebase()` for image base)
- `.so` → Linux (uses `0x0` as image base, skips RTTI metadata for `_ZTV` prefixed vtables)

## Linux VTable Handling

For Linux binaries, vtables with `_ZTV` prefix (mangled vtable names) have RTTI metadata at the beginning:
- Offset 0x00: offset to top
- Offset 0x08: RTTI pointer
- Offset 0x10: First virtual function pointer

The skill automatically skips this metadata when counting virtual functions.

## Notes

- All values marked "changes with game updates" should be regenerated when analyzing new binary versions
- The YAML file is written to the same directory as the input binary
- vtable_size is automatically calculated as `vtable_numvfunc * pointer_size`
- vtable_rva is automatically calculated as `vtable_va - image_base`
