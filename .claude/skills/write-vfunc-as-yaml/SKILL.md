---
name: write-vfunc-as-yaml
description: Write virtual function analysis results as YAML file beside the binary using IDA Pro MCP. Use this skill after completing virtual function identification, signature generation, and vtable analysis to persist the results in a standardized YAML format.
---

# Write Virtual Function IDA Analysis Output as YAML

Persist virtual function analysis results to a YAML file beside the binary using IDA Pro MCP.

## Prerequisites

Before using this skill, you should have:
1. Identified and renamed the target virtual function
2. Generated a unique signature using `/generate-signature-for-function`
3. Obtained vtable information using `/get-vtable-index`

## Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `func_name` | Name of the function | `CCSPlayerController_ChangeTeam` |
| `vtable_name` | Class name for vtable | `CCSPlayerController` |
| `vfunc_offset` | Offset from vtable start | `0x330` |
| `vfunc_index` | Index in vtable | `102` |

## Optional Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `func_addr` | Virtual address of the function (use `None` to omit) | `0x180999830` |
| `func_sig` | Unique byte signature to locate function body (use `None` to omit) | `48 89 5C 24 08` |
| `vfunc_sig` | Unique byte signature to determine vfunc offset (use `None` to omit) | `FF 90 80 04 00 00 4C 8B AC 24 ?? ?? ?? ??` |

When `func_addr` is `None`, the following fields will be omitted from output: `func_va`, `func_rva`, `func_size`.
When `func_sig` is `None`, the `func_sig` field will be omitted from output.
When `vfunc_sig` is `None`, the `vfunc_sig` field will be omitted from output.

## Method

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi
import os
import yaml

# === REQUIRED: Replace these values ===
func_name = "<func_name>"           # e.g., "CCSPlayerController_ChangeTeam"
# ======================================

# === OPTIONAL: Set to None to omit from output ===
func_addr = <func_addr>             # e.g., 0x180999830 or None
func_sig = <func_sig>               # e.g., "48 89 5C 24 08" or None
vfunc_sig = <vfunc_sig>               # e.g., "FF 90 80 04 00 00 4C 8B AC 24 ?? ?? ?? ??" or None
# =================================================

# === VTABLE INFO: Replace these values ===
vtable_name = "<vtable_name>"       # e.g., "CCSPlayerController"
vfunc_offset = <vfunc_offset>       # e.g., 0x330
vfunc_index = <vfunc_index>         # e.g., 102
# =========================================

# Get binary path and determine platform
input_file = idaapi.get_input_file_path()
dir_path = os.path.dirname(input_file)

if input_file.endswith('.dll'):
    platform = 'windows'
    image_base = idaapi.get_imagebase()
else:
    platform = 'linux'
    image_base = 0x0

# Build data dictionary conditionally
data = {}

if func_addr is not None:
    func = idaapi.get_func(func_addr)
    func_size = func.size() if func else 0
    func_rva = func_addr - image_base
    data['func_name'] = func_name
    data['func_va'] = hex(func_addr)
    data['func_rva'] = hex(func_rva)
    data['func_size'] = hex(func_size)

if func_sig is not None:
    data['func_sig'] = func_sig

if vfunc_sig is not None:
    data['vfunc_sig'] = vfunc_sig

data['vtable_name'] = vtable_name
data['vfunc_offset'] = hex(vfunc_offset)
data['vfunc_index'] = vfunc_index

yaml_path = os.path.join(dir_path, f"{func_name}.{platform}.yaml")
with open(yaml_path, 'w', encoding='utf-8') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
print(f"Written to: {yaml_path}")
"""
```

## Output File Naming Convention

The output YAML filename follows this pattern:
- `<func_name>.<platform>.yaml`

Examples:
- `server.dll` → `CCSPlayerController_ChangeTeam.windows.yaml`
- `server.so` / `libserver.so` → `CCSPlayerController_ChangeTeam.linux.yaml`

## Output YAML Format

Full output (with `func_addr` and `func_sig` provided):
```yaml
func_name: CCSPlayerController_ChangeTeam
func_va: 0x180999830      # Virtual address - changes with game updates (optional)
func_rva: 0x999830        # Relative virtual address (VA - image base) - changes with game updates (optional)
func_size: 0x301          # Function size in bytes - changes with game updates (optional)
func_sig: 48 89 5C 24 08  # Unique byte signature (optional)
vtable_name: CCSPlayerController
vfunc_offset: 0x330       # Offset from vtable start - changes with game updates
vfunc_index: 102          # vtable[102] - changes with game updates
```

Minimal output (with `func_addr=None`, `func_sig=None`, `vfunc_sig=None`):
```yaml
func_name: CCSPlayerController_ChangeTeam
vtable_name: CCSPlayerController
vfunc_offset: 0x330       # Offset from vtable start - changes with game updates
vfunc_index: 102          # vtable[102] - changes with game updates
```

## Platform Detection

The skill automatically detects the platform based on file extension:
- `.dll` → Windows (uses `idaapi.get_imagebase()` for image base)
- `.so` → Linux (uses `0x0` as image base)

## Notes

- All values marked "changes with game updates" should be regenerated when analyzing new binary versions
- The YAML file is written to the same directory as the input binary
- When `func_addr` is provided, func_size is automatically calculated from IDA's function analysis
- When `func_addr` is provided, func_rva is automatically calculated as `func_va - image_base`
- When `func_addr` / `func_sig` / `vfunc_sig`  is `None`, those fields are omitted from the output entirely
- This skill is specifically for virtual functions that have vtable information
- For regular functions without vtable, use `/write-func-as-yaml` instead
