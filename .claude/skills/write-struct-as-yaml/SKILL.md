---
name: write-struct-as-yaml
description: Write struct member analysis results as YAML file beside the binary using IDA Pro MCP. Use this skill after identifying struct member offsets to persist the results in a standardized YAML format. Supports incremental updates - new members are merged with existing entries.
---

# Write Struct Members as YAML

Persist struct member analysis results to a YAML file beside the binary using IDA Pro MCP.

## Prerequisites

Before using this skill, you should have:
1. Identified the struct name
2. Determined member offsets, names, and optionally sizes

## Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `struct_name` | Name of the struct/class | `CBaseEntity` |
| `members` | List of tuples: (offset, member_name, size) | `[(0x278, "m_skeletonInstance", 8), (0x3A0, "m_animationController", 8)]` |

**Note:** The `size` field is optional. Pass `None` or `0` to omit size from output.

## Method

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi
import os
import re

# === REQUIRED: Replace these values ===
struct_name = "<struct_name>"           # e.g., "CBaseEntity"
members = [                             # List of (offset, member_name, size)
    # (0x278, "m_skeletonInstance", 8),
    # (0x3A0, "m_animationController", 8),
    # (0x400, "m_someFlag", None),      # size is optional
]
# ======================================

# Get binary path and determine platform
input_file = idaapi.get_input_file_path()
dir_path = os.path.dirname(input_file)

if input_file.endswith('.dll'):
    platform = 'windows'
else:
    platform = 'linux'

yaml_path = os.path.join(dir_path, f"{struct_name}.{platform}.yaml")

# Read existing YAML if present
existing_entries = {}  # member_name -> (offset, size)
if os.path.exists(yaml_path):
    with open(yaml_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Parse format: "0xOFFSET: member_name [size]"
            match = re.match(r'^(0x[0-9A-Fa-f]+):\s+(\S+)(?:\s+(\d+))?$', line)
            if match:
                offset_str, name, size_str = match.groups()
                offset = int(offset_str, 16)
                size = int(size_str) if size_str else None
                existing_entries[name] = (offset, size)

# Merge new members (overwrite by member_name)
for offset, name, size in members:
    existing_entries[name] = (offset, size)

# Sort by offset and write
sorted_entries = sorted(existing_entries.items(), key=lambda x: x[1][0])

with open(yaml_path, 'w', encoding='utf-8') as f:
    for name, (offset, size) in sorted_entries:
        if size and size > 0:
            f.write(f"0x{offset:X}: {name} {size}\\n")
        else:
            f.write(f"0x{offset:X}: {name}\\n")

print(f"Written to: {yaml_path}")
print(f"Total members: {len(sorted_entries)}")
"""
```

## Output File Naming Convention

The output YAML filename follows this pattern:
- `<struct_name>.<platform>.yaml`

Examples:
- `server.dll` → `CBaseEntity.windows.yaml`
- `server.so` / `libserver.so` → `CBaseEntity.linux.yaml`

## Output YAML Format

```yaml
0x278: m_skeletonInstance 8
0x3A0: m_animationController 8
0x400: m_someFlag
```

Each line contains:
- `0xOFFSET:` - Hex offset from struct start
- `member_name` - Name of the struct member
- `size` (optional) - Size in bytes

## Merge Behavior

When writing to an existing YAML file:
1. **Same member_name**: The new entry overwrites the existing one (even if offset differs)
2. **Different member_name**: The new entry is appended
3. **After merge**: All entries are sorted by offset

This allows incremental updates to struct definitions as new members are discovered.

## Platform Detection

The skill automatically detects the platform based on file extension:
- `.dll` → Windows
- `.so` → Linux

## Example Usage

### Adding new members to an existing struct

```python
struct_name = "CBaseEntity"
members = [
    (0x278, "m_skeletonInstance", 8),
    (0x3A0, "m_animationController", 8),
]
```

### Updating an existing member's offset

If `CBaseEntity.windows.yaml` already contains `m_skeletonInstance` at a different offset, the new offset will replace it:

```python
struct_name = "CBaseEntity"
members = [
    (0x280, "m_skeletonInstance", 8),  # Updated offset
]
```

### Members without size

```python
struct_name = "CBaseEntity"
members = [
    (0x400, "m_bIsAlive", None),       # No size specified
    (0x408, "m_iHealth", 4),           # With size
]
```

## Notes

- All offsets are written in hexadecimal format with uppercase letters
- The YAML file is written to the same directory as the input binary
- Existing entries are preserved unless overwritten by matching member_name
- Entries are always sorted by offset after merge
