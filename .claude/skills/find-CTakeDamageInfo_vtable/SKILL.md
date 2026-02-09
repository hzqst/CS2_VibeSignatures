---
name: find-CTakeDamageInfo_vtable
description: Find and identify the CTakeDamageInfo vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CTakeDamageInfo virtual function table by searching for the mangled vtable symbol name.
expected_output:
  - name: CTakeDamageInfo_vtable
    category: vtable
    files:
      - CTakeDamageInfo_vtable.{platform}.yaml
---

# Find CTakeDamageInfo_vtable

Locate `CTakeDamageInfo_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CTakeDamageInfo`:

```
/get-vtable-address CTakeDamageInfo
```

This will return:
- `vtable_va`: The address of the vtable
- `vtable_size`: Total size of the vtable in bytes
- `vtable_numvfuncs`: Count of virtual function entries

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CTakeDamageInfo`
- `vtable_va`: The vtable address from step 1

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CTakeDamageInfo@@6B@` - CTakeDamageInfo vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV15CTakeDamageInfo` - CTakeDamageInfo vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CTakeDamageInfo_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CTakeDamageInfo_vtable.linux.yaml`

```yaml
vtable_class: CTakeDamageInfo
vtable_va: 0x215f528        # Virtual address - changes with game updates
vtable_rva: 0x215f528       # Relative virtual address - changes with game updates
vtable_size: 0x18           # VTable size in bytes - changes with game updates
vtable_numvfunc: 3          # Number of virtual functions - changes with game updates
```
