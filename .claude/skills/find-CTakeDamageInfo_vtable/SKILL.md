---
name: find-CTakeDamageInfo_vtable
description: Find and identify the CTakeDamageInfo vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CTakeDamageInfo virtual function table by searching for the mangled vtable symbol name.
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
- `vtableAddress`: The address of the vtable
- `sizeInBytes`: Total size of the vtable in bytes
- `numberOfVirtualFunctions`: Count of virtual function entries

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
vtable_va: 0x180XXXXXX    # Virtual address - changes with game updates
vtable_rva: 0xXXXXXX      # Relative virtual address - changes with game updates
vtable_size: 0xXXX        # VTable size in bytes - changes with game updates
vtable_numvfunc: XX       # Number of virtual functions - changes with game updates
```
