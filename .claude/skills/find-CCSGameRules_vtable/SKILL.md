---
name: find-CCSGameRules_vtable
description: Find and identify the CCSGameRules vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CCSGameRules virtual function table by searching for the mangled vtable symbol name.
---

# Find CCSGameRules_vtable

Locate `CCSGameRules_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CCSGameRules`:

```
/get-vtable-address CCSGameRules
```

This will return:
- `vtableAddress`: The address of the vtable
- `sizeInBytes`: Total size of the vtable in bytes
- `numberOfVirtualFunctions`: Count of virtual function entries

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CCSGameRules`
- `vtable_va`: The vtable address from step 1

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CCSGameRules@@6B@` - CCSGameRules vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV12CCSGameRules` - CCSGameRules vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSGameRules_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CCSGameRules_vtable.linux.yaml`

```yaml
vtable_class: CCSGameRules
vtable_va: 0x21d5b38     # Virtual address - changes with game updates
vtable_rva: 0x21d5b38    # Relative virtual address - changes with game updates
vtable_size: 0x408       # VTable size in bytes - changes with game updates
vtable_numvfunc: 129     # Number of virtual functions - changes with game updates
```
