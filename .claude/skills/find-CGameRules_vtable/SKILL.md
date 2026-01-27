---
name: find-CGameRules_vtable
description: Find and identify the CGameRules vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CGameRules virtual function table by searching for the mangled vtable symbol name.
---

# Find CGameRules_vtable

Locate `CGameRules_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CGameRules`:

```
/get-vtable-address CGameRules
```

This will return:
- `vtableAddress`: The address of the vtable
- `sizeInBytes`: Total size of the vtable in bytes
- `numberOfVirtualFunctions`: Count of virtual function entries

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CGameRules`
- `vtable_va`: The vtable address from step 1

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CGameRules@@6B@` - CGameRules vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV10CGameRules` - CGameRules vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CGameRules_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CGameRules_vtable.linux.yaml`

```yaml
vtable_class: CGameRules
vtable_va: 0x18171dc00    # Virtual address - changes with game updates
vtable_rva: 0x171dc00     # Relative virtual address - changes with game updates
vtable_size: 0x3a0        # VTable size in bytes - changes with game updates
vtable_numvfunc: 116      # Number of virtual functions - changes with game updates
```
