---
name: find-CCSPlayerController_vtable
description: Find and identify the CCSPlayerController vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CCSPlayerController virtual function table by searching for the mangled vtable symbol name.
---

# Find CCSPlayerController_vtable

Locate `CCSPlayerController_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CCSPlayerController`:

```
/get-vtable-address CCSPlayerController
```

This will return:
- `vtable_va`: The address of the vtable
- `vtable_size`: Total size of the vtable in bytes
- `vtable_numvfuncs`: Count of virtual function entries

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CCSPlayerController`
- `vtable_va`: The vtable address from step 1

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CCSPlayerController@@6B@` - CCSPlayerController vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV19CCSPlayerController` - CCSPlayerController vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSPlayerController_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CCSPlayerController_vtable.linux.yaml`

```yaml
vtable_class: CCSPlayerController
vtable_va: 0x1816b11c8    # Virtual address - changes with game updates
vtable_rva: 0x16b11c8     # Relative virtual address - changes with game updates
vtable_size: 0x898        # VTable size in bytes - changes with game updates
vtable_numvfunc: 275      # Number of virtual functions - changes with game updates
```
