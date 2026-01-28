---
name: find-CCSPlayerPawn_vtable
description: Find and identify the CCSPlayerPawn vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CCSPlayerPawn virtual function table by searching for the mangled vtable symbol name.
---

# Find CCSPlayerPawn_vtable

Locate `CCSPlayerPawn_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CCSPlayerPawn`:

```
/get-vtable-address CCSPlayerPawn
```

This will return:
- `vtableAddress`: The address of the vtable
- `sizeInBytes`: Total size of the vtable in bytes
- `numberOfVirtualFunctions`: Count of virtual function entries

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CCSPlayerPawn`
- `vtable_va`: The vtable address from step 1

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CCSPlayerPawn@@6B@` - CCSPlayerPawn vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV13CCSPlayerPawn` - CCSPlayerPawn vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSPlayerPawn_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CCSPlayerPawn_vtable.linux.yaml`

```yaml
vtable_class: CCSPlayerPawn
vtable_va: 0x181534778    # Virtual address - changes with game updates
vtable_rva: 0x1534778     # Relative virtual address - changes with game updates
vtable_size: 0xd50        # VTable size in bytes - changes with game updates
vtable_numvfunc: 426      # Number of virtual functions - changes with game updates
```
