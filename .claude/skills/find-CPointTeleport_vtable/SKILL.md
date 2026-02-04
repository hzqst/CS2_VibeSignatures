---
name: find-CPointTeleport_vtable
description: Find and identify the CPointTeleport vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CPointTeleport virtual function table by searching for the mangled vtable symbol name.
---

# Find CPointTeleport_vtable

Locate `CPointTeleport_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CPointTeleport`:

```
/get-vtable-address CPointTeleport
```

This will return:
- `vtableAddress`: The address of the vtable
- `sizeInBytes`: Total size of the vtable in bytes
- `numberOfVirtualFunctions`: Count of virtual function entries

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CPointTeleport`
- `vtable_va`: The vtable address from step 1

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CPointTeleport@@6B@` - CPointTeleport vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV15CPointTeleport` - CPointTeleport vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CPointTeleport_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CPointTeleport_vtable.linux.yaml`

```yaml
vtable_class: CPointTeleport
vtable_va: 0x18175fa00    # Virtual address - changes with game updates
vtable_rva: 0x175fa00     # Relative virtual address - changes with game updates
vtable_size: 0x770        # VTable size in bytes - changes with game updates
vtable_numvfunc: 238      # Number of virtual functions - changes with game updates
```
