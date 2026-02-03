---
name: find-CBasePlayerPawn_vtable
description: Find and identify the CBasePlayerPawn vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CBasePlayerPawn virtual function table by searching for the mangled vtable symbol name.
expected_output:
  - name: CBasePlayerPawn_vtable
    category: vtable
    files:
      - CBasePlayerPawn_vtable.{platform}.yaml
---

# Find CBasePlayerPawn_vtable

Locate `CBasePlayerPawn_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CBasePlayerPawn`:

```
/get-vtable-address CBasePlayerPawn
```

This will return:
- `vtableAddress`: The address of the vtable
- `sizeInBytes`: Total size of the vtable in bytes
- `numberOfVirtualFunctions`: Count of virtual function entries

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CBasePlayerPawn`
- `vtable_va`: The vtable address from step 1

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CBasePlayerPawn@@6B@` - CBasePlayerPawn vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV15CBasePlayerPawn` - CBasePlayerPawn vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBasePlayerPawn_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CBasePlayerPawn_vtable.linux.yaml`

```yaml
vtable_class: CBasePlayerPawn
vtable_va: 0x216e380       # Virtual address - changes with game updates
vtable_rva: 0x216e380      # Relative virtual address - changes with game updates
vtable_size: 0xcf0         # VTable size in bytes - changes with game updates
vtable_numvfunc: 414       # Number of virtual functions - changes with game updates
```
