---
name: find-CBasePlayerController_vtable
description: Find and identify the CBasePlayerController vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CBasePlayerController virtual function table by searching for the mangled vtable symbol name.
---

# Find CBasePlayerController_vtable

Locate `CBasePlayerController_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CBasePlayerController`:

```
/get-vtable-address CBasePlayerController
```

This will return:
- `vtable_va`: The address of the vtable
- `vtable_size`: Total size of the vtable in bytes
- `vtable_numvfuncs`: Count of virtual function entries

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CBasePlayerController`
- `vtable_va`: The vtable address from step 1

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CBasePlayerController@@6B@` - CBasePlayerController vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV21CBasePlayerController` - CBasePlayerController vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBasePlayerController_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CBasePlayerController_vtable.linux.yaml`

```yaml
vtable_class: CBasePlayerController
vtable_va: 0x2227958      # Virtual address - changes with game updates
vtable_rva: 0x2227958     # Relative virtual address - changes with game updates
vtable_size: 0x888        # VTable size in bytes - changes with game updates
vtable_numvfunc: 273      # Number of virtual functions - changes with game updates
```
