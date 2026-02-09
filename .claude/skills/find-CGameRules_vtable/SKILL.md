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

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CGameRules`
- `vtable_va`: The vtable address from step 1
- `vtable_symbol`: The vtable symbol from step 1

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
