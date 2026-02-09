---
name: find-CCSPlayer_ItemServices_vtable
description: Find and identify the CCSPlayer_ItemServices vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CCSPlayer_ItemServices virtual function table by searching for the mangled vtable symbol name.
---

# Find CCSPlayer_ItemServices_vtable

Locate `CCSPlayer_ItemServices_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CCSPlayer_ItemServices`:

```
/get-vtable-address CCSPlayer_ItemServices
```

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CCSPlayer_ItemServices`
- `vtable_va`: The vtable address from step 1
- `vtable_symbol`: The vtable symbol from step 1

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CCSPlayer_ItemServices@@6B@` - CCSPlayer_ItemServices vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV22CCSPlayer_ItemServices` - CCSPlayer_ItemServices vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSPlayer_ItemServices_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CCSPlayer_ItemServices_vtable.linux.yaml`
