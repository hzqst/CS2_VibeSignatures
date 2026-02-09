---
name: find-CServerSideClient_vtable
description: Find and identify the CServerSideClient vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 engine2.dll or libengine2.so to locate the CServerSideClient virtual function table by searching for the mangled vtable symbol name.
---

# Find CServerSideClient_vtable

Locate `CServerSideClient_vtable` in CS2 engine2.dll or libengine2.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CServerSideClient`:

```
/get-vtable-address CServerSideClient
```

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CServerSideClient`
- `vtable_va`: The vtable address from step 1
- `vtable_symbol`: The vtable symbol from step 1

## VTable Symbol Patterns

### Windows (engine2.dll)

The vtable uses MSVC name mangling:
- `??_7CServerSideClient@@6B@` - CServerSideClient vtable

### Linux (libengine2.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV18CServerSideClient` - CServerSideClient vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `engine2.dll` → `CServerSideClient_vtable.windows.yaml`
- `libengine2.so` → `CServerSideClient_vtable.linux.yaml`