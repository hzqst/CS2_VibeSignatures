---
name: find-CTakeDamageInfo_vtable
description: Find and identify the CTakeDamageInfo vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CTakeDamageInfo virtual function table by searching for the mangled vtable symbol name.
expected_output:
  - name: CTakeDamageInfo_vtable
    category: vtable
    files:
      - CTakeDamageInfo_vtable.{platform}.yaml
---

# Find CTakeDamageInfo_vtable

Locate `CTakeDamageInfo_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CTakeDamageInfo`:

```
/get-vtable-address CTakeDamageInfo
```

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CTakeDamageInfo`
- `vtable_va`: The vtable address from step 1
- `vtable_symbol`: The vtable symbol from step 1

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CTakeDamageInfo@@6B@` - CTakeDamageInfo vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV15CTakeDamageInfo` - CTakeDamageInfo vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CTakeDamageInfo_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CTakeDamageInfo_vtable.linux.yaml`
