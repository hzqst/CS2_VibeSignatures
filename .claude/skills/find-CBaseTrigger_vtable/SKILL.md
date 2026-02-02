---
name: find-CBaseTrigger_vtable
description: Find and identify the CBaseTrigger vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CBaseTrigger virtual function table by searching for the mangled vtable symbol name.
---

# Find CBaseTrigger_vtable

Locate `CBaseTrigger_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CBaseTrigger`:

```
/get-vtable-address CBaseTrigger
```

This will return:
- `vtableAddress`: The address of the vtable
- `sizeInBytes`: Total size of the vtable in bytes
- `numberOfVirtualFunctions`: Count of virtual function entries

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CBaseTrigger`
- `vtable_va`: The vtable address from step 1

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CBaseTrigger@@6B@` - CBaseTrigger vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV12CBaseTrigger` - CBaseTrigger vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBaseTrigger_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CBaseTrigger_vtable.linux.yaml`

```yaml
vtable_class: CBaseTrigger
vtable_va: 0x2227958      # Virtual address - changes with game updates
vtable_rva: 0x2227958     # Relative virtual address - changes with game updates
vtable_size: 0x888        # VTable size in bytes - changes with game updates
vtable_numvfunc: 273      # Number of virtual functions - changes with game updates
```
