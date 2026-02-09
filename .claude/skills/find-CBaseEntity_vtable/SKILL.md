---
name: find-CBaseEntity_vtable
description: Find and identify the CBaseEntity vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CBaseEntity virtual function table by searching for the mangled vtable symbol name.
---

# Find CBaseEntity_vtable

Locate `CBaseEntity_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get VTable Address and Size

Use `/get-vtable-address` skill with `CBaseEntity`:

```
/get-vtable-address CBaseEntity
```

This will return:
- `vtable_class`: `CBaseEntity`
- `vtable_symbol`: `??_7CBaseEntity@@6B@` or `_ZTV11CBaseEntity + 0x10`, depending on platform.
- `vtable_va`: The address of the vtable
- `vtable_size`: Total size of the vtable in bytes
- `vtable_numvfuncs`: Count of virtual function entries

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CBaseEntity`
- `vtable_symbol`: `??_7CBaseEntity@@6B@` or `_ZTV11CBaseEntity + 0x10`, depending on platform.
- `vtable_va`: The vtable address from step 1

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CBaseEntity@@6B@` - CBaseEntity vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV11CBaseEntity` - CBaseEntity vtable

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBaseEntity_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CBaseEntity_vtable.linux.yaml`

```yaml
vtable_class: CBaseEntity
vtable_symbol: ??_7CBaseEntity@@6B@   # The address of symbol "??_7CBaseEntity@@6B@" in IDA is the start address of CBaseEntity's vtable.
vtable_va: '0x1816f2a10'   # Virtual address - changes with game updates
vtable_rva: '0x16f2a10'    # Relative virtual address - changes with game updates
vtable_size: '0x770'       # VTable size in bytes - changes with game updates
vtable_numvfunc: 238       # Number of virtual functions - changes with game updates
```

```yaml
vtable_class: CBaseEntity
vtable_symbol: _ZTV11CBaseEntity + 0x10  # The address of symbol "_ZTV11CBaseEntity" in IDA, with "+ 0x10" offset, is the start address of CBaseEntity's vtable.
vtable_va: '0x216df80'      # Virtual address - changes with game updates
vtable_rva: '0x216df80'     # Relative virtual address - changes with game updates
vtable_size: '0x778'        # VTable size in bytes - changes with game updates
vtable_numvfunc: 239        # Number of virtual functions - changes with game updates
```
