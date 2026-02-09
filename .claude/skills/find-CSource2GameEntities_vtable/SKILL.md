---
name: find-CSource2GameEntities_vtable
description: Find and identify the CSource2GameEntities vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CSource2GameEntities virtual function table by searching for the "_ZTV21CSource2GameEntities" RTTI symbol (Linux) or tracing through the "Source2GameEntities001" interface registration pattern (Windows).
---

# Find CSource2GameEntities_vtable

Locate `CSource2GameEntities_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

For Linux binaries (server.so), use RTTI symbols to directly locate the vtable:

### 1. Search for VTable Symbol

Use `/get-vtable-address` skill with `CSource2GameEntities`:

```
/get-vtable-address CSource2GameEntities
```

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CSource2GameEntities`
- `vtable_va`: The vtable address from step 1
- `vtable_symbol`: The vtable symbol from step 1

## Interface Registration Pattern (Windows)

The Source2GameEntities interface follows this pattern:

```asm
lea     r8, aSource2gameent  ; "Source2GameEntities001"
lea     rdx, GetSource2GameEntities   ; Interface implementation function
lea     rcx, s_Source2GameEntities    ; Static instance pointer
jmp     <registration_func>
```

## Key Globals (Windows)

- `s_Source2GameEntities` - Static instance pointer returned by `GetSource2GameEntities()`
- `CSource2GameEntities_vtable` - Virtual function table for CSource2GameEntities class
- `s_Source2GameEntities` points to `CSource2GameEntities_vtable` as its primary vtable.

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CSource2GameEntities_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CSource2GameEntities_vtable.linux.yaml`

## Platform Differences

### Linux (server.so) - Recommended Approach
- **Direct RTTI lookup**: Search for `_ZTV21CSource2GameEntities` symbol
- VTable mangled name: `_ZTV21CSource2GameEntities`
- Linux vtables have 16 bytes of RTTI metadata before the actual function pointers
- Much faster than tracing interface strings

### Windows (server.dll) - Alternative Approach
- **No RTTI symbols**: Must trace through interface registration pattern
- Interface string: `Source2GameEntities001`
- VTable mangled name pattern: `??_7CSource2GameEntities@@6B@` (MSVC mangling)
- Requires finding static instance and reading vtable pointer from it
