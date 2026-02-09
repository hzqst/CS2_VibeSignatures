---
name: find-CSource2Server_vtable
description: Find and identify the CSource2Server vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CSource2Server virtual function table by searching for the "_ZTV14CSource2Server" RTTI symbol (Linux) or tracing through the "Source2Server001" interface registration pattern (Windows).
---

# Find CSource2Server_vtable

Locate `CSource2Server_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Search for VTable Symbol

Use `/get-vtable-address` skill with `CSource2Server`:

```
/get-vtable-address CSource2Server
```

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CSource2Server`
- `vtable_va`: The vtable address from step 1
- `vtable_symbol`: The vtable symbol from step 1

## Interface Registration Pattern (Windows)

The Source2Server interface follows this pattern:

```asm
lea     r8, aSource2server0  ; "Source2Server001"
lea     rdx, source2server   ; Interface implementation function
lea     rcx, s_Source2Server ; Static instance pointer
jmp     <registration_func>
```

## Key Globals (Windows)

- `s_Source2Server` - Static instance pointer returned by `source2server()`
- `CSource2Server_vtable` - Virtual function table for CSource2Server class
- `s_Source2Server` points to `CSource2Server_vtable` as it's primary vtable.

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CSource2Server_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CSource2Server_vtable.linux.yaml`

## Platform Differences

### Linux (server.so) - Recommended Approach
- **Direct RTTI lookup**: Search for `_ZTV14CSource2Server` symbol
- VTable mangled name: `_ZTV14CSource2Server`
- Linux vtables have 16 bytes of RTTI metadata before the actual function pointers
- Much faster than tracing interface strings

### Windows (server.dll) - Alternative Approach
- **No RTTI symbols**: Must trace through interface registration pattern
- Interface string: `Source2Server001`
- VTable mangled name pattern: `??_7CSource2Server@@6B@` (MSVC mangling)
- Requires finding static instance and reading vtable pointer from it
