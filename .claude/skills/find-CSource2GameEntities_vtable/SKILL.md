---
name: find-CSource2GameEntities_vtable
description: Find and identify the CSource2GameEntities vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CSource2GameEntities virtual function table by searching for the "_ZTV21CSource2GameEntities" RTTI symbol (Linux) or tracing through the "Source2GameEntities001" interface registration pattern (Windows).
---

# Find CSource2GameEntities_vtable

Locate `CSource2GameEntities_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method (Linux Only)

For Linux binaries (server.so), use RTTI symbols to directly locate the vtable:

### 1. Search for VTable Symbol

```
mcp__ida-pro-mcp__list_globals queries={"filter": "_ZTV*CSource2GameEntities*"}
```

Look for `_ZTV21CSource2GameEntities` - this is the mangled vtable symbol.

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CSource2GameEntities`
- `vtable_va`: The vtable address from step 1

Done! The `/write-vtable-as-yaml` skill automatically:
- Skips Linux RTTI metadata (16 bytes)
- Counts virtual functions
- Calculates vtable size
- Writes the YAML file

---

## Method (Windows Only)

For Windows binaries (server.dll) without RTTI symbols, trace through the interface registration pattern:

### 1. Search for Interface String

Search for the Source2GameEntities interface identifier:

```
mcp__ida-pro-mcp__find_regex pattern="Source2GameEntities001"
```

### 2. Get Cross-References to String

Find functions that reference this string:

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
```

Look for a small function (~0x1a bytes) that:
- Loads the interface string into r8
- Loads an implementation function into rdx
- Loads a global pointer into rcx
- Jumps to a registration function

### 3. Identify Interface Implementation Function

Decompile the small registration wrapper to find the interface implementation function:

```
mcp__ida-pro-mcp__decompile addr="<wrapper_func_addr>"
```

The implementation function (e.g., `sub_180CBXXXX`) simply returns a pointer to the static instance.

### 4. Rename Interface Implementation

```
mcp__ida-pro-mcp__rename batch={"func": {"addr": "<impl_func_addr>", "name": "GetSource2GameEntities"}}
```

### 5. Decompile to Find Static Instance

```
mcp__ida-pro-mcp__decompile addr="<impl_func_addr>"
```

The function returns `&s_Source2GameEntities` - rename this global:

```
mcp__ida-pro-mcp__rename batch={"data": {"old": "off_181XXXXXX", "new": "s_Source2GameEntities"}}
```

### 6. Find VTable by Reading the Pointer s_Source2GameEntities Points To

Use `get_bytes` to read 8 bytes (64-bit pointer) at the static instance address:

```
mcp__ida-pro-mcp__get_bytes regions={"addr": "<s_Source2GameEntities_addr>", "size": 8}
```

The returned bytes are in little-endian format. Convert them to get the vtable address.

Example:
- Bytes: `0x90 0xd5 0x71 0x81 0x01 0x00 0x00 0x00`
- Reversed (little-endian): `0x18171D590`

### 7. Rename VTable

Use `func` rename with the vtable address:

```
mcp__ida-pro-mcp__rename batch={"func": {"addr": "<vtable_addr>", "name": "CSource2GameEntities_vtable"}}
```

### 8. Write VTable Info as YAML

- **ALWAYS** Use SKILL `/write-vtable-as-yaml` with:
- `vtable_class`: `CSource2GameEntities`
- `vtable_va`: The vtable address found in step 6

---

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

```yaml
vtable_class: CSource2GameEntities
vtable_va: 0x18171D590    # Virtual address - changes with game updates
vtable_rva: 0x171D590     # Relative virtual address - changes with game updates
vtable_size: 0xXX         # VTable size in bytes - changes with game updates
vtable_numvfunc: XX       # Number of virtual functions - changes with game updates
```

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
