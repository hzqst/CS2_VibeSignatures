---
name: find-CSource2Server_vtable
description: Find and identify the CSource2Server vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CSource2Server virtual function table by searching for the "_ZTV14CSource2Server" RTTI symbol (Linux) or tracing through the "Source2Server001" interface registration pattern (Windows).
---

# Find CSource2Server_vtable

Locate `CSource2Server_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method (Linux - Preferred)

For Linux binaries (server.so), use RTTI symbols to directly locate the vtable:

### 1. Search for VTable Symbol

```
mcp__ida-pro-mcp__list_globals queries={"filter": "_ZTV*CSource2Server*"}
```

Look for `_ZTV14CSource2Server` - this is the mangled vtable symbol.

### 2. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CSource2Server`
- `vtable_va`: The vtable address from step 1

Done! The `/write-vtable-as-yaml` skill automatically:
- Skips Linux RTTI metadata (16 bytes)
- Counts virtual functions
- Calculates vtable size
- Writes the YAML file

---

## Method (Windows - Alternative)

For Windows binaries (server.dll) without RTTI symbols, trace through the interface registration pattern:

### 1. Search for Interface String

Search for the Source2Server interface identifier:

```
mcp__ida-pro-mcp__find_regex pattern="Source2Server001"
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

The implementation function (e.g., `sub_180CBCA50`) simply returns a pointer to the static instance.

### 4. Rename Interface Implementation

```
mcp__ida-pro-mcp__rename batch={"func": {"addr": "<impl_func_addr>", "name": "source2server"}}
```

### 5. Decompile to Find Static Instance

```
mcp__ida-pro-mcp__decompile addr="<impl_func_addr>"
```

The function returns `&s_Source2Server` - rename this global:

```
mcp__ida-pro-mcp__rename batch={"data": {"old": "off_181bc3cd0", "new": "s_Source2Server"}}
```

### 6. Find VTable by Reading the Pointer s_Source2Server Points To

Use `get_global_value` to get the address of `s_Source2Server`, then read 8 bytes (64-bit pointer) at that address:

```
mcp__ida-pro-mcp__get_bytes regions={"addr": "<s_Source2Server_addr>", "size": 8}
```

The returned bytes are in little-endian format. Convert them to get the vtable address.

Example:
- Bytes: `0x90 0xd1 0x71 0x81 0x01 0x00 0x00 0x00`
- Reversed (little-endian): `0x18171D190`

### 7. Rename VTable

Use `func` rename with the vtable address:

```
mcp__ida-pro-mcp__rename batch={"func": {"addr": "<vtable_addr>", "name": "CSource2Server_vtable"}}
```

Example:
```
mcp__ida-pro-mcp__rename batch={"func": {"addr": "0x18171D190", "name": "CSource2Server_vtable"}}
```

### 8. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CSource2Server`
- `vtable_va`: The vtable address found in step 6

---

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

```yaml
vtable_class: CSource2Server
vtable_va: 0x18171c170    # Virtual address - changes with game updates
vtable_rva: 0x171c170     # Relative virtual address - changes with game updates
vtable_size: 0x120        # VTable size in bytes - changes with game updates
vtable_numvfunc: 36       # Number of virtual functions - changes with game updates
```

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
