---
name: find-CGameRules_vtable
description: Find and identify the CGameRules vtable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CGameRules virtual function table by searching for the mangled vtable symbol name.
---

# Find CGameRules_vtable

Locate `CGameRules_vtable` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Search for VTable Symbol

Search for the CGameRules vtable using the mangled name pattern:

```
mcp__ida-pro-mcp__list_globals(queries={"filter": "*CGameRules*"})
```

Look for:
- Windows: `??_7CGameRules@@6B@`
- Linux: `_ZTV10CGameRules`

### 2. Identify VTable Address

From the search results, identify the vtable symbol:

| Platform | Symbol Pattern | Example |
|----------|---------------|---------|
| Windows | `??_7CGameRules@@6B@` | Direct vtable address |
| Linux | `_ZTV10CGameRules` | Add 0x10 to skip RTTI metadata |

### 3. Get VTable Size

Run this Python script using `mcp__ida-pro-mcp__py_eval` with the vtable address:

```python
mcp__ida-pro-mcp__py_eval code="""
import ida_bytes, ida_name, idaapi

# Replace with actual vtable address from step 2
vtable_sym = <VTABLE_ADDRESS>

# Handle Linux vtables (skip RTTI metadata)
vtable_name = ida_name.get_name(vtable_sym) or ""
vtable_start = vtable_sym
if vtable_name.startswith("_ZTV"):
    vtable_start = vtable_sym + 0x10

# Determine pointer size
ptr_size = 8 if idaapi.inf_is_64bit() else 4
count = 0

# Count consecutive valid function pointers
for i in range(1000):
    if ptr_size == 8:
        ptr_value = ida_bytes.get_qword(vtable_start + i * ptr_size)
    else:
        ptr_value = ida_bytes.get_dword(vtable_start + i * ptr_size)

    # Stop if null or invalid pointer
    if ptr_value == 0 or ptr_value == 0xFFFFFFFFFFFFFFFF:
        break

    # Check if it points to a function
    func = idaapi.get_func(ptr_value)
    if func is None:
        flags = ida_bytes.get_full_flags(ptr_value)
        if not ida_bytes.is_code(flags):
            break

    count += 1

size_in_bytes = count * ptr_size
print(f"vtableAddress: {hex(vtable_start)}")
print(f"sizeInBytes: {size_in_bytes}")
print(f"numberOfVirtualFunctions: {count}")
"""
```

Replace `<VTABLE_ADDRESS>` with the actual hex address (e.g., `0x18171dc00`).

### 4. Rename VTable (Optional)

If the vtable doesn't have a meaningful name:

```
mcp__ida-pro-mcp__rename batch={"data": {"old": "<current_name>", "new": "CGameRules_vtable"}}
```

### 5. Write VTable Info as YAML

Use `/write-vtable-as-yaml` skill with:
- `vtable_class`: `CGameRules`
- `vtable_va`: The vtable address found in step 2

## VTable Symbol Patterns

### Windows (server.dll)

The vtable uses MSVC name mangling:
- `??_7CGameRules@@6B@` - CGameRules vtable

### Linux (server.so)

The vtable uses Itanium C++ ABI name mangling:
- `_ZTV10CGameRules` - CGameRules vtable
- Note: First 16 bytes are RTTI metadata (offset-to-top + typeinfo pointer)
- Real vtable starts at symbol address + 0x10

## Key Globals

- `??_7CGameRules@@6B@` (Windows) / `_ZTV10CGameRules` (Linux) - Virtual function table for CGameRules class

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CGameRules_vtable.windows.yaml`
- `server.so` / `libserver.so` → `CGameRules_vtable.linux.yaml`

```yaml
vtable_class: CGameRules
vtable_va: 0x18171dc00    # Virtual address - changes with game updates
vtable_rva: 0x171dc00     # Relative virtual address - changes with game updates
vtable_size: 0x3a0        # VTable size in bytes - changes with game updates
vtable_numvfunc: 116      # Number of virtual functions - changes with game updates
```

## Platform Differences

### Windows (server.dll)
- VTable starts directly at the symbol address
- Symbol pattern: `??_7CGameRules@@6B@`

### Linux (server.so)
- VTable has 16 bytes of RTTI metadata before function pointers
- Symbol pattern: `_ZTV10CGameRules`
- Real vtable address = symbol address + 0x10
