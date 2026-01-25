---
name: get-vftable-index
description: |
  Find a function's vtable offset and index using IDA Pro MCP. Use this skill when you have a function address and need to determine its position in a vtable by iterating through vtable entries.
  Triggers: vtable index, vftable offset, virtual function table position, find function in vtable
---

# Get VTable Index

Find a function's position (offset and index) within a vtable by iterating through vtable entries.

## Prerequisites

- Function address (from decompilation or xrefs)
- VTable address (from `list_globals` with class name filter)

## Method

### 1. Get vtable address:
   ```
   mcp__ida-pro-mcp__list_globals(queries={"filter": "*ClassName*"})
   ```
   Look for:
   - Windows: `??_7ClassName@@6B@`
   - Linux: `_ZTVNClassName` or `_ZTVN...E`

### 2. Find function in vtable:
   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import ida_bytes

   func_addr = <func_addr>       # Target function address
   vtable_addr = <vtable_addr>   # VTable start address

   # VTable = array of 8-byte function pointers (64-bit)
   for i in range(500):
       ptr = ida_bytes.get_qword(vtable_addr + i * 8)
       if ptr == func_addr:
           print(f"Found at vtable offset: {hex(i * 8)}, index: {i}")
           break
   else:
       print("Function not found in vtable!")
   """
   ```
### 3. Continue with the unfinished tasks

    If we are called by a task from a task list / parent SKILL, restore and continue with the unfinished tasks.

## Memory Layout

```
VTable @ vtable_addr:
┌─────────────────┬──────────────────────┐
│ Offset   Index  │ Value (func pointer) │
├─────────────────┼──────────────────────┤
│ 0x000    [0]    │ 0x180XXXXXX          │
│ 0x008    [1]    │ 0x180XXXXXX          │
│ ...      ...    │ ...                  │
│ 0xNNN    [N]    │ func_addr  ← Found!  │
└─────────────────┴──────────────────────┘
```

## Formulas

- `vfunc_offset = index × 8`
- `vfunc_index = offset / 8`

## Platform Notes

- **Windows**: VTable starts directly at the symbol address
- **Linux**: First 16 bytes are RTTI metadata. Real vtable = `_ZTV... + 0x10`
