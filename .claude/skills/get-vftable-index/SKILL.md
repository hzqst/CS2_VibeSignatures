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

   IMPORTANT NOTES (common pitfalls):
   - Use the function *entry* address. VTables store pointers to the function start; string xrefs often land in the middle of a function.
     If you only have an address inside the function, resolve the real entry first (e.g. `idaapi.get_func(ea).start_ea`).
   - Linux vtables: the first 16 bytes are RTTI/metadata. The real vtable entries start at `_ZTV... + 0x10`.
   - If the function is not found, increase the scan range (some classes have very large vtables), and double-check you are scanning the correct class' vtable.

   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import ida_bytes, ida_name, idaapi, ida_segment

   # Target function address (MUST be the function entry/start address)
   # If you only have an address inside the function, uncomment the next 2 lines:
   # f = idaapi.get_func(func_addr)
   # func_addr = f.start_ea if f else func_addr
   func_addr = <func_addr>

   # VTable symbol (preferred on Linux), e.g. "_ZTV13CCSPlayerPawn"
   # Windows: vtable_start = vtable_sym
   # Linux:   vtable_start = vtable_sym + 0x10  (skip RTTI/metadata)
   vtable_sym = <vtable_addr>
   vtable_start = vtable_sym
   vtable_name = ida_name.get_name(vtable_sym) or ""
   if vtable_name.startswith("_ZTV"):
       vtable_start = vtable_sym + 0x10

   # VTable = array of 8-byte function pointers (64-bit)
   for i in range(500):
       ptr = ida_bytes.get_qword(vtable_start + i * 8)
       if ptr == func_addr:
           print(f"Found at vtable offset: {hex(i * 8)}, index: {i}")
           print("vtable_sym  :", hex(vtable_sym))
           print("vtable_start:", hex(vtable_start))
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
