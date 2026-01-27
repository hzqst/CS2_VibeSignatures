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
- ClassName (to get vtable via `get-vftable-address` skill)

## Method

### 1. Get vtable address and size:
   **ALWAYS** Invoke the SKILL: `get-vftable-address` with the <ClassName> to obtain:
   - `vtableAddress`: The actual vtable start address (already adjusted for Linux RTTI offset)
   - `numberOfVirtualFunctions`: The valid vtable entry count

   Example output from `get-vftable-address`:
   ```
   vtableAddress: 0x180A12345
   sizeInBytes: 400
   numberOfVirtualFunctions: 50
   ```

### 2. Find function in vtable:

   IMPORTANT NOTES (common pitfalls):
   - Use the function *entry* address. VTables store pointers to the function start; string xrefs often land in the middle of a function.
     If you only have an address inside the function, resolve the real entry first (e.g. `idaapi.get_func(ea).start_ea`).
   - The `vtableAddress` from step 1 is already adjusted for Linux RTTI offset, use it directly.

   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import ida_bytes, idaapi

   # Target function address (MUST be the function entry/start address)
   # If you only have an address inside the function, uncomment the next 2 lines:
   # f = idaapi.get_func(func_addr)
   # func_addr = f.start_ea if f else func_addr
   func_addr = <FUNC_ADDRESS>

   # From get-vftable-address skill output
   vtable_start = <VTABLE_ADDRESS>
   vtable_size = <NUMBER_OF_VIRTUAL_FUNCTIONS>

   # Determine pointer size
   ptr_size = 8 if idaapi.inf_is_64bit() else 4

   # Search within the valid vtable range
   for i in range(vtable_size):
       if ptr_size == 8:
           ptr = ida_bytes.get_qword(vtable_start + i * ptr_size)
       else:
           ptr = ida_bytes.get_dword(vtable_start + i * ptr_size)
       if ptr == func_addr:
           print(f"Found at vtable offset: {hex(i * ptr_size)}, index: {i}")
           print(f"vtable_start: {hex(vtable_start)}")
           break
   else:
       print("Function not found in vtable!")
   """
   ```

   Replace:
   - `<FUNC_ADDRESS>` with the target function address
   - `<VTABLE_ADDRESS>` with `vtableAddress` from step 1
   - `<NUMBER_OF_VIRTUAL_FUNCTIONS>` with `numberOfVirtualFunctions` from step 1
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

- `vfunc_offset = index × ptr_size` (ptr_size = 8 for 64-bit, 4 for 32-bit)
- `vfunc_index = offset / ptr_size`

## Platform Notes

- **Windows/Linux**: The `vtableAddress` from `get-vftable-address` skill is already adjusted for platform differences (Linux RTTI offset handled automatically).
