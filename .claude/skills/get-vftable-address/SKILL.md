---
name: get-vftable-address
description: |
  Find a function's vtable address using IDA Pro MCP. Use this skill when want to get exact virtual address of a class.
  Triggers: get vftable address, get virtual function table, find vtable, get vtable
---

# Get VTable Index

Find a class's virtual function table within it's class name.

## Prerequisites

- ClassName

## Method

### 1. Get vtable address by class name:
   ```
   mcp__ida-pro-mcp__list_globals(queries={"filter": "*ClassName*"})
   ```
   Look for:
   - Windows: `??_7ClassName@@6B@`
   - Linux: `_ZTVNClassName` or `_ZTVN...E`

### 2. Get vtable size:
   Run this Python script using `mcp__ida-pro-mcp__py_eval` with the vtable address from step 1:

   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import ida_bytes, ida_name, idaapi

   # Replace with actual vtable address from step 1
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
           # Also check if it's code that IDA hasn't recognized as a function
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

   Replace `<VTABLE_ADDRESS>` with the actual hex address (e.g., `0x180A12345`).

### 3. Continue with Unfinished Tasks

If we are called by a task from a task list / parent SKILL, restore and continue with the unfinished tasks.

## Output

The skill returns:
- **vtableAddress**: The address of the vtable
- **sizeInBytes**: Total size of the vtable in bytes
- **numberOfVirtualFunctions**: Count of virtual function entries in the vtable

## Platform Notes

- **Windows**: VTable starts directly at the symbol address
- **Linux**: First 16 bytes are RTTI metadata. Real vtable address = `_ZTV... + 0x10`, The vtable structure is:
    - Offset 0x00: offset to this (8 bytes)
    - Offset 0x08: typeinfo pointer (8 bytes)
    - Offset 0x10: **Index 0 starts here**
