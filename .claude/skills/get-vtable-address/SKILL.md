---
name: get-vtable-address
description: |
  Find a function's vtable address using IDA Pro MCP. Use this skill when want to get exact virtual address of a class.
  Triggers: get vftable address, get virtual function table, find vtable, get vtable
---

# Get VTable address and size

Find a class's virtual function table within it's class name. Get it's address and size.

## Prerequisites

- ClassName

## Method

### 1. Get vtable address by class name:

   Windows:
   ```
   mcp__ida-pro-mcp__list_globals(queries={"filter": "*ClassName*"})

   ```
   Linux:
   ```
   mcp__ida-pro-mcp__list_globals(queries={"filter": "_ZTV*ClassName*"})
   ```

   Look for:
   - Windows: `??_7ClassName@@6B@`, 
     For example: 
       `CGameRules` -> `??_7CGameRules@@6B@`
       `CCSPlayer_ItemServices` -> `??_7CCSPlayer_ItemServices@@6B@`

   - Linux: `_ZTV*ClassName` , 
     For example: 
       `CSource2Server` -> `ZTV14CSource2Server`
       `CGameRules` -> `_ZTV10CGameRules`
       `CCSPlayer_ItemServices` -> `_ZTV22CCSPlayer_ItemServices`

### 2. Get vtable size:
   Run this Python script using `mcp__ida-pro-mcp__py_eval` with the vtable address from step 1:

   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import ida_bytes, ida_name, idaapi

   # Replace with actual vtable address from step 1
   vtable_sym = <VTABLE_ADDRESS>

   # Detect platform by vtable symbol name
   vtable_name = ida_name.get_name(vtable_sym) or ""
   is_linux = vtable_name.startswith("_ZTV")

   # Handle Linux vtables (skip RTTI metadata: 2 pointers for typeinfo and offset-to-top)
   vtable_start = vtable_sym
   if is_linux:
       vtable_start = vtable_sym + 0x10

   # Determine pointer size
   ptr_size = 8 if idaapi.inf_is_64bit() else 4

   count = 0
   for i in range(1000):
       addr = vtable_start + i * ptr_size

       # Linux only: check if current address has a symbol name (next vtable or RTTI)
       if is_linux and i > 0:
           name = ida_name.get_name(addr)
           if name and (name.startswith("_ZTV") or name.startswith("_ZTI")):
               break

       if ptr_size == 8:
           ptr_value = ida_bytes.get_qword(addr)
       else:
           ptr_value = ida_bytes.get_dword(addr)

       # Handle NULL entries differently per platform
       if ptr_value == 0:
           if is_linux:
               # Linux: NULL may be pure virtual function, continue counting
               count += 1
               continue
           else:
               # Windows: NULL means vtable end
               break

       # Stop on invalid pointer marker
       if ptr_value == 0xFFFFFFFFFFFFFFFF:
           break

       # Check if it points to a function or code
       func = idaapi.get_func(ptr_value)
       if func is not None:
           count += 1
           continue

       # Also check if it's code that IDA hasn't recognized as a function
       flags = ida_bytes.get_full_flags(ptr_value)
       if ida_bytes.is_code(flags):
           count += 1
           continue

       # Not a valid function pointer, stop
       break

   size_in_bytes = count * ptr_size
   print(f"vtableAddress: {hex(vtable_start)}")
   print(f"sizeInBytes: {hex(size_in_bytes)}")
   print(f"numberOfVirtualFunctions: {count}")
   """
   ```

   Replace `<VTABLE_ADDRESS>` with the actual hex address (e.g., `0x180A12345`).

   **Platform-specific behavior**:
   - **Linux** (`_ZTV` prefix): NULL entries may be pure virtual functions, continues counting until reaching another symbol (`_ZTV`, `_ZTI`)
   - **Windows** (`??_7` prefix): Stops when vtable entry points to 0 or non-function pointer

### 3. Continue with Unfinished Tasks

If we are called by a task from a task list / parent SKILL, restore and continue with the unfinished tasks.

## Output

The skill returns:
- **vtableAddress**: The start address of the vtable
- **sizeInBytes**: Total size of the vtable in bytes
- **numberOfVirtualFunctions**: Count of virtual function entries in the vtable