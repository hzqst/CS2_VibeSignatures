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

### 1b. Fallback: Locate vtable via RTTI COL / TypeInfo symbols

   If `list_globals` in step 1 cannot find the vtable symbol (`??_7ClassName@@6B@` or `_ZTV*ClassName`), leverage IDA's existing RTTI symbol analysis to reverse-locate the vtable via cross-references.

   #### Windows (PE) fallback:

   IDA typically creates `??_R4ClassName@@6B@` (RTTI Complete Object Locator) symbols. The vtable meta-entry in `.rdata` stores a pointer to the COL, and the vtable starts immediately after:
   ```
   .rdata:XXXX     dq offset ??_R4ClassName@@6B@   ; COL pointer (vtable meta-entry)
   .rdata:XXXX+8   ??_7ClassName@@6B@  dq ...      ; first vfunc = vtable_start
   ```

   **Step A**: Find the COL symbol:
   ```
   mcp__ida-pro-mcp__list_globals(queries={"filter": "??_R4*ClassName*"})
   ```
   Look for: `??_R4ClassName@@6B@`

   **Step B**: Use data xrefs to find the vtable meta-entry that points to the COL:
   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import idautils, idaapi, ida_bytes, ida_name, ida_segment

   class_name = "<CLASS_NAME>"  # Replace with actual class name
   col_addr = <COL_ADDRESS>     # Replace with ??_R4ClassName@@6B@ address from Step A

   ptr_size = 8 if idaapi.inf_is_64bit() else 4
   rdata_seg = ida_segment.get_segm_by_name(".rdata")

   vtable_start = None
   for ref in idautils.DataRefsTo(col_addr):
       # Only accept references within .rdata (vtable meta-entry)
       if rdata_seg and not (rdata_seg.start_ea <= ref < rdata_seg.end_ea):
           continue
       vtable_start = ref + ptr_size
       break

   assert vtable_start, f"No vtable meta-entry referencing COL for {class_name}"

   sym = ida_name.get_name(vtable_start) or f"??_7{class_name}@@6B@"
   print(f"[RTTI Fallback] Found vtable for {class_name}")
   print(f"vtable_va: {hex(vtable_start)}")
   print(f"vtable_symbol: {sym}")
   """
   ```

   #### Linux (ELF) fallback:

   IDA typically creates `_ZTI<len>ClassName` (typeinfo) symbols. The vtable stores a pointer to typeinfo at offset +0x8 from the `_ZTV` symbol, with offset-to-top at +0x0:
   ```
   .data.rel.ro:XXXX      _ZTV...  dq 0                     ; offset-to-top (must be 0)
   .data.rel.ro:XXXX+0x8           dq offset _ZTI...        ; typeinfo pointer
   .data.rel.ro:XXXX+0x10          dq offset first_vfunc    ; vtable_start
   ```

   **Step A**: Find the typeinfo symbol:
   ```
   mcp__ida-pro-mcp__list_globals(queries={"filter": "_ZTI*ClassName*"})
   ```
   Look for: `_ZTI<len>ClassName` (e.g., `_ZTI11CBaseEntity`)

   **Step B**: Use data xrefs to find the vtable entry that points to the typeinfo, then verify offset-to-top == 0:
   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import idautils, idaapi, ida_bytes, ida_name

   class_name = "<CLASS_NAME>"      # Replace with actual class name
   typeinfo_addr = <TYPEINFO_ADDRESS>  # Replace with _ZTI address from Step A

   ptr_size = 8 if idaapi.inf_is_64bit() else 4

   vtable_start = None
   for ref in idautils.DataRefsTo(typeinfo_addr):
       # offset-to-top is ptr_size bytes before the typeinfo pointer
       ott = ida_bytes.get_qword(ref - ptr_size) if ptr_size == 8 else ida_bytes.get_dword(ref - ptr_size)
       if ott == 0:
           vtable_start = ref + ptr_size
           break

   assert vtable_start, f"No primary vtable referencing typeinfo for {class_name}"

   ztv_addr = vtable_start - 0x10
   ztv_name = ida_name.get_name(ztv_addr) or ""
   sym = f"{ztv_name} + 0x10" if ztv_name else f"_ZTV{len(class_name)}{class_name} + 0x10"
   print(f"[RTTI Fallback] Found vtable for {class_name}")
   print(f"vtable_va: {hex(vtable_start)}")
   print(f"vtable_symbol: {sym}")
   """
   ```

   **Using fallback results with Step 2**: The fallback outputs `vtable_va` which is already the start address of virtual function pointers. In Step 2's script:
   - Set `vtable_start` directly to the `vtable_va` from the fallback (skip the `vtable_sym` → `vtable_start` offset adjustment)
   - Use the `class_name` and `vtable_symbol` already output by the fallback (skip the mangled name parsing)

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

   # Extract class name from mangled vtable symbol
   if is_linux:
       # Itanium mangling: _ZTV<len><name> (simple) or _ZTVN<len><name>...E (nested)
       mangled = vtable_name[4:]  # strip "_ZTV"
       class_name = ""
       i = 0
       while i < len(mangled) and mangled[i].isdigit():
           j = i
           while j < len(mangled) and mangled[j].isdigit():
               j += 1
           length = int(mangled[i:j])
           class_name += mangled[j:j+length]
           i = j + length
       if not class_name:
           class_name = mangled
       vtable_symbol_str = f"{vtable_name} + 0x10"
   else:
       # MSVC mangling: ??_7ClassName@@6B@
       if vtable_name.startswith("??_7") and "@@" in vtable_name:
           class_name = vtable_name[4:vtable_name.index("@@")]
       else:
           class_name = vtable_name
       vtable_symbol_str = vtable_name

   print(f"vtable_class: {class_name}")
   print(f"vtable_symbol: {vtable_symbol_str}")
   print(f"vtable_va: {hex(vtable_start)}")
   print(f"vtable_size: {hex(size_in_bytes)}")
   print(f"vtable_numvfuncs: {count}")
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
- **vtable_va**: The class name of vtable
- **vtable_symbol**: The IDA symbol of vtable address. typically `mangledVTableName` or `mangledVTableName + 0x10` depending on platform. e.g. `??_7CGameRules@@6B@` or `_ZTV10CGameRules + 0x10`.
- **vtable_va**: The start address of the vtable
- **vtable_size**: Total size of the vtable in bytes
- **vtable_numvfuncs**: Count of virtual function entries in the vtable