---
name: generate-signature-for-function
description: |
  Generate and validate unique byte signatures for functions using IDA Pro MCP. Use this skill when you need to create a pattern-scanning signature for a function that can reliably locate it across binary updates.
  Triggers: generate signature, byte signature, pattern signature, function signature, unique signature, sig for function
---

# Generate Signature for Function

Generate a unique hex byte signature for a function that can be used for pattern scanning.

## Prerequisites

- Function address (from decompilation, xrefs, or rename)
- IDA Pro MCP connection

## Method

### 1. Get Function Bytes and Disassembly

First, retrieve the raw bytes and disassembly to understand the function structure.

**Note**: The input address may be in the middle of a function. The script automatically resolves it to the actual function start.

```python
mcp__ida-pro-mcp__py_eval code="""
import ida_bytes
import idaapi

input_addr = <func_addr>

# Resolve to actual function start (input may be in the middle of a function)
func = idaapi.get_func(input_addr)
if func:
    func_addr = func.start_ea
    if func_addr != input_addr:
        print(f"Resolved {hex(input_addr)} -> function start at {hex(func_addr)}")
else:
    func_addr = input_addr
    print(f"Warning: {hex(input_addr)} is not inside a known function, using as-is")

# Get first 64 bytes of function
raw_bytes = ida_bytes.get_bytes(func_addr, 64)
print("Function address:", hex(func_addr))
print("Function bytes:", ' '.join(f'{b:02X}' for b in raw_bytes))
"""
```

Also get disassembly for context (use the resolved function address from above):
```
mcp__ida-pro-mcp__disasm addr="<resolved_func_addr>" max_instructions=15
```

### 2. Analyze and Generate Signature (LLM Task)

**YOU (the LLM) must analyze the bytes and disassembly to create a signature.**

When analyzing, consider:
- **Opcodes** (instruction bytes): Usually stable, keep as-is
- **Immediates/Offsets**: Often change between builds, use `??` wildcards
- **Register encodings**: Usually stable unless compiler changes register allocation
- **Relocation addresses**: Always use `??` wildcards (4 bytes for 32-bit, 8 for 64-bit)
- **Displacement values in memory operands**: May change, consider wildcarding, **ESPECIALLY** with E8 call, E9 jmp

Example analysis:
```
Bytes: 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 E8 12 34 56 00
       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^
       Prologue - stable opcodes                           Call with relative offset - wildcard it

Result: 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 E8 ?? ?? ?? ??
```

**Generate a signature that is:**
- Long enough to be unique (typically 16-32 bytes)
- Uses `??` for bytes that may change between binary updates
- Starts from function entry point

### 3. Validate Signature Uniqueness

Test that YOUR generated signature matches ONLY this function:

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi
import ida_bytes
import ida_segment

func_addr = <func_addr>

# YOUR GENERATED SIGNATURE HERE (space-separated hex with ?? for wildcards)
signature_str = "<YOUR_SIGNATURE>"  # e.g., "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 E8 ?? ?? ?? ??"

# IDA pattern syntax uses single '?' wildcard tokens (not '??').
pattern_str = " ".join("?" if p == "??" else p for p in signature_str.split())

# Get .text segment bounds
seg = ida_segment.get_segm_by_name(".text")
start = seg.start_ea
end = seg.end_ea

# Compile pattern and search using IDA's native binary search (fast, avoids get_bytes() timeouts)
pat = ida_bytes.compiled_binpat_vec_t()
ida_bytes.parse_binpat_str(pat, start, pattern_str, 16)

flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK
matches = []

res = ida_bytes.bin_search3(start, end, pat, flags)
ea = res[0] if isinstance(res, tuple) else res  # IDA 9 may return (ea, idx)
while ea != idaapi.BADADDR:
    matches.append(ea)
    res = ida_bytes.bin_search3(ea + 1, end, pat, flags)
    ea = res[0] if isinstance(res, tuple) else res

print(f"Signature matches: {len(matches)}")
for m in matches:
    print(hex(m))

if len(matches) == 1 and matches[0] == func_addr:
    print("SUCCESS: Signature is unique and matches target function!")
elif len(matches) == 1 and matches[0] != func_addr:
    print("WARNING: Signature matches but at different address ! You should re-generate a valid signature that exactly matches the {hex(func_addr)} !")
elif len(matches) > 1:
    print("FAILED: Signature not unique, need longer pattern.")
elif len(matches) == 0:
    print("FAILED: Found nothing with this signature. You should re-generate a valid signature that exactly matches the {hex(func_addr)} !")

"""
```

### 4. Iterate if Needed

If the signature is not unique:
1. Extend the signature length, maybe include some preceding padding, or even bytes from next function, to make it unique.
2. Re-validate until unique

### 5. Continue with Unfinished Tasks

If we are called by a task from a task list / parent SKILL, restore and continue with the unfinished tasks.

## Output Format

Signature format: space-separated hex bytes with `??` for wildcards.

Example: `48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ?? 48 8B F9 E8 ?? ?? ?? ??`

## Signature Analysis Guidelines for LLM

When analyzing function bytes, consider these instruction patterns:

### Bytes to Keep (Usually Stable)
- **Function prologues**: `48 89 5C 24` (mov [rsp+x], rbx), `55` (push rbp), `48 83 EC` (sub rsp)
- **Opcode bytes**: The actual instruction opcodes
- **ModR/M bytes**: Register-to-register operations
- **Fixed immediate values**: Constants that are part of the algorithm

### Bytes to Wildcard (May Change)
- **Relative call/jump offsets**: 4 bytes after `E8` (call) or `E9` (jmp) - these are relative addresses
- **Absolute addresses**: Any pointer/address in code
- **Stack offsets in large functions**: May change with local variable layout
- **String/data references**: Offsets to .rdata/.data sections

### Common Patterns
| Pattern | Meaning | Wildcard? |
|---------|---------|-----------|
| `E8 XX XX XX XX` | Relative call | Wildcard the 4 offset bytes |
| `48 8D 0D XX XX XX XX` | LEA with RIP-relative | Wildcard the 4 offset bytes |
| `FF 15 XX XX XX XX` | Indirect call via IAT | Wildcard the 4 offset bytes |
| `48 8B 05 XX XX XX XX` | MOV from global | Wildcard the 4 offset bytes |