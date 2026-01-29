---
name: generate-signature-for-globalvar
description: |
  Generate and validate unique byte signatures for global variable using IDA Pro MCP. Use this skill when you need to create a pattern-scanning signature for a global variable that can reliably locate it across binary updates.
  Triggers: global variable signature, signature for global variable
---

# Generate Signature for Global Variable

Generate a unique hex byte signature that locates an **instruction accessing a global variable**. Users can then resolve the actual global variable address at runtime by parsing the instruction's RIP-relative offset.

## Core Concept

Since global variable addresses change between binary updates, we don't signature the GV itself. Instead, we:
1. Find an instruction that **references** the global variable (mov/lea/cmp/etc.)
2. Generate a signature to locate that **instruction**
3. At runtime, parse the instruction to **resolve** the actual GV address

### RIP-Relative Addressing (x86-64)

In x86-64, most global variable accesses use RIP-relative addressing:
```
GV_Address = Instruction_Address + Instruction_Length + RIP_Offset
```

Where:
- `Instruction_Address` = address found by pattern scan
- `Instruction_Length` = total bytes of the instruction (opcode + ModR/M + offset)
- `RIP_Offset` = signed 32-bit displacement (last 4 bytes of instruction)

## Prerequisites

- Global variable address. `qword_XXXXXX` for example.
- IDA Pro MCP connection

## Method

### 1. Find an instruction that has ref to this global variable

- Find an instruction that has reference to this global variable, for example:

`48 8B 1D XX XX XX XX     mov rbx, cs:qword_XXXXXX`.

### 2. Analyze and Generate Signature (LLM Task)

**YOU (the LLM) must analyze the bytes and disassembly to create a signature.**

When analyzing, consider:
- **Opcodes** (instruction bytes): Usually stable, keep as-is
- **Immediates/Offsets**: Often change between builds, use `??` wildcards
- **Register encodings**: Usually stable unless compiler changes register allocation
- **Relocation addresses**: Always use `??` wildcards (4 bytes for 32-bit, 8 for 64-bit)
- **Displacement values in memory operands**: May change, consider wildcarding, **ESPECIALLY** with E8 call, E9 jmp, jnz, jz, je, jne, other conditional branching...

Example analysis:
```
.text:00000001804F3DF3 48 8B 1D 2E 93 88 01                                mov     rbx, cs:IGameSystem_InitAllSystems_pFirst
.text:00000001804F3DFA 48 85 DB                                            test    rbx, rbx
.text:00000001804F3DFD 0F 84 A4 00 00 00                                   jz      loc_1804F3EA7
.text:00000001804F3E03 BD FF FF 00 00                                      mov     ebp, 0FFFFh
```

Expected Result: `48 8B 1D ?? ?? ?? ?? 48 85 DB 0F ?? ?? ?? ?? BD FF FF 00 00`

**Generate a signature that is:**
- Long enough to be unique (typically 16-32 bytes)
- Uses `??` for bytes that may change between binary updates
- **Includes the GV-accessing instruction** (the instruction with RIP-relative offset to the GV)

**IMPORTANT:** Record the offset from signature start to the GV-accessing instruction. This is needed for runtime resolution.

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

Provide the following information for runtime GV resolution:

### Required Output Fields

1. **signature**: Space-separated hex bytes with `??` for wildcards
2. **instr_offset**: Offset (in bytes) from signature start to the GV-accessing instruction
3. **instr_length**: Total length of the GV-accessing instruction (for RIP calculation)
4. **offset_position**: Position of the 4-byte RIP-relative offset within the instruction

### Example Output

```yaml
signature: "48 8B 1D ?? ?? ?? ?? 48 85 DB 0F 84 ?? ?? ?? ?? BD FF FF 00 00"
instr_offset: 0          # GV instruction starts at signature start
instr_length: 7          # 48 8B 1D XX XX XX XX = 7 bytes
offset_position: 3       # Offset bytes start at position 3 (after 48 8B 1D)
```

### Runtime Resolution Formula

At runtime, after pattern scan finds the signature at address `scan_result`:

```cpp
// C++ example
uint8_t* instr_addr = scan_result + instr_offset;
int32_t rip_offset = *(int32_t*)(instr_addr + offset_position);
void* gv_address = instr_addr + instr_length + rip_offset;
```

```python
# Python example
import struct
instr_addr = scan_result + instr_offset
rip_offset = struct.unpack('<i', memory[instr_addr + offset_position : instr_addr + offset_position + 4])[0]
gv_address = instr_addr + instr_length + rip_offset
```

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

### GV-Accessing Instruction Reference (x86-64)

Use this table to determine `instr_length` and `offset_position` for common GV access patterns:

| Opcode Pattern | Example Disasm | instr_length | offset_position | Notes |
|----------------|----------------|--------------|-----------------|-------|
| `48 8B 05 XX XX XX XX` | `mov rax, [rip+XX]` | 7 | 3 | Load 64-bit from GV |
| `48 8B 0D XX XX XX XX` | `mov rcx, [rip+XX]` | 7 | 3 | Load 64-bit from GV |
| `48 8B 15 XX XX XX XX` | `mov rdx, [rip+XX]` | 7 | 3 | Load 64-bit from GV |
| `48 8B 1D XX XX XX XX` | `mov rbx, [rip+XX]` | 7 | 3 | Load 64-bit from GV |
| `48 8B 35 XX XX XX XX` | `mov rsi, [rip+XX]` | 7 | 3 | Load 64-bit from GV |
| `48 8B 3D XX XX XX XX` | `mov rdi, [rip+XX]` | 7 | 3 | Load 64-bit from GV |
| `4C 8B 05 XX XX XX XX` | `mov r8, [rip+XX]` | 7 | 3 | Load 64-bit from GV (r8-r15) |
| `48 8D 05 XX XX XX XX` | `lea rax, [rip+XX]` | 7 | 3 | Load address of GV |
| `48 8D 0D XX XX XX XX` | `lea rcx, [rip+XX]` | 7 | 3 | Load address of GV |
| `48 8D 15 XX XX XX XX` | `lea rdx, [rip+XX]` | 7 | 3 | Load address of GV |
| `48 8D 1D XX XX XX XX` | `lea rbx, [rip+XX]` | 7 | 3 | Load address of GV |
| `48 89 05 XX XX XX XX` | `mov [rip+XX], rax` | 7 | 3 | Store 64-bit to GV |
| `48 89 0D XX XX XX XX` | `mov [rip+XX], rcx` | 7 | 3 | Store 64-bit to GV |
| `48 89 15 XX XX XX XX` | `mov [rip+XX], rdx` | 7 | 3 | Store 64-bit to GV |
| `48 89 1D XX XX XX XX` | `mov [rip+XX], rbx` | 7 | 3 | Store 64-bit to GV |
| `8B 05 XX XX XX XX` | `mov eax, [rip+XX]` | 6 | 2 | Load 32-bit from GV (no REX) |
| `8B 0D XX XX XX XX` | `mov ecx, [rip+XX]` | 6 | 2 | Load 32-bit from GV (no REX) |
| `89 05 XX XX XX XX` | `mov [rip+XX], eax` | 6 | 2 | Store 32-bit to GV (no REX) |
| `48 83 3D XX XX XX XX YY` | `cmp qword [rip+XX], YY` | 8 | 3 | Compare GV with imm8 |
| `48 39 05 XX XX XX XX` | `cmp [rip+XX], rax` | 7 | 3 | Compare GV with reg |
| `48 C7 05 XX XX XX XX YY YY YY YY` | `mov qword [rip+XX], imm32` | 11 | 3 | Store imm32 to GV |
| `C7 05 XX XX XX XX YY YY YY YY` | `mov dword [rip+XX], imm32` | 10 | 2 | Store imm32 to GV (no REX) |
| `F3 0F 10 05 XX XX XX XX` | `movss xmm0, [rip+XX]` | 8 | 4 | Load float from GV |
| `F3 0F 11 05 XX XX XX XX` | `movss [rip+XX], xmm0` | 8 | 4 | Store float to GV |
| `F2 0F 10 05 XX XX XX XX` | `movsd xmm0, [rip+XX]` | 8 | 4 | Load double from GV |
| `0F B6 05 XX XX XX XX` | `movzx eax, byte [rip+XX]` | 7 | 3 | Load byte from GV (zero-extend) |
| `0F BE 05 XX XX XX XX` | `movsx eax, byte [rip+XX]` | 7 | 3 | Load byte from GV (sign-extend) |

## Important

**DO NOT** use `find_bytes` to validate signatures - it doesn't work reliably for code pattern matching. Always use the `py_eval` method with mask support above.
