---
name: generate-signature-for-globalvar
description: |
  Generate and validate unique byte signatures for global variable using IDA Pro MCP. Use this skill when you need to create a pattern-scanning signature for a global variable that can reliably locate it across binary updates.
  Triggers: global variable signature, signature for global variable
---

# Generate Signature for Global Variable

Generate a unique hex byte signature that locates an **instruction accessing a global variable** using fully programmatic wildcard detection — no manual byte analysis required.

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

### 1. Find GV-Accessing Instructions and Generate Signature Tokens

Use a single `py_eval` call to:
- Find instructions that reference the GV via `DataRefsTo`
- Verify each instruction actually resolves to the target GV via RIP-relative displacement
- Collect instruction stream with auto-wildcarding for each candidate
- Output candidates with full signature tokens and metadata

**Note**: If you already know the GV-accessing instruction address, set `target_inst = <inst_addr>` to skip candidate discovery. If you know the containing function, set `target_func = <func_addr>` to restrict search to that function.

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi, ida_bytes, idautils, ida_ua, json

target_gv = <gv_addr>
target_inst = None       # Set to instruction address if known, e.g. 0x1804F3DF3
target_func = None       # Set to function address to restrict search, e.g. 0x1804F3DA0
max_sig_bytes = 96
max_instructions = 64
max_candidates = 32

def _resolve_disp_off(insn_ea, insn, raw):
    \"\"\"Find the RIP-relative displacement offset that resolves to target_gv.\"\"\"
    cand_offsets = set()
    for op in insn.ops:
        op_type = int(op.type)
        if op_type == int(idaapi.o_void):
            continue
        offb = int(getattr(op, 'offb', 0))
        offo = int(getattr(op, 'offo', 0))
        if offb > 0 and offb + 4 <= insn.size:
            cand_offsets.add(offb)
        if offo > 0 and offo + 4 <= insn.size:
            cand_offsets.add(offo)

    for off in sorted(cand_offsets):
        disp_i32 = int.from_bytes(raw[off:off + 4], 'little', signed=True)
        resolved = (insn_ea + insn.size + disp_i32) & 0xFFFFFFFFFFFFFFFF
        if resolved == target_gv:
            return off
    return None

def _collect_sig_stream(inst_ea, disp_off):
    \"\"\"Collect instruction stream with auto-wildcarding starting from inst_ea.\"\"\"
    f = idaapi.get_func(inst_ea)
    if not f:
        return None

    limit_end = min(f.end_ea, inst_ea + max_sig_bytes)
    sig_tokens = []
    cursor = inst_ea
    first_len = None

    while cursor < f.end_ea and cursor < limit_end and len(sig_tokens) < max_sig_bytes:
        insn = idautils.DecodeInstruction(cursor)
        if not insn or insn.size <= 0:
            break
        raw = ida_bytes.get_bytes(cursor, insn.size)
        if not raw:
            break

        # Determine wildcard byte positions within this instruction
        wild = set()

        # Auto-wildcard volatile operand bytes (imm/near/far/mem/displ)
        for op in insn.ops:
            op_type = int(op.type)
            if op_type == int(idaapi.o_void):
                continue
            if op_type in (int(idaapi.o_imm), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_mem), int(idaapi.o_displ)):
                offb = int(getattr(op, 'offb', 0))
                if offb > 0 and offb < insn.size:
                    dsz = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))
                    if dsz <= 0:
                        dsz = insn.size - offb
                    end = min(insn.size, offb + dsz)
                    for i in range(offb, end):
                        wild.add(i)
                offo = int(getattr(op, 'offo', 0))
                if offo > 0 and offo < insn.size:
                    dsz2 = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))
                    if dsz2 <= 0:
                        dsz2 = insn.size - offo
                    end2 = min(insn.size, offo + dsz2)
                    for i in range(offo, end2):
                        wild.add(i)

        # Special handling for call/jump instructions
        b0 = raw[0]
        if b0 in (0xE8, 0xE9, 0xEB):  # CALL rel32, JMP rel32, JMP rel8
            for i in range(1, insn.size):
                wild.add(i)
        elif b0 == 0x0F and insn.size >= 2 and (raw[1] & 0xF0) == 0x80:  # Jcc rel32
            for i in range(2, insn.size):
                wild.add(i)
        elif 0x70 <= b0 <= 0x7F:  # Jcc rel8
            for i in range(1, insn.size):
                wild.add(i)

        # For the first instruction (GV-accessing), ensure disp bytes are wildcarded
        if cursor == inst_ea:
            first_len = insn.size
            for i in range(disp_off, min(insn.size, disp_off + 4)):
                wild.add(i)

        # Build tokens for this instruction
        for idx in range(insn.size):
            sig_tokens.append("??" if idx in wild else f"{raw[idx]:02X}")

        cursor += insn.size

    if not sig_tokens or first_len is None:
        return None

    return {
        "gv_inst_va": hex(inst_ea),
        "gv_inst_length": first_len,
        "gv_inst_disp": disp_off,
        "total_bytes": len(sig_tokens),
        "sig_full": " ".join(sig_tokens),
    }

# --- Discover candidate GV-accessing instructions ---
candidates = []
seen = set()

def _try_add(inst_ea):
    if inst_ea in seen:
        return
    seen.add(inst_ea)

    insn = idautils.DecodeInstruction(inst_ea)
    if not insn or insn.size <= 0:
        return
    raw = ida_bytes.get_bytes(inst_ea, insn.size)
    if not raw:
        return

    disp_off = _resolve_disp_off(inst_ea, insn, raw)
    if disp_off is None:
        return

    result = _collect_sig_stream(inst_ea, disp_off)
    if result is not None:
        candidates.append(result)

if target_inst is not None:
    _try_add(target_inst)
elif target_func is not None:
    f = idaapi.get_func(target_func)
    if f:
        ea = f.start_ea
        while ea < f.end_ea and len(candidates) < max_candidates:
            flags = ida_bytes.get_full_flags(ea)
            if ida_bytes.is_code(flags):
                _try_add(ea)
            next_ea = ida_bytes.next_head(ea, f.end_ea)
            if next_ea == idaapi.BADADDR or next_ea <= ea:
                break
            ea = next_ea
else:
    for ref in idautils.DataRefsTo(target_gv):
        if len(candidates) >= max_candidates:
            break
        flags = ida_bytes.get_full_flags(ref)
        if not ida_bytes.is_code(flags):
            continue
        _try_add(ref)

print(json.dumps(candidates))
"""
```

### 2. Validate Signature Uniqueness with Progressive Prefix

For each candidate from the JSON output, test with `find_bytes` to find the shortest unique prefix.

**Start with ~16 bytes prefix, extend if not unique:**

```
mcp__ida-pro-mcp__find_bytes patterns=["<first_N_tokens_from_sig_full>"] limit=2
```

Check the result:
- If `n == 1` and match address equals `gv_inst_va` → **SUCCESS**: signature is unique
- If `n > 1` → Extend the signature (add more tokens) and retry
- If `n == 0` → Something is wrong; try next candidate

**Recommended flow:**
1. Pick the first candidate from the output
2. Split its `sig_full` by spaces into token array
3. Try first 16 tokens → `find_bytes patterns=["<16_tokens>"] limit=2`
4. If 2+ matches, try 24 tokens, then 32, etc.
5. If 1 match at `gv_inst_va` → done, use this candidate
6. If cannot find unique prefix, move to the next candidate

### 3. Iterate if Needed

If no candidate produces a unique signature:
1. Increase `max_sig_bytes` and re-run Step 1
2. Consider specifying a different `target_func` to find more candidates
3. Re-validate until unique

### 4. Continue with Unfinished Tasks

If we are called by a task from a task list / parent SKILL, restore and continue with the unfinished tasks.

## Output Format

Provide the following information for runtime GV resolution:

### Required Output Fields

1. **gv_sig**: Space-separated hex bytes with `??` for wildcards
1. **gv_sig_va**: The virtual address that the signature matches
2. **gv_inst_offset**: Always `0` (signature starts at the GV-accessing instruction)
3. **gv_inst_length**: Total length of the GV-accessing instruction (from candidate metadata)
4. **gv_inst_disp**: Position of the 4-byte RIP-relative offset within the instruction (from candidate metadata)

### Example Output

```yaml
gv_sig: "48 8B 1D ?? ?? ?? ?? 48 85 DB 0F 84 ?? ?? ?? ?? BD FF FF 00 00"
gv_sig_va: 0x1804f3df3     # The virtual address that the signature matches
gv_inst_offset: 0          # GV instruction starts at signature start
gv_inst_length: 7          # 48 8B 1D XX XX XX XX = 7 bytes
gv_inst_disp:   3          # Displacement offset start at position 3 (after 48 8B 1D)
```

### Runtime Resolution Formula

At runtime, after pattern scan finds the signature at address `scan_result`:

```cpp
// C++ example
uint8_t* inst_addr = scan_result + inst_offset;
int32_t rip_offset = *(int32_t*)(inst_addr + inst_disp);
void* gv_address = inst_addr + inst_length + rip_offset;
```

```python
# Python example
import struct
inst_addr = scan_result + inst_offset
rip_offset = struct.unpack('<i', memory[inst_addr + inst_disp : inst_addr + inst_disp + 4])[0]
gv_address = inst_addr + inst_length + rip_offset
```
