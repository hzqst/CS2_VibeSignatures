---
name: generate-signature-for-function
description: |
  Generate and validate unique byte signatures for functions using IDA Pro MCP. Use this skill when you need to create a pattern-scanning signature for a function that can reliably locate it across binary updates.
  Triggers: generate signature, byte signature, pattern signature, function signature, unique signature, sig for function
---

# Generate Signature for Function

Generate a unique hex byte signature for a function using fully programmatic wildcard detection — no manual byte analysis required.

## Prerequisites

- Function address (from decompilation, xrefs, or rename)
- IDA Pro MCP connection

## Method

### 1. Collect Instruction Data with Auto-Wildcarding

Use a single `py_eval` call to decode instructions, programmatically determine wildcard positions based on operand types and branch instructions, and output the full signature token string.

**Note**: The input address may be in the middle of a function. The script automatically resolves it to the actual function start.

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi, ida_bytes, idautils, ida_ua, json

input_addr = <func_addr>
max_sig_bytes = 96
max_instructions = 64

# Resolve to actual function start (input may be in the middle of a function)
func = idaapi.get_func(input_addr)
if not func:
    print(json.dumps({"error": f"{hex(input_addr)} is not inside a known function"}))
    raise SystemExit

func_addr = func.start_ea
if func_addr != input_addr:
    print(f"NOTE: Resolved {hex(input_addr)} -> function start at {hex(func_addr)}")

limit_end = min(func.end_ea, func_addr + max_sig_bytes)
sig_tokens = []
cursor = func_addr
inst_count = 0

while cursor < func.end_ea and cursor < limit_end and inst_count < max_instructions:
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
            offb = int(op.offb)
            if offb > 0 and offb < insn.size:
                dsz = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))
                if dsz <= 0:
                    dsz = insn.size - offb
                end = min(insn.size, offb + dsz)
                for i in range(offb, end):
                    wild.add(i)
            offo = int(op.offo)
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

    # Build tokens for this instruction
    for idx in range(insn.size):
        sig_tokens.append("??" if idx in wild else f"{raw[idx]:02X}")

    cursor += insn.size
    inst_count += 1

sig_full = " ".join(sig_tokens)
print(json.dumps({
    "func_va": hex(func_addr),
    "func_size": hex(func.end_ea - func_addr),
    "total_bytes": len(sig_tokens),
    "sig_full": sig_full
}))
"""
```

### 2. Validate Signature Uniqueness with Progressive Prefix

From the `sig_full` string in the JSON output, test with `find_bytes` to find the shortest unique prefix.

**Start with ~16 bytes prefix, extend if not unique:**

```
mcp__ida-pro-mcp__find_bytes patterns=["<first_N_tokens_from_sig_full>"] limit=2
```

Check the result:
- If `n == 1` and match address equals `func_addr` → **SUCCESS**: signature is unique
- If `n > 1` → Extend the signature (add more tokens) and retry
- If `n == 0` → Something is wrong; verify the tokens against func_addr

**Recommended flow:**
1. Split `sig_full` by spaces into token array
2. Try first 16 tokens joined by spaces → `find_bytes patterns=["<16_tokens>"] limit=2`
3. If 2+ matches, try first 24 tokens, then 32, etc.
4. If 1 match at target address → done, use this as the final signature

### 3. Iterate if Needed

If the signature is not unique even with all available tokens:
1. Increase `max_sig_bytes` and re-run Step 1 to collect more bytes
2. Consider including bytes beyond the function boundary
3. Re-validate until unique

### 4. Continue with Unfinished Tasks

If we are called by a task from a task list / parent SKILL, restore and continue with the unfinished tasks.

## Output Format

Signature format: space-separated hex bytes with `??` for wildcards.

Example: `48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F9 E8 ?? ?? ?? ??`
