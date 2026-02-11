---
name: generate-signature-for-function
description: |
  Generate and validate unique byte signatures for functions using IDA Pro MCP. Use this skill when you need to create a pattern-scanning signature for a function that can reliably locate it across binary updates.
  Triggers: generate signature, byte signature, pattern signature, function signature, unique signature, sig for function
---

# Generate Signature for Function

Generate a unique hex byte signature for a function using fully programmatic wildcard detection and validation — no manual byte analysis required.

## Prerequisites

- Function address (from decompilation, xrefs, or rename)
- IDA Pro MCP connection

## Method

### 1. Generate and Validate Signature (Single Step)

Use a single `py_eval` call that:
- Resolves the input address to the actual function start
- Decodes instructions and programmatically determines wildcard positions
- Progressively tests increasing prefix lengths via `bin_search3`
- Outputs the shortest unique signature directly

**Note**: The input address may be in the middle of a function. The script automatically resolves it to the actual function start.

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi, ida_bytes, idautils, ida_ua, ida_segment, json

input_addr = <func_addr>
min_sig_bytes = 6
max_sig_bytes = 96
max_instructions = 64

# --- Resolve to actual function start ---
func = idaapi.get_func(input_addr)
if not func:
    print(json.dumps({"error": f"{hex(input_addr)} is not inside a known function", "status": "failed"}))
    raise SystemExit

func_addr = func.start_ea
if func_addr != input_addr:
    print(f"NOTE: Resolved {hex(input_addr)} -> function start at {hex(func_addr)}")

# --- Collect instruction bytes with auto-wildcarding ---
limit_end = min(func.end_ea, func_addr + max_sig_bytes)
sig_tokens = []
cursor = func_addr

while cursor < func.end_ea and cursor < limit_end and len(sig_tokens) < max_sig_bytes:
    insn = idautils.DecodeInstruction(cursor)
    if not insn or insn.size <= 0:
        break
    raw = ida_bytes.get_bytes(cursor, insn.size)
    if not raw:
        break

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
    if b0 in (0xE8, 0xE9, 0xEB):
        for i in range(1, insn.size):
            wild.add(i)
    elif b0 == 0x0F and insn.size >= 2 and (raw[1] & 0xF0) == 0x80:
        for i in range(2, insn.size):
            wild.add(i)
    elif 0x70 <= b0 <= 0x7F:
        for i in range(1, insn.size):
            wild.add(i)

    for idx in range(insn.size):
        sig_tokens.append("??" if idx in wild else f"{raw[idx]:02X}")

    cursor += insn.size

if not sig_tokens:
    print(json.dumps({"error": f"no instruction bytes at {hex(func_addr)}", "status": "failed"}))
    raise SystemExit

# --- Search bounds ---
seg = ida_segment.get_segm_by_name(".text")
if seg:
    search_start, search_end = seg.start_ea, seg.end_ea
else:
    search_start, search_end = idaapi.cvar.inf.min_ea, idaapi.cvar.inf.max_ea

# --- Progressive prefix search for shortest unique signature ---
best_sig = None
start_len = min(min_sig_bytes, len(sig_tokens))

for prefix_len in range(start_len, len(sig_tokens) + 1):
    prefix_tokens = sig_tokens[:prefix_len]
    if all(t == "??" for t in prefix_tokens):
        continue

    pattern_str = " ".join("?" if t == "??" else t for t in prefix_tokens)
    pat = ida_bytes.compiled_binpat_vec_t()
    ida_bytes.parse_binpat_str(pat, search_start, pattern_str, 16)
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK

    matches = []
    res = ida_bytes.bin_search3(search_start, search_end, pat, flags)
    ea = res[0] if isinstance(res, tuple) else res
    while ea != idaapi.BADADDR and len(matches) < 2:
        matches.append(ea)
        res = ida_bytes.bin_search3(ea + 1, search_end, pat, flags)
        ea = res[0] if isinstance(res, tuple) else res

    if len(matches) == 1 and matches[0] == func_addr:
        best_sig = " ".join(prefix_tokens)
        break

if best_sig:
    print(json.dumps({
        "func_va": hex(func_addr),
        "func_rva": hex(func_addr - idaapi.get_imagebase()),
        "func_size": hex(func.end_ea - func_addr),
        "func_sig": best_sig,
        "sig_bytes": len(best_sig.split()),
        "status": "success"
    }))
else:
    print(json.dumps({
        "func_va": hex(func_addr),
        "func_size": hex(func.end_ea - func_addr),
        "total_tokens": len(sig_tokens),
        "sig_full": " ".join(sig_tokens),
        "error": "no unique prefix found within collected bytes",
        "status": "failed"
    }))
"""
```

**Result handling:**
- `status == "success"` → Use `func_sig` directly as the final signature
- `status == "failed"` → See Step 2

### 2. Iterate if Needed

If Step 1 returns `status: "failed"`:
1. Increase `max_sig_bytes` (e.g., to 192) and re-run Step 1
2. Consider including bytes beyond the function boundary
3. Re-run until unique

### 3. Continue with Unfinished Tasks

If we are called by a task from a task list / parent SKILL, restore and continue with the unfinished tasks.

## Output Format

Signature format: space-separated hex bytes with `??` for wildcards.

Example: `48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F9 E8 ?? ?? ?? ??`
