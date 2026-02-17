---
name: generate-signature-for-structoffset
description: |
  Generate and validate unique byte signatures for instructions containing a struct member offset using IDA Pro MCP.
  Use this skill when you need a signature for an instruction like mov [rcx+1A8h], eax or cmp dword ptr [rdi+0B0h], 0, where the struct offset must be explicitly fixed in the first instruction bytes.
  Triggers: struct offset signature, signature for struct offset, structure member offset signature, mov [reg+offset] signature, struct field signature
---

# Generate Signature for Struct Offset

Generate a unique hex byte signature that locates an instruction containing a specific struct member offset (for example: `mov [rcx+1A8h], eax`, `cmp dword ptr [rdi+0B0h], 0`).

## Core Concept

For struct-offset signatures, we signature the **instruction containing the struct offset**, not the function body itself.

Hard requirements:
1. Signature must start at the target instruction address.
2. The first instruction must be fully fixed (no wildcard bytes at all).
3. The displacement bytes carrying `struct_offset` in the first instruction must be explicitly included (not wildcarded).
4. Only instructions after the first instruction may use wildcarding.
5. Signature length grows by complete instruction boundaries and stops at the shortest unique prefix.

## Prerequisites

- Target instruction address (the instruction that contains the struct offset)
- Expected `struct_offset` value (e.g. `0x1A8`)
- IDA Pro MCP connection

## Method

### 1. Generate and Validate Signature (Single Step)

Use a single `py_eval` call that:
- Validates the input instruction contains the expected `struct_offset` displacement.
- Collects instruction bytes from the target instruction forward.
- Enforces **no wildcard in the first instruction**.
- Applies programmatic wildcarding only on following instructions.
- Tracks instruction boundaries so prefixes always end on complete instructions.
- Progressively tests uniqueness via `bin_search3`.
- Outputs the shortest unique signature as `struct_sig`.

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi, ida_bytes, idautils, ida_ua, ida_segment, json

def main():
    target_inst = <inst_addr>
    target_struct_offset = <struct_offset>   # e.g. 0x1A8 from "mov [rcx+1A8h], eax"
    min_sig_bytes = 6
    max_sig_bytes = 96
    max_instructions = 64

    f = idaapi.get_func(target_inst)
    if not f:
        print(json.dumps({
            "inst_va": hex(target_inst),
            "error": "target instruction is not inside a known function",
            "status": "failed"
        }))
        return

    insn0 = idautils.DecodeInstruction(target_inst)
    if not insn0 or insn0.size <= 0:
        print(json.dumps({
            "inst_va": hex(target_inst),
            "error": "failed to decode target instruction",
            "status": "failed"
        }))
        return

    raw0 = ida_bytes.get_bytes(target_inst, insn0.size)
    if not raw0:
        print(json.dumps({
            "inst_va": hex(target_inst),
            "error": "failed to read target instruction bytes",
            "status": "failed"
        }))
        return

    def find_struct_disp_matches(insn, raw, expected):
        hits = []
        for op in insn.ops:
            ot = int(op.type)
            if ot == int(idaapi.o_void):
                continue
            if ot not in (int(idaapi.o_displ), int(idaapi.o_mem), int(idaapi.o_imm)):
                continue

            for attr in ("offb", "offo"):
                off = int(getattr(op, attr, 0))
                if off <= 0 or off >= insn.size:
                    continue

                sizes = []
                dsz = ida_ua.get_dtype_size(getattr(op, "dtype", getattr(op, "dtyp", 0)))
                if dsz > 0:
                    sizes.append(dsz)
                for s in (1, 2, 4, 8):
                    if s not in sizes:
                        sizes.append(s)

                for sz in sizes:
                    if off + sz > insn.size:
                        continue
                    unsigned_val = int.from_bytes(raw[off:off + sz], "little", signed=False)
                    signed_val = int.from_bytes(raw[off:off + sz], "little", signed=True)
                    expected_mod = expected & ((1 << (8 * sz)) - 1)
                    if unsigned_val == expected_mod or signed_val == expected:
                        hits.append((off, sz, unsigned_val, signed_val))

        uniq = []
        seen = set()
        for h in hits:
            key = (h[0], h[1])
            if key not in seen:
                seen.add(key)
                uniq.append(h)
        return uniq

    disp_hits = find_struct_disp_matches(insn0, raw0, target_struct_offset)
    if not disp_hits:
        print(json.dumps({
            "inst_va": hex(target_inst),
            "inst_bytes": " ".join(f"{b:02X}" for b in raw0),
            "struct_offset": hex(target_struct_offset),
            "error": "target instruction does not contain the expected struct offset",
            "status": "failed"
        }))
        return

    # Prefer the largest matching displacement size so we lock the full offset bytes.
    disp_hits.sort(key=lambda x: (x[1], -x[0]), reverse=True)
    disp_off, disp_size, _, _ = disp_hits[0]

    seg = ida_segment.get_segm_by_name(".text")
    if seg:
        search_start, search_end = seg.start_ea, seg.end_ea
    else:
        search_start, search_end = idaapi.cvar.inf.min_ea, idaapi.cvar.inf.max_ea

    limit_end = min(f.end_ea, target_inst + max_sig_bytes)
    sig_tokens = []
    inst_boundaries = []
    cursor = target_inst
    inst_count = 0
    first_len = None

    while (
        cursor < f.end_ea
        and cursor < limit_end
        and len(sig_tokens) < max_sig_bytes
        and inst_count < max_instructions
    ):
        insn = idautils.DecodeInstruction(cursor)
        if not insn or insn.size <= 0:
            break
        raw = ida_bytes.get_bytes(cursor, insn.size)
        if not raw:
            break

        wild = set()

        if cursor == target_inst:
            # Hard rule: first instruction must be fully fixed, including struct offset bytes.
            first_len = insn.size
        else:
            # Auto-wildcard volatile operand bytes after the first instruction.
            for op in insn.ops:
                ot = int(op.type)
                if ot == int(idaapi.o_void):
                    continue
                if ot in (int(idaapi.o_imm), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_mem), int(idaapi.o_displ)):
                    offb = int(getattr(op, "offb", 0))
                    if offb > 0 and offb < insn.size:
                        dsz = ida_ua.get_dtype_size(getattr(op, "dtype", getattr(op, "dtyp", 0)))
                        if dsz <= 0:
                            dsz = insn.size - offb
                        for i in range(offb, min(insn.size, offb + dsz)):
                            wild.add(i)

                    offo = int(getattr(op, "offo", 0))
                    if offo > 0 and offo < insn.size:
                        dsz2 = ida_ua.get_dtype_size(getattr(op, "dtype", getattr(op, "dtyp", 0)))
                        if dsz2 <= 0:
                            dsz2 = insn.size - offo
                        for i in range(offo, min(insn.size, offo + dsz2)):
                            wild.add(i)

            # Branch/call rel targets are volatile.
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
            if len(sig_tokens) >= max_sig_bytes:
                break
            sig_tokens.append("??" if idx in wild else f"{raw[idx]:02X}")

        inst_boundaries.append(len(sig_tokens))
        cursor += insn.size
        inst_count += 1

    if not sig_tokens or first_len is None:
        print(json.dumps({
            "inst_va": hex(target_inst),
            "error": "no signature bytes collected",
            "status": "failed"
        }))
        return

    min_boundary = max(min_sig_bytes, first_len)
    best_sig = None
    best_boundary = 0

    for boundary in inst_boundaries:
        if boundary < min_boundary:
            continue

        prefix_tokens = sig_tokens[:boundary]
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

        if len(matches) == 1 and matches[0] == target_inst:
            best_sig = " ".join(prefix_tokens)
            best_boundary = boundary
            break

    if best_sig:
        print(json.dumps({
            "struct_sig": best_sig,
            "sig_bytes": best_boundary,
            "struct_sig_va": hex(target_inst),
            "struct_inst_offset": 0,
            "struct_inst_length": first_len,
            "struct_disp_offset": disp_off,
            "struct_disp_size": disp_size,
            "struct_offset": hex(target_struct_offset),
            "status": "success"
        }))
    else:
        print(json.dumps({
            "struct_sig_va": hex(target_inst),
            "struct_offset": hex(target_struct_offset),
            "first_inst_bytes": " ".join(f"{b:02X}" for b in raw0),
            "total_tokens": len(sig_tokens),
            "sig_full": " ".join(sig_tokens),
            "error": "no unique prefix found within collected bytes",
            "status": "failed"
        }))

main()
"""
```

**Result handling:**
- `status == "success"` -> Use `struct_sig` directly as final signature.
- `status == "failed"` -> See Step 2.

### 2. Iterate if Needed

If Step 1 returns `status: "failed"`:
1. Increase `max_sig_bytes` (e.g. from `96` to `192`) and re-run Step 1.
2. Increase `max_instructions` (e.g. from `64` to `128`) if function instructions are short.
3. If still not unique, use a different instruction that references the same struct offset and re-run.

Keep the hard rule unchanged: first instruction remains fully fixed and must include explicit offset bytes.

### 3. Continue with Unfinished Tasks

If we are called by a task from a task list / parent SKILL, restore and continue with the unfinished tasks.

## Output Format

Required:
- `struct_sig`: Space-separated hex bytes with `??` for wildcards.

Recommended metadata:
- `struct_sig_va`: VA of matched instruction.
- `struct_inst_offset`: Always `0` (signature starts at target instruction).
- `struct_inst_length`: Length of the first instruction.
- `struct_disp_offset`: Displacement position inside first instruction.
- `struct_disp_size`: Displacement byte size.
- `struct_offset`: The expected struct offset used for validation.

### Example Output

```yaml
struct_sig: "C7 81 A8 01 00 00 01 00 00 00 48 8B ?? ?? ?? ?? 48 85 C0 74 ??"
struct_sig_va: 0x180123456
struct_inst_offset: 0
struct_inst_length: 10
struct_disp_offset: 2
struct_disp_size: 4
struct_offset: 0x1A8
```
