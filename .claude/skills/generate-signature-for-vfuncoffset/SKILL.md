---
name: generate-signature-for-vfuncoffset
description: |
  Generate and validate unique byte signatures for instructions containing a virtual-function offset using IDA Pro MCP.
  Use this skill when you need a signature for an instruction like call qword ptr [rax+538h], where the vfunc offset (0x538) must be explicitly fixed in the first instruction bytes.
  Triggers: vfunc offset signature, signature for vfunc offset, virtual function offset signature, call [reg+offset] signature
---

# Generate Signature for VFunc Offset

Generate a unique hex byte signature that locates an instruction containing a specific vfunc offset (for example: `call qword ptr [rax+538h]`).

## Core Concept

For vfunc-offset signatures, we signature the **instruction containing the vfunc offset**, not the function body itself.

Hard requirements:
1. The target instruction must be fully fixed (no wildcard bytes at all).
2. The displacement bytes carrying `vfuncoffset` in the target instruction must be explicitly included (not wildcarded).
3. Instructions other than the target instruction may use wildcarding.
4. Signature length grows by complete instruction boundaries and stops at the shortest unique prefix.

Strategy:
- **Phase 1 (forward-only):** Try expanding only forward (after target instruction) within the function. This keeps `vfunc_sig_disp = 0` for the simplest case.
- **Phase 2 (backward expansion, wildcarded):** If Phase 1 fails, prepend wildcarded instructions before the target instruction (within the same function) and re-test. The `vfunc_sig_disp` field records the byte distance from signature start to the target instruction.
- **Phase 3 (backward expansion, fully-fixed):** If Phase 2 fails (wildcarding erased distinguishing bytes), retry with fully-fixed (no wildcard) preceding instructions.

## Prerequisites

- Target instruction address (the instruction that contains vfunc offset)
- Expected `vfuncoffset` value (e.g. `0x538`)
- IDA Pro MCP connection

## Method

### 1. Generate and Validate Signature (Single Step)

Use a single `py_eval` call that:
- Validates the input instruction contains the expected `vfuncoffset` displacement.
- Phase 1: collects instruction bytes from the target instruction forward, tests uniqueness.
- Phase 2 (if Phase 1 fails): prepends wildcarded instructions before the target instruction within the same function, re-tests uniqueness after each prepend.
- Phase 3 (if Phase 2 fails): retries backward expansion with fully-fixed (no wildcard) preceding instructions, for cases where wildcarding erased the distinguishing bytes.
- Enforces **no wildcard on the target instruction**.
- Applies programmatic wildcarding on all other instructions (Phase 1 & 2 only).
- Tracks instruction boundaries so prefixes always end on complete instructions.
- Progressively tests uniqueness via `bin_search3`.
- Outputs the shortest unique signature as `vfunc_sig` with `vfunc_sig_disp`.

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi, ida_bytes, idautils, ida_ua, ida_segment, json

def main():
    target_inst = <inst_addr>
    target_vfunc_offset = <vfunc_offset>   # e.g. 0x538 from "call qword ptr [rax+538h]"
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

    def find_vfunc_disp_matches(insn, raw, expected):
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

    disp_hits = find_vfunc_disp_matches(insn0, raw0, target_vfunc_offset)
    if not disp_hits:
        print(json.dumps({
            "inst_va": hex(target_inst),
            "inst_bytes": " ".join(f"{b:02X}" for b in raw0),
            "vfunc_offset": hex(target_vfunc_offset),
            "error": "target instruction does not contain the expected vfunc offset",
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

    # --- Helper: wildcard non-target instructions ---
    def wildcard_instruction(addr, insn_obj, raw_bytes):
        wild = set()
        for op in insn_obj.ops:
            ot = int(op.type)
            if ot == int(idaapi.o_void):
                continue
            if ot in (int(idaapi.o_imm), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_mem), int(idaapi.o_displ)):
                offb = int(getattr(op, "offb", 0))
                if offb > 0 and offb < insn_obj.size:
                    dsz = ida_ua.get_dtype_size(getattr(op, "dtype", getattr(op, "dtyp", 0)))
                    if dsz <= 0:
                        dsz = insn_obj.size - offb
                    for i in range(offb, min(insn_obj.size, offb + dsz)):
                        wild.add(i)

                offo = int(getattr(op, "offo", 0))
                if offo > 0 and offo < insn_obj.size:
                    dsz2 = ida_ua.get_dtype_size(getattr(op, "dtype", getattr(op, "dtyp", 0)))
                    if dsz2 <= 0:
                        dsz2 = insn_obj.size - offo
                    for i in range(offo, min(insn_obj.size, offo + dsz2)):
                        wild.add(i)

        # Branch/call rel targets are volatile.
        b0 = raw_bytes[0]
        if b0 in (0xE8, 0xE9, 0xEB):
            for i in range(1, insn_obj.size):
                wild.add(i)
        elif b0 == 0x0F and insn_obj.size >= 2 and (raw_bytes[1] & 0xF0) == 0x80:
            for i in range(2, insn_obj.size):
                wild.add(i)
        elif 0x70 <= b0 <= 0x7F:
            for i in range(1, insn_obj.size):
                wild.add(i)

        tokens = []
        for idx in range(insn_obj.size):
            tokens.append("??" if idx in wild else f"{raw_bytes[idx]:02X}")
        return tokens

    # --- Helper: test uniqueness of a token list, expecting match at expected_addr ---
    def test_unique(tokens, expected_addr):
        if all(t == "??" for t in tokens):
            return False
        pattern_str = " ".join("?" if t == "??" else t for t in tokens)
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

        return len(matches) == 1 and matches[0] == expected_addr

    # ====================================================================
    # Phase 1: Forward-only expansion (signature starts at target_inst)
    # ====================================================================
    limit_end = min(f.end_ea, target_inst + max_sig_bytes)
    fwd_tokens = []
    fwd_boundaries = []
    cursor = target_inst
    inst_count = 0
    target_inst_len = None

    while (
        cursor < f.end_ea
        and cursor < limit_end
        and len(fwd_tokens) < max_sig_bytes
        and inst_count < max_instructions
    ):
        insn = idautils.DecodeInstruction(cursor)
        if not insn or insn.size <= 0:
            break
        raw = ida_bytes.get_bytes(cursor, insn.size)
        if not raw:
            break

        if cursor == target_inst:
            # Target instruction: fully fixed, no wildcards.
            target_inst_len = insn.size
            for idx in range(insn.size):
                if len(fwd_tokens) < max_sig_bytes:
                    fwd_tokens.append(f"{raw[idx]:02X}")
        else:
            toks = wildcard_instruction(cursor, insn, raw)
            for t in toks:
                if len(fwd_tokens) < max_sig_bytes:
                    fwd_tokens.append(t)

        fwd_boundaries.append(len(fwd_tokens))
        cursor += insn.size
        inst_count += 1

    if target_inst_len is None:
        print(json.dumps({
            "inst_va": hex(target_inst),
            "error": "no signature bytes collected",
            "status": "failed"
        }))
        return

    min_boundary = max(min_sig_bytes, target_inst_len)

    # Try forward-only first
    phase1_sig = None
    phase1_boundary = 0
    for boundary in fwd_boundaries:
        if boundary < min_boundary:
            continue
        prefix = fwd_tokens[:boundary]
        if test_unique(prefix, target_inst):
            phase1_sig = " ".join(prefix)
            phase1_boundary = boundary
            break

    if phase1_sig:
        print(json.dumps({
            "vfunc_sig": phase1_sig,
            "sig_bytes": phase1_boundary,
            "vfunc_sig_va": hex(target_inst),
            "vfunc_sig_disp": 0,
            "vfunc_inst_length": target_inst_len,
            "vfunc_disp_offset": disp_off,
            "vfunc_disp_size": disp_size,
            "vfunc_offset": hex(target_vfunc_offset),
            "status": "success"
        }))
        return

    # ====================================================================
    # Phase 2: Backward expansion (prepend wildcarded instructions)
    # ====================================================================

    # Collect all instructions in the function from f.start_ea up to target_inst.
    pre_instructions = []   # list of (addr, insn, raw_bytes)
    cursor = f.start_ea
    while cursor < target_inst:
        insn = idautils.DecodeInstruction(cursor)
        if not insn or insn.size <= 0:
            break
        raw = ida_bytes.get_bytes(cursor, insn.size)
        if not raw:
            break
        pre_instructions.append((cursor, insn, raw))
        cursor += insn.size

    if not pre_instructions:
        # Nothing to prepend, truly failed.
        print(json.dumps({
            "vfunc_sig_va": hex(target_inst),
            "vfunc_offset": hex(target_vfunc_offset),
            "first_inst_bytes": " ".join(f"{b:02X}" for b in raw0),
            "total_fwd_tokens": len(fwd_tokens),
            "sig_full_fwd": " ".join(fwd_tokens),
            "error": "no unique signature found: forward exhausted, no preceding instructions available",
            "status": "failed"
        }))
        return

    # Build wildcarded tokens for each preceding instruction (in order).
    pre_token_groups = []   # list of token lists, in forward order
    for addr, insn, raw in pre_instructions:
        toks = wildcard_instruction(addr, insn, raw)
        pre_token_groups.append(toks)

    # Prepend one instruction at a time (from the nearest predecessor backward).
    prepend_tokens = []
    phase2_prepend_bytes = 0

    for i in range(len(pre_token_groups) - 1, -1, -1):
        group = pre_token_groups[i]
        prepend_tokens = group + prepend_tokens
        phase2_prepend_bytes += len(group)

        if phase2_prepend_bytes + len(fwd_tokens) > max_sig_bytes:
            break

        # Try with full forward extent first, then shrink forward if possible.
        for boundary in reversed(fwd_boundaries):
            candidate = prepend_tokens + fwd_tokens[:boundary]
            if len(candidate) < min_sig_bytes:
                continue
            sig_start_addr = pre_instructions[i][0]
            if test_unique(candidate, sig_start_addr):
                print(json.dumps({
                    "vfunc_sig": " ".join(candidate),
                    "sig_bytes": len(candidate),
                    "vfunc_sig_va": hex(sig_start_addr),
                    "vfunc_sig_disp": phase2_prepend_bytes,
                    "vfunc_inst_length": target_inst_len,
                    "vfunc_disp_offset": disp_off + phase2_prepend_bytes,
                    "vfunc_disp_size": disp_size,
                    "vfunc_offset": hex(target_vfunc_offset),
                    "status": "success"
                }))
                return

        # Also try prepend + target_inst only (minimal forward)
        candidate_min = prepend_tokens + fwd_tokens[:target_inst_len]
        if len(candidate_min) >= min_sig_bytes:
            sig_start_addr = pre_instructions[i][0]
            if test_unique(candidate_min, sig_start_addr):
                print(json.dumps({
                    "vfunc_sig": " ".join(candidate_min),
                    "sig_bytes": len(candidate_min),
                    "vfunc_sig_va": hex(sig_start_addr),
                    "vfunc_sig_disp": phase2_prepend_bytes,
                    "vfunc_inst_length": target_inst_len,
                    "vfunc_disp_offset": disp_off + phase2_prepend_bytes,
                    "vfunc_disp_size": disp_size,
                    "vfunc_offset": hex(target_vfunc_offset),
                    "status": "success"
                }))
                return

    # ====================================================================
    # Phase 3: Backward expansion with fully-fixed preceding instructions
    # ====================================================================
    # Phase 2 failed because wildcarding erased the distinguishing bytes.
    # Retry with fully-fixed (no wildcard) preceding instructions.

    pre_fixed_groups = []
    for addr, insn, raw in pre_instructions:
        toks = [f"{raw[idx]:02X}" for idx in range(insn.size)]
        pre_fixed_groups.append(toks)

    prepend_tokens = []
    phase3_prepend_bytes = 0

    for i in range(len(pre_fixed_groups) - 1, -1, -1):
        group = pre_fixed_groups[i]
        prepend_tokens = group + prepend_tokens
        phase3_prepend_bytes += len(group)

        if phase3_prepend_bytes + len(fwd_tokens) > max_sig_bytes:
            break

        for boundary in reversed(fwd_boundaries):
            candidate = prepend_tokens + fwd_tokens[:boundary]
            if len(candidate) < min_sig_bytes:
                continue
            sig_start_addr = pre_instructions[i][0]
            if test_unique(candidate, sig_start_addr):
                print(json.dumps({
                    "vfunc_sig": " ".join(candidate),
                    "sig_bytes": len(candidate),
                    "vfunc_sig_va": hex(sig_start_addr),
                    "vfunc_sig_disp": phase3_prepend_bytes,
                    "vfunc_inst_length": target_inst_len,
                    "vfunc_disp_offset": disp_off + phase3_prepend_bytes,
                    "vfunc_disp_size": disp_size,
                    "vfunc_offset": hex(target_vfunc_offset),
                    "status": "success"
                }))
                return

        candidate_min = prepend_tokens + fwd_tokens[:target_inst_len]
        if len(candidate_min) >= min_sig_bytes:
            sig_start_addr = pre_instructions[i][0]
            if test_unique(candidate_min, sig_start_addr):
                print(json.dumps({
                    "vfunc_sig": " ".join(candidate_min),
                    "sig_bytes": len(candidate_min),
                    "vfunc_sig_va": hex(sig_start_addr),
                    "vfunc_sig_disp": phase3_prepend_bytes,
                    "vfunc_inst_length": target_inst_len,
                    "vfunc_disp_offset": disp_off + phase3_prepend_bytes,
                    "vfunc_disp_size": disp_size,
                    "vfunc_offset": hex(target_vfunc_offset),
                    "status": "success"
                }))
                return

    # All attempts exhausted.
    print(json.dumps({
        "vfunc_sig_va": hex(target_inst),
        "vfunc_offset": hex(target_vfunc_offset),
        "first_inst_bytes": " ".join(f"{b:02X}" for b in raw0),
        "total_fwd_tokens": len(fwd_tokens),
        "total_pre_instructions": len(pre_instructions),
        "sig_full_fwd": " ".join(fwd_tokens),
        "error": "no unique signature found after all phases",
        "status": "failed"
    }))

main()
"""
```

**Result handling:**
- `status == "success"` -> Use `vfunc_sig` directly as final signature.
- `status == "failed"` -> See Step 2.

### 2. Iterate if Needed

If Step 1 returns `status: "failed"`:
1. Increase `max_sig_bytes` (e.g. from `96` to `192`) and re-run Step 1.
2. Increase `max_instructions` (e.g. from `64` to `128`) if function instructions are short.
3. If still not unique, use a different instruction that references the same vfunc offset and re-run.

### 3. Continue with Unfinished Tasks

If we are called by a task from a task list / parent SKILL, restore and continue with the unfinished tasks.

## Output Format

Required:
- `vfunc_sig`: Space-separated hex bytes with `??` for wildcards.

Recommended metadata:
- `vfunc_sig_va`: VA of signature start (may be before target instruction if backward expansion was used).
- `vfunc_sig_disp`: Byte displacement from signature start to the target instruction. `0` means signature starts at target instruction (forward-only). Non-zero means backward expansion was used.
- `vfunc_inst_length`: Length of the target instruction in bytes.
- `vfunc_disp_offset`: Byte position of the vfunc offset displacement within the **signature** (= `vfunc_sig_disp` + displacement position within target instruction).
- `vfunc_disp_size`: Displacement byte size.
- `vfunc_offset`: The expected vfunc offset used for validation.

### Example Output (Forward-only, vfunc_sig_disp = 0)

```yaml
vfunc_sig: "FF 90 38 05 00 00 48 8B ?? ?? ?? ?? 48 85 C0 74 ??"
vfunc_sig_va: 0x180123456
vfunc_sig_disp: 0
vfunc_inst_length: 6
vfunc_disp_offset: 2
vfunc_disp_size: 4
vfunc_offset: 0x538
```

### Example Output (Backward expansion, vfunc_sig_disp > 0)

When the target instruction is `call qword ptr [rax+538h]` and forward-only expansion cannot produce a unique signature, backward expansion prepends preceding instructions:

```yaml
vfunc_sig: "48 8B 01 FF 90 38 05 00 00 48 8B ?? ?? ?? ?? 48 85 C0"
vfunc_sig_va: 0x180123453
vfunc_sig_disp: 3
vfunc_inst_length: 6
vfunc_disp_offset: 5
vfunc_disp_size: 4
vfunc_offset: 0x538
```

In this example:
- Signature starts 3 bytes before the target instruction (`vfunc_sig_disp: 3`)
- The vfunc offset bytes `38 05 00 00` are at byte position 5 within the signature (`vfunc_disp_offset: 5` = `vfunc_sig_disp(3)` + displacement within target instruction `(2)`)
- Runtime: scan for `vfunc_sig`, then add `vfunc_sig_disp` to get the target instruction address
