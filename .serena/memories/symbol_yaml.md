# symbol_yaml

## Overview
`{symbol}.{platform}.yaml` files under `bin/<gamever>/<module>/` store per-symbol binary metadata for function signatures, virtual-table data, global-variable signatures, patch metadata, and struct-member offsets.

## Scope
- Naming pattern: `{symbol}.{platform}.yaml`
- Platform suffix observed: `windows`, `linux`
- Files analyzed: 922

## Observed YAML Shapes
- Function signature: `func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`
- Virtual function (resolved): function fields + `vtable_name`, `vfunc_offset`, `vfunc_index`
- Virtual function (fallback-signature style): may include `vfunc_sig` (and in one file, `vfunc_inst_offset`)
- VTable dump: `vtable_class`, `vtable_va`, `vtable_rva`, `vtable_size`, `vtable_numvfunc`, `vtable_entries` (optional `vtable_symbol`)
- Global variable signature: `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`
- Patch: `patch_name`, `patch_sig`, `patch_bytes`
- Struct member offset (new format): `struct_name`, `member_name`, `offset`, optional `size`, `offset_sig`
- Legacy struct-member files (old format): top-level hex key only (example: `'0x68': HitGroupInfo 8`)

## Field Reference (Purpose of Each Field)
- `func_name`: Logical symbol/function name used by config and downstream gamedata mapping.
- `func_va`: Absolute virtual address of function start in the current binary.
- `func_rva`: Relative virtual address (`func_va - image_base`).
- `func_size`: Function size in bytes.
- `func_sig`: Byte-pattern signature (with `??` wildcards) used to relocate a function uniquely.

- `vtable_name`: Class/vtable name that owns the virtual function slot.
- `vfunc_offset`: Byte offset of the vfunc slot inside the vtable (normally `vfunc_index * 8` on 64-bit).
- `vfunc_index`: Zero-based virtual function slot index in the vtable.
- `vfunc_sig`: Alternate signature anchor used for virtual-function relocation/fallback when `func_sig` is unavailable or unstable.
- `vfunc_inst_offset`: Optional displacement from `vfunc_sig` match start to the target call/site instruction (observed in one Linux file; special-case metadata).

- `vtable_class`: Class name whose vtable is dumped.
- `vtable_symbol`: Platform/ABI-specific vtable symbol name (e.g., mangled/decorated symbol); optional in some files.
- `vtable_va`: Absolute virtual address of the vtable.
- `vtable_rva`: Relative virtual address of the vtable.
- `vtable_size`: Vtable byte size.
- `vtable_numvfunc`: Number of virtual-function slots.
- `vtable_entries`: Mapping `{slot_index -> function_va_hex}` for vtable slots.

- `gv_name`: Logical global-variable symbol name.
- `gv_va`: Absolute virtual address of the global variable.
- `gv_rva`: Relative virtual address (`gv_va - image_base`).
- `gv_sig`: Signature that uniquely matches around a GV-access instruction.
- `gv_sig_va`: Address where `gv_sig` starts (signature match location).
- `gv_inst_offset`: Byte offset from `gv_sig` start to the instruction that contains the RIP-relative displacement to the GV.
- `gv_inst_length`: Length (bytes) of that instruction.
- `gv_inst_disp`: Byte offset inside that instruction where the displacement begins.

- `patch_name`: Logical patch identifier.
- `patch_sig`: Signature used to locate the patch site.
- `patch_bytes`: Replacement bytes to write at the located patch site.

- `struct_name`: Struct/class name containing the member.
- `member_name`: Struct member name.
- `offset`: Member offset from struct base.
- `size`: Member size in bytes (optional but commonly present in struct-member YAML).
- `offset_sig`: Signature near the target instruction used to recover/revalidate the member offset across versions.

## Legacy Flat-Offset Keys
- Keys like `'0x50'`, `'0x58'`, `'0x68'`, `'0x240'`, `'0x278'`, `'0x3A0'`, `'0x3B0'`, `'0x530'` appear as top-level keys only in old files (mainly `14132`).
- Meaning: key is the member offset; value is a compact string `"<member_name> <size>"`.
- This is a legacy representation of struct-member metadata and should be treated as backward-compatibility data.

## Where Semantics Come From (Code Sources)
- Writers and preprocessors: `ida_analyze_util.py`
  - `write_func_yaml`, `write_vtable_yaml`, `write_gv_yaml`, `write_patch_yaml`, `write_struct_offset_yaml`
  - `preprocess_func_sig_via_mcp`, `preprocess_gen_func_sig_via_mcp`, `preprocess_gen_gv_sig_via_mcp`, `preprocess_gv_sig_via_mcp`, `preprocess_patch_via_mcp`, `preprocess_struct_offset_sig_via_mcp`, `preprocess_index_based_vfunc_via_mcp`
- Loader compatibility logic: `update_gamedata.py` (`parse_struct_yaml`, `load_all_yaml_data`)
- Downstream consumers: `dist/*/gamedata.py` (notably consumes `func_sig`, `vfunc_index`, `struct_member_offset`, `patch_bytes`).

## Notes
- `offset_sig_disp` exists in writer/preprocess schema but was not observed in current `bin/` files.
- `vtable_symbol` is optional in practice (present in older subsets, absent in some newer vtable files).


## func_sig: Generation Principle and Usage

### Generation Principle
- Canonical auto-generation is implemented by `preprocess_gen_func_sig_via_mcp` in `ida_analyze_util.py`.
- Input is a known function start address (`func_va`). The algorithm reads bytes from the function head instruction-by-instruction.
- It wildcards volatile bytes (`??`), including immediates/displacements and relative branch/call offsets.
- Candidate signatures grow only at instruction boundaries.
- For each candidate, `find_bytes(limit=2)` is used to enforce uniqueness.
- A valid candidate must match exactly one location, and that location must be the same function head address.
- The shortest valid candidate is selected as `func_sig`.

### Usage Method
- In version-to-version preprocessing (`preprocess_func_sig_via_mcp`), `func_sig` is the primary relocation anchor.
- Workflow:
  1. Run `find_bytes` with old `func_sig`.
  2. Require exactly one match.
  3. Query IDA function info at the match address (`func_va`, `func_size`).
  4. Recompute `func_rva` and write new YAML.
- Important behavior: if old YAML already has `func_sig`, preprocessing takes this path first and does not auto-fallback to `vfunc_sig` on failure.
- Downstream gamedata modules mainly consume `func_sig` (converted to target pattern formats), so `func_sig` is the main runtime-facing signature field.

## vfunc_sig: Generation Principle and Usage

### Generation Principle
- In this repository, `vfunc_sig` is typically produced by the skill `/generate-signature-for-vfuncoffset` (see `.claude/skills/generate-signature-for-vfuncoffset/SKILL.md`).
- Target anchor is a virtual-call instruction that encodes the vtable slot displacement (e.g., call/jmp through `[reg+imm]`).
- Generation is forward-expanding from that anchor instruction; the skill documents `vfunc_sig_disp` as `0` in its default strategy (signature starts at the target instruction).
- As with `func_sig`, candidates are validated by uniqueness (`find_bytes`) and robustness, then the shortest unique pattern is kept.
- The displacement bytes tied to the virtual slot are intentionally preserved/represented so the signature remains slot-specific.

### Usage Method
- `vfunc_sig` is mainly a preprocessing fallback anchor, not the primary downstream gamedata field.
- In `preprocess_func_sig_via_mcp`, it is used when old YAML has no `func_sig`:
  1. Require `vfunc_sig` + `vtable_name` + (`vfunc_index` or `vfunc_offset`).
  2. Unique-match `vfunc_sig` in new binary.
  3. Load/generate target `vtable` YAML and resolve function VA from `vtable_entries[vfunc_index]`.
  4. Query function info and emit function YAML with vfunc metadata.
- This path is especially useful when function-head signatures are too short/unstable but vtable slot semantics are stable.
- Current dist gamedata updaters primarily consume `vfunc_index` (offset metadata), while `vfunc_sig` is used by the analysis/preprocess pipeline for cross-version relocation.

## Practical Selection Guidance
- Prefer `func_sig` when a stable, unique function-head signature can be generated.
- Prefer `vfunc_sig` fallback for virtual methods where head bytes are weak but the vtable slot identity is reliable.
- Keep both uniqueness and target-address correctness checks mandatory; do not accept multi-hit signatures.
