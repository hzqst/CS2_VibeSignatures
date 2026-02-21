# _igamesystem_dispatch_common

## Overview
`ida_preprocessor_scripts/_igamesystem_dispatch_common.py` is the shared preprocess entry for IGameSystem dispatch-style skills. The current design no longer depends on scan/decompiler order. It now collects all dispatch calls first, then maps targets deterministically by `vfunc_index`/`vfunc_offset`.

## Key Design Update (2026-02)
### 1) Collect all dispatch entries (no early truncation)
- `_build_dispatch_py_eval(...)` no longer takes `target_count`.
- Windows path: scans `lea rdx, callback`, then extracts `call/jmp [reg+disp]` in callback bodies.
- Linux path: scans `mov esi/rsi, odd_imm` + subsequent `call`, using `vfunc_off = imm - 1`.
- Basic filtering added on both paths: only non-negative, 8-byte aligned offsets are accepted.

### 2) Strict total-count validation
- New argument: `expected_dispatch_count` (optional).
- Preprocess requires `len(entries) == expected_dispatch_count`; otherwise fail-fast.
- If omitted:
  - without `dispatch_rank`: defaults to `target_count`
  - with `dispatch_rank`: defaults to `max(dispatch_rank) + 1`

### 3) Stable mapping with `dispatch_rank`
- `target_specs` now supports:
  - `target_name` (required)
  - `rename_to` (optional)
  - `dispatch_rank` (optional)
- With `dispatch_rank`:
  - all entries are sorted by `(vfunc_index, vfunc_offset)` ascending
  - each target picks entry by rank
- Validation rules:
  - all specs must provide rank once rank mode is used
  - ranks must be non-negative and unique
  - `expected_dispatch_count > max(rank)`

### 4) `entry_start_index` is now legacy compatibility
- `entry_start_index` still works, but is deprecated.
- Internally converted to contiguous `dispatch_rank` (`start + i`) and
  `expected_dispatch_count = start + target_count`.
- Cannot be mixed with explicit `dispatch_rank` or explicit `expected_dispatch_count`.

## Public API Snapshot
`preprocess_igamesystem_dispatch_skill(...)` relevant parameters:
- `target_specs`
- `multi_order` (`scan` / `index`)
- `expected_dispatch_count=None`
- `entry_start_index=0` (legacy/deprecated)

## Behavior Notes
- Still fail-fast: returns `False` on validation/extraction mismatches.
- `multi_order == "index"` controls index-based ordering for multi-target scan mode.
- If `dispatch_rank` is used, stable index sorting is forced even when `multi_order="scan"`.
- Internal/callback renaming remains best-effort (non-fatal on rename failure).

## Updated Callers (Migrated)
### SpawnGroup series
- `find-IGameSystem_PreSpawnGroupLoad.py`
  - `dispatch_rank=0`
  - `EXPECTED_DISPATCH_COUNT=2`
- `find-IGameSystem_PostSpawnGroupLoad.py`
  - `dispatch_rank=1`
  - `EXPECTED_DISPATCH_COUNT=2`
- `find-IGameSystem_PostSpawnGroupUnload.py`
  - `dispatch_rank=1`
  - `EXPECTED_DISPATCH_COUNT=2`
- `find-IGameSystem_PreSpawnGroupUnload.py`
  - removed redundant `ENTRY_START_INDEX=0` pass-through (single-target default mapping)

### ClientPreEntityThink case
- `find-IGameSystem_ClientPreEntityThink.py`
  - observed 3 dispatch indices: `22 / 23 / 24`
  - `IGameSystem_ClientPreEntityThink` mapped with `dispatch_rank=0` (index 22)
  - `EXPECTED_DISPATCH_COUNT=3`

## Rationale
The old "scan/decompiler order + ENTRY_START_INDEX" approach was unstable under compiler/reordering changes. The new design uses vfunc-index-based deterministic mapping plus strict count assertions to reduce false matches.

## Files Involved
- `ida_preprocessor_scripts/_igamesystem_dispatch_common.py`
- `ida_preprocessor_scripts/find-IGameSystem_PreSpawnGroupLoad.py`
- `ida_preprocessor_scripts/find-IGameSystem_PostSpawnGroupLoad.py`
- `ida_preprocessor_scripts/find-IGameSystem_PostSpawnGroupUnload.py`
- `ida_preprocessor_scripts/find-IGameSystem_PreSpawnGroupUnload.py`
- `ida_preprocessor_scripts/find-IGameSystem_ClientPreEntityThink.py`
