---
name: find-CBasePlayerPawn_CommitSuicide
description: Find and identify the CBasePlayerPawn_CommitSuicide function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CommitSuicide function by analyzing the CBasePlayerPawn vtable and identifying unique function characteristics including specific pointer offsets (0x890, 0xBF8) and sequential function call patterns.
expected_output:
  - name: CBasePlayerPawn_CommitSuicide
    category: vfunc
    alias:
      - CBasePlayerPawn::CommitSuicide
    files:
      - CBasePlayerPawn_CommitSuicide.{platform}.yaml
---

# Find CBasePlayerPawn_CommitSuicide

Locate `CBasePlayerPawn_CommitSuicide` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Get CBasePlayerPawn vtable information:

   **ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CBasePlayerPawn`.

   Extract `vtable_va` and `vtable_entries` from the result.

2. Decompile the virtual function at IDA index 400:

   ```
   mcp__ida-pro-mcp__decompile addr="<vtable_entries[399]>"
   ```

   Note: IDA index 400 = array index 399 (IDA uses 1-based indexing)

3. Verify function characteristics to confirm this is CommitSuicide:

   The function should exhibit these unique patterns:

   - **Pointer arithmetic**: `lea r12, [rdi+890h]` - accessing `a1 + 274` (274 * 8 = 0x890)
   - **Sequential function calls** in fixed order:
     - Call to view initialization function (e.g., sub_166C040)
     - Virtual function call at vtable offset 0xBF8 (index 383)
     - Two consecutive helper function calls
   - **Bitwise operations**: Uses `| 0x200000` flag (bit 21)
   - **Conditional logic**: Checks non-zero values before calling virtual functions

   If characteristics match, proceed to rename.

4. Rename the function:

   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CBasePlayerPawn_CommitSuicide"}]}
   ```

5. Get vtable offset and index:

   **ALWAYS** Use SKILL `/get-vtable-index` with the function address.

   VTable class name: `CBasePlayerPawn`

6. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

7. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CBasePlayerPawn_CommitSuicide`
   - `func_addr`: The function address from step 2
   - `func_sig`: The validated signature from step 6

   VTable parameters (when this is a virtual function):
   - `vtable_name`: `CBasePlayerPawn`
   - `vfunc_offset`: The offset from step 5
   - `vfunc_index`: The index from step 5

## Function Characteristics

- **Parameters**: `(this)` where `this` is CBasePlayerPawn pointer
- **Purpose**: Handles player suicide/death state cleanup and processing
- **Key Operations**:
  - Sets up player state at offset 0x890 (2192 bytes)
  - Calls cleanup functions
  - Invokes virtual function for death handling
  - Sets death-related flags (bit 21 = 0x200000)
  - Finalizes the suicide process

## VTable Information

- **VTable Name**: `CBasePlayerPawn::\`vftable'`
- **VTable Mangled Name**: `??_7CBasePlayerPawn@@6B@` (Windows) / `_ZTV16CBasePlayerPawn` (Linux)
- **VTable Index**: 400 (IDA index) / 399 (array index) - This can change when game updates.
- **VTable Offset**: 0xC78 - This can change when game updates.

* Note that for `server.so`, the first 16 bytes of "vftable" are for RTTI. The real vftable = `_ZTV16CBasePlayerPawn` + `0x10`.

## Unique Identifiers

The function can be uniquely identified by:

1. **Offset 0x890** (`4C 8D A7 90 08 00 00`) - LEA r12, [rdi+890h]
   - This is `a1 + 274` in QWORD pointer arithmetic

2. **Vtable offset 0xBF8** (`FF 90 F8 0B 00 00`) - call qword ptr [rax+0BF8h]
   - Virtual function call at index 383
   - This corresponds to `(*a1 + 3064)` in bytes

3. **Sequential function call pattern**:
   - Call to view initialization
   - Virtual call at vtable[383]
   - Two helper function calls for offset calculations

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBasePlayerPawn_CommitSuicide.windows.yaml`
- `server.so` → `CBasePlayerPawn_CommitSuicide.linux.yaml`

```yaml
func_va: 0x1625080         # Virtual address of the function - This can change when game updates.
func_rva: 0x1625080        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xba            # Function size in bytes - This can change when game updates.
func_sig: 55 31 F6 48 89 E5 41 56 41 55 41 54 4C 8D A7 90 08 00 00 53 48 89 FB 4C 89 E7 E8 ?? ?? ?? ?? 48 8B 03 48 89 DF FF 90 F8 0B 00 00 4C 89 E7 49 89 C5 E8 ?? ?? ?? ?? 4C 89 E7 49 89 C6 E8 ?? ?? ?? ??
vtable_name: CBasePlayerPawn
vfunc_offset: 0xc78        # Offset from vtable start - This can change when game updates.
vfunc_index: 400           # IDA vtable index (array index 399) - This can change when game updates.
```
