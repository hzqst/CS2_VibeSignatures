---
name: find-CBasePlayerController_HandleCommand_JoinTeam
description: Find and identify the CBasePlayerController_HandleCommand_JoinTeam function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the HandleCommand_JoinTeam function by searching for known debug string references and analyzing cross-references.
---

# Find CBasePlayerController_HandleCommand_JoinTeam

Locate `CBasePlayerController_HandleCommand_JoinTeam` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the debug string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="HandleCommand_JoinTeam\( %d \) - invalid"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CBasePlayerController_HandleCommand_JoinTeam"}]}
   ```

5. Find VTable and Calculate Offset:

  **ALWAYS** Use SKILL `/get-vftable-index` to get vtable offset and index for the function.

   VTable class name to search for:
   - Windows: `??_7CBasePlayerController@@6B@`
   - Linux: `_ZTV21CBasePlayerController`

   Note: For Linux `server.so`, the first 16 bytes of vtable are for RTTI metadata. The real vtable starts at `_ZTV21CBasePlayerController + 0x10`.

6. Generate and validate unique signature:

  **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

7. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CBasePlayerController_HandleCommand_JoinTeam`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 6

   VTable parameters (when this is a virtual function):
   - `vtable_name`: `CBasePlayerController`
   - `vfunc_offset`: The offset from step 5
   - `vfunc_index`: The index from step 5

## Signature Pattern

The function contains a debug warning call with format string:
```
HandleCommand_JoinTeam( %d ) - invalid team index.
```

## Function Characteristics

- **Prototype**: `bool CBasePlayerController::HandleCommand_JoinTeam(CBasePlayerController *pPlayerController, int teamIndex, bool bQueue)`
- **Parameters**:
  - `this`: CBasePlayerController pointer
  - `teamIndex`: The target team index
  - `bQueue`: Whether to queue the team change
- **Return**: bool indicating success/failure

## Team IDs

- `0`: Unassigned
- `1`: Spectator
- `2`: Terrorist
- `3`: Counter-Terrorist

## VTable Information

- **VTable Name**: `CBasePlayerController::\`vftable'`
- **VTable Mangled Name**: `??_7CBasePlayerController@@6B@` (Windows) or `_ZTV21CBasePlayerController` (Linux)
- **VTable Index**: TBD - This can change when game updates.
- **VTable Offset**: TBD - This can change when game updates.

* Note that for `server.so`, The first 16 bytes of "vftable" are for RTTI. the real vftable = `_ZTV21CBasePlayerController` + `0x10`.

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBasePlayerController_HandleCommand_JoinTeam.windows.yaml`
- `server.so` → `CBasePlayerController_HandleCommand_JoinTeam.linux.yaml`

```yaml
func_va: 0x180XXXXXX      # Virtual address of the function - This can change when game updates.
func_rva: 0xXXXXXX        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xXXX          # Function size in bytes  - This can change when game updates.
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - This can change when game updates.
vtable_name: CBasePlayerController
vfunc_offset: 0xXXX       # Offset from vtable start - This can change when game updates.
vfunc_index: XX           # vtable[XX] - This can change when game updates.
```
