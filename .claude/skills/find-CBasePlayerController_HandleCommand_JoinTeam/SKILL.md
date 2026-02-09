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

5. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CBasePlayerController_HandleCommand_JoinTeam`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 6

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

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBasePlayerController_HandleCommand_JoinTeam.windows.yaml`
- `server.so` → `CBasePlayerController_HandleCommand_JoinTeam.linux.yaml`

```yaml
func_va: 0x180XXXXXX      # Virtual address of the function - This can change when game updates.
func_rva: 0xXXXXXX        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xXXX          # Function size in bytes  - This can change when game updates.
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - This can change when game updates.
```
