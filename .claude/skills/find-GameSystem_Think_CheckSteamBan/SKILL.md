---
name: find-GameSystem_Think_CheckSteamBan
description: Find and identify the GameSystem_Think_CheckSteamBan function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the GameSystem_Think_CheckSteamBan function by searching for the known debug string "Kicking user %s (sv_kick_players_with_cooldown=%d)" and analyzing cross-references.
disable-model-invocation: true
---

# Find GameSystem_Think_CheckSteamBan

Locate `GameSystem_Think_CheckSteamBan` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

1. Search for the debug string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="Kicking user %s \(sv_kick_players_with_cooldown=%d\)"
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
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "GameSystem_Think_CheckSteamBan"}]}
   ```

5. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `GameSystem_Think_CheckSteamBan`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

## String References

The function contains a debug log call with format string:
- `Kicking user %s (sv_kick_players_with_cooldown=%d)`

## Function Characteristics

- **Type**: Regular function (not virtual)
- **Purpose**: Periodic think function that checks for Steam VAC/Game bans and kicks players with cooldowns based on server configuration
- **Behavior**:
  1. Iterates over connected players
  2. Checks Steam ban status for each player
  3. Kicks players matching the `sv_kick_players_with_cooldown` criteria
  4. Logs the kick with the format string containing the player name and cooldown value

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `GameSystem_Think_CheckSteamBan.windows.yaml`
- `libserver.so` / `libserver.so` → `GameSystem_Think_CheckSteamBan.linux.yaml`
