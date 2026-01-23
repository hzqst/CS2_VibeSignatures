---
name: find-CBasePlayerController_SetPlayerName
description: Find and identify the CBasePlayerController_SetPlayerName function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll to locate the SetPlayerName function by searching for known string references and analyzing cross-references.
---

# Find CBasePlayerController_SetPlayerName

Locate `CBasePlayerController_SetPlayerName` in CS2 server.dll using IDA Pro MCP tools.

## Method

1. Search for strings `fov_desired` and `newname`:
   ```
   mcp__ida-pro-mcp__find_regex pattern="fov_desired"
   mcp__ida-pro-mcp__find_regex pattern="newname"
   ```

2. Get cross-references to both strings:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs=["<fov_desired_addr>", "<newname_addr>"]
   ```

3. Find the function that references **both** strings - this is the player info sync function.

4. Decompile that function and look for the call to `CBasePlayerController_SetPlayerName`:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

5. In the decompiled output, find the pattern:
   ```c
   CBasePlayerController_SetPlayerName(a2, v6);  // after name comparison and event firing
   ```

6. Rename if needed:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<target_addr>", "name": "CBasePlayerController_SetPlayerName"}]}
   ```

## Signature Pattern

The function is called after:
- Creating `CMsgPlayerInfo` message
- Firing `player_changename` event with `userid`, `oldname`, `newname` fields
- Comparing old and new player names

The surrounding function also handles `fov_desired` cvar (clamps FOV between 1-135).
