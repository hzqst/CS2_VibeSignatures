---
name: find-CBasePlayerController_ChangeTeam
description: Find and identify the CBasePlayerController_ChangeTeam function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll to locate the ChangeTeam function by searching for known debug string references and analyzing cross-references.
---

# Find CBasePlayerController_ChangeTeam

Locate `CBasePlayerController_ChangeTeam` in CS2 server.dll using IDA Pro MCP tools.

## Method

1. Search for the debug string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="ChangeTeam\(\) CTMDBG"
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
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CBasePlayerController_ChangeTeam"}]}
   ```

## Signature Pattern

The function contains a debug log call with format string:
```
"%s<%i><%s><%s>" ChangeTeam() CTMDBG , team %d, req team %d willSwitch %d, %.2f
```

## Function Characteristics

- **Parameters**: `(this, team_id)` where `this` is CCSPlayerController pointer, `team_id` is the target team
- **Key offsets**:
  - `this + 0x344`: Current team ID
  - `this + 0x810`: Team-related field
  - `this + 0x824`: Flag (set to 1 when changing to non-spectator)
  - `this + 0x827`: Flag (set to 1 when team is spectator)
  - `this + 0x828`: `willSwitch` field
  - `this + 0x82C`: Timestamp field

## Team IDs

- `0`: Unassigned
- `1`: Spectator
- `2`: Terrorist
- `3`: Counter-Terrorist
