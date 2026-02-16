---
name: find-CBasePlayerController_ProcessUsercmds
description: Find and identify the CBasePlayerController_ProcessUsercmds function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the ProcessUsercmds function by searching for the known usercmd debug format string and analyzing cross-references.
---

# Find CBasePlayerController_ProcessUsercmds

Locate `CBasePlayerController_ProcessUsercmds` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the debug format string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="Recv usercmd %d"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. There should be exactly one referencing function. Decompile it:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Confirm the function matches the expected pattern (see below), then rename it:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CBasePlayerController_ProcessUsercmds"}]}
   ```

5. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CBasePlayerController_ProcessUsercmds`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

   Note: This is NOT a virtual function, so no vtable parameters are needed.

## Signature Pattern

The function contains a debug logging call with the format string:
```
%sRecv usercmd %d.  Margin:%5.1fms net +%2d queue =%5.1f total
```

This string is unique in the binary — only one function references it.

## Function Characteristics

- **Type**: Regular member function (NOT virtual)
- **Parameters**: `(CBasePlayerController* this, usercmd_array, num_cmds, paused_flag, margin)`
- **Behavior**:
  - Resolves the controller's pawn entity via entity handle lookup
  - Validates the pawn is alive before processing
  - Iterates over received user commands, tracking sequence numbers and timing margins
  - Logs debug info with the `%sRecv usercmd` format string when channel logging is enabled
  - Calls into pawn movement processing for each valid command
  - Updates the controller's last processed command tick

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `CBasePlayerController_ProcessUsercmds.windows.yaml`
- `server.so` / `libserver.so` -> `CBasePlayerController_ProcessUsercmds.linux.yaml`
