---
name: find-CCSPlayerController_ChangeTeam
description: Find and identify the CCSPlayerController_ChangeTeam function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the ChangeTeam function by searching for known debug string references and analyzing cross-references.
---

# Find CCSPlayerController_ChangeTeam

Locate `CCSPlayerController_ChangeTeam` in CS2 server.dll or server.so using IDA Pro MCP tools.

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
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSPlayerController_ChangeTeam"}]}
   ```

5. Find VTable and Calculate Offset:

  **ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.

   VTable class name: `CCSPlayerController`

6. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

7. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CCSPlayerController_ChangeTeam`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 6

   VTable parameters (when this is a virtual function):
   - `vtable_name`: `CCSPlayerController`
   - `vfunc_offset`: The offset from step 5
   - `vfunc_index`: The index from step 5

## Signature Pattern

The function contains a debug log call with format string:
```
"%s<%i><%s><%s>" ChangeTeam() CTMDBG , team %d, req team %d willSwitch %d, %.2f
```

## Function Characteristics

- **Parameters**: `(this, team_id)` where `this` is CCSPlayerController pointer, `team_id` is the target team

## Team IDs

- `0`: Unassigned
- `1`: Spectator
- `2`: Terrorist
- `3`: Counter-Terrorist

## VTable Information

- **VTable Name**: `CCSPlayerController::\`vftable'`
- **VTable Mangled Name**: `??_7CCSPlayerController@@6B@`
- **VTable Index**: 102 (0x66) - This can change when game updates.
- **VTable Offset**: 0x330  - This can change when game updates.

* Note that for `server.so`, The first 16 bytes of "vftable" are for RTTI. the real vftable =  `_ZTV19CCSPlayerController (0x221e390)` + `0x10` = `0x221e3A0`.

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSPlayerController_ChangeTeam.windows.yaml`
- `server.so` → `CCSPlayerController_ChangeTeam.linux.yaml`
