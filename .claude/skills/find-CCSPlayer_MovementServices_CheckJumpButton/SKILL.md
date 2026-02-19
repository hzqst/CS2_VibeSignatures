---
name: find-CCSPlayer_MovementServices_CheckJumpButton
description: Find and identify the CCSPlayer_MovementServices_CheckJumpButton function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the CheckJumpButton function by searching for the "player_jump" game event string and analyzing cross-references.
disable-model-invocation: true
---

# Find CCSPlayer_MovementServices_CheckJumpButton

Locate `CCSPlayer_MovementServices_CheckJumpButton` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

1. Search for the game event string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="player_jump"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function and verify it contains the `"player_jump"` event firing pattern:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

   Look for the code pattern:
   ```c
   v5 = (int *)(*(__int64 (__fastcall **)(__int64, const char *, _QWORD, _QWORD))(*(_QWORD *)qword_XXXXXX + 48LL))(
                  qword_XXXXXX,
                  "player_jump",
                  0LL,
                  0LL);
   ```

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSPlayer_MovementServices_CheckJumpButton"}]}
   ```

5. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CCSPlayer_MovementServices_CheckJumpButton`.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CCSPlayer_MovementServices_CheckJumpButton`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

## String References

The function fires the `"player_jump"` game event using the game event manager:
```c
(*(__int64 (__fastcall **)(game_event_manager, "player_jump", 0, 0))(*game_event_manager + 48))(...)
```

## Function Characteristics

- **Parameters**: `(this, move_data)` where `this` is a pointer to a helper/context object containing CCSPlayer_MovementServices pointer at offset +8, and `move_data` is the movement data structure
- **Size**: ~0xB0B bytes (large function)
- **Behavior**: Checks if the player can jump, handles jump stamina, water jumping, ladder jumping, and fires the `"player_jump"` game event on successful jump

## Key Code Patterns

- Accesses player pawn via `this->movementServices->playerPawn` (offset 56 from movement services)
- Checks move type via helper function (returns 2 for ladder)
- Handles jump stamina decay at offset +84 of a sub-structure
- Fires `"player_jump"` game event with `"userid"` field set to the player pawn entity
- Contains water/ladder jump special cases with different jump velocities

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `CCSPlayer_MovementServices_CheckJumpButton.windows.yaml`
- `libserver.so` -> `CCSPlayer_MovementServices_CheckJumpButton.linux.yaml`
