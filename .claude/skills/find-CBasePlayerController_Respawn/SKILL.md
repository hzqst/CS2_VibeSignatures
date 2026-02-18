---
name: find-CBasePlayerController_Respawn
description: |
  Find and identify the CBasePlayerController_Respawn virtual function call in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 server.dll or server.so to locate the Respawn vfunc call
  by searching for the "GMR_BeginRound" log string, tracing to the CCSGameRules_BeginRound function,
  and identifying the Respawn vfunc call in the player respawn loop.
  Trigger: CBasePlayerController_Respawn
disable-model-invocation: true
---

# Find CBasePlayerController_Respawn

Locate `CBasePlayerController_Respawn` vfunc call in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the `GMR_BeginRound` log string:

   ```
   mcp__ida-pro-mcp__find_regex pattern="GMR_BeginRound"
   ```

2. Find cross-references to the string:

   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

   This leads to the `CCSGameRules_BeginRound` function.

3. Rename the function:

   ```
   mcp__ida-pro-mcp__rename batch={"func": {"addr": "<function_addr>", "name": "CCSGameRules_BeginRound"}}
   ```

4. Decompile and locate the respawn loop pattern:

   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

   Look for a loop pattern like this:

   ```c
   do
   {
     v30 = *v28;                                          // player controller
     (*(void (__fastcall **)(__int64))(*(_QWORD *)*v28 + <PreRound_offset>))(*v28);
     v31 = sub_XXX(v30);                                  // resolve m_hPawn -> pawn entity
     // ... resolve another entity handle from controller ...
     if ( v31 )
     {
       if ( (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)v31 + <IsAlive_offset>))(v31) )
       {
         (*(void (__fastcall **)(__int64))(*(_QWORD *)v33 + <AliveAction_offset>))(v33);
         if ( v36 )
         {
           sub_XXX(v36);
           sub_XXX(v36, 32LL);
         }
       }
       else if ( v36 && *(_BYTE *)(v30 + <team_offset>) == 3 || *(_BYTE *)(v30 + <team_offset>) == 2 )
       {
         sub_XXX(v36);                                    // reset pawn model/skeleton state
         (*(void (__fastcall **)(__int64))(*(_QWORD *)v30 + <Respawn_offset>))(v30);  // CBasePlayerController::Respawn
       }
     }
     ++v28;
   }
   while ( v28 != v29 );
   ```

   The loop iterates over a shuffled player controller list. For each controller:
   - Resolves the player pawn via `m_hPawn` handle
   - If pawn is alive: performs alive-state updates
   - If pawn is NOT alive AND team is T(2) or CT(3): calls `controller->Respawn()` via vtable

   Extract `<Respawn_offset>` from the virtual call on the **controller** (`v30`), in the else branch.
   This is the vfunc offset for `CBasePlayerController_Respawn`.

   Key identification points:
   - The Respawn call is in the **else** branch (pawn not alive)
   - It is guarded by a team number check (`== 2 || == 3`)
   - The call target is on the **controller** object, not the pawn
   - A model/skeleton reset function is called just before Respawn

5. Calculate vtable index:

   ```
   vfunc_index = <Respawn_offset> / 8
   ```

6. Generate vfunc offset signature:

   Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<Respawn_offset>]`.

   **ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CBasePlayerController_Respawn`, with `inst_addr` and `vfunc_offset` from this step.

7. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CBasePlayerController_Respawn`
   - `func_addr`: `None` (virtual call, actual address resolved at runtime)
   - `func_sig`: `None`
   - `vfunc_sig`: The validated signature from step 6

   VTable parameters:
   - `vtable_name`: `CBasePlayerController`
   - `vfunc_offset`: `<Respawn_offset>` from step 4
   - `vfunc_index`: The vtable index from step 5

## Function Characteristics

- **Purpose**: Respawns a player controller's pawn at round start
- **Called from**: `CCSGameRules_BeginRound` — the round-start handler logged as `"GMR_BeginRound"`
- **Call context**: Only called for dead players on T(2) or CT(3) teams
- **Call site object**: `CBasePlayerController` (not the pawn)

## VTable Information

- **VTable Name**: `CBasePlayerController`
- **VTable Mangled Name**: `??_7CBasePlayerController@@6B@` (Windows) / `_ZTV21CBasePlayerController` (Linux)
- **VTable Offset**: Changes with game updates. Extract from the `CCSGameRules_BeginRound` respawn loop.
- **VTable Index**: Changes with game updates. Resolve via `<Respawn_offset> / 8`.

## String-Based Discovery

The primary discovery method uses the `GMR_BeginRound` log message:

1. **Search string**: `"GMR_BeginRound"`
2. **Xref chain**: String → `CCSGameRules_BeginRound`
3. **Respawn loop**: The function iterates shuffled players, calling `controller->Respawn()` via vtable for dead T/CT players

This is robust because:
- The `GMR_BeginRound` string is unique and stable across updates
- The respawn loop structure with team checks (2/3) is distinctive
- The vfunc offset is extracted directly from the call site

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBasePlayerController_Respawn.windows.yaml`
- `server.so` / `libserver.so` → `CBasePlayerController_Respawn.linux.yaml`
