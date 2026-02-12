---
name: find-CCSGameRules_TerminateRound-AND-CEntityInstance_AcceptInput
description: Find and identify the CCSGameRules_TerminateRound and CEntityInstance_AcceptInput functions in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the TerminateRound function by searching for the "TerminateRound" string reference and then identifying CEntityInstance_AcceptInput by analyzing calls with "CTsWin" or "TerroristsWin" string parameters.
---

# Find CCSGameRules_TerminateRound and CEntityInstance_AcceptInput

Locate `CCSGameRules_TerminateRound` and `CEntityInstance_AcceptInput` in CS2 `server.dll` or `server.so` using IDA Pro MCP tools.

## Method

1. Search for the debug string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="TerminateRound"
   ```

   Expected matches:
   - `TerminateRound` - Plain string reference
   - `TerminateRound: unknown round end ID %i\n` - Error message

2. Get cross-references to the plain string `TerminateRound`:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function to verify:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CCSGameRules_TerminateRound"}]}
   ```

5. In the decompiled code of `CCSGameRules_TerminateRound`, look for calls with "CTsWin" or "TerroristsWin" string parameters:
   ```c
   if ( v11 == 1 )
   {
     v28 = 0;
     if ( dword_181D5DB68 > 0 )
     {
       v29 = 0LL;
       do
       {
         sub_XXXXXXX(*(_QWORD *)(v29 + qword_181D5DB70), (__int64)"CTsWin", 0, 0, (__int64)&v123, 0, 0LL);  // <-- CEntityInstance_AcceptInput
         ++v28;
         v29 += 8LL;
       }
       while ( v28 < dword_181D5DB68 );
     }
   }
   else if ( v11 == 2 )
   {
     v30 = 0;
     if ( dword_181D5DB68 > 0 )
     {
       v31 = 0LL;
       do
       {
         sub_XXXXXXX(*(_QWORD *)(v31 + qword_181D5DB70), (__int64)"TerroristsWin", 0, 0, (__int64)&v123, 0, 0LL);  // <-- CEntityInstance_AcceptInput
         ++v30;
         v31 += 8LL;
       }
       while ( v30 < dword_181D5DB68 );
     }
   }
   ```

   The function being called with "CTsWin" or "TerroristsWin" is `CEntityInstance_AcceptInput`.

6. Rename `CEntityInstance_AcceptInput`:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<acceptinput_func_addr>", "name": "CEntityInstance_AcceptInput"}]}
   ```

7. Generate and validate unique signature for `CCSGameRules_TerminateRound`:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

8. Write IDA analysis output for `CCSGameRules_TerminateRound` as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CCSGameRules_TerminateRound`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 7

   Note: This is NOT a virtual function, so no vtable parameters are needed.

9. Generate and validate unique signature for `CEntityInstance_AcceptInput`:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

10. Write IDA analysis output for `CEntityInstance_AcceptInput` as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CEntityInstance_AcceptInput`
   - `func_addr`: The function address of `CEntityInstance_AcceptInput` from step 5
   - `func_sig`: The validated signature from step 9

   Note: This is NOT a virtual function, so no vtable parameters are needed.

## Function Characteristics

### CCSGameRules_TerminateRound

- **Purpose**: Terminates the current round with a specified reason and delay
- **Prototype**: `void CCSGameRules_TerminateRound(CCSGameRules* this, float delay, int reason, ...)`
- **Parameters**:
  - `this` - CCSGameRules pointer
  - `delay` (xmm1) - Float delay before round ends
  - `reason` (r8d) - Round end reason ID
  - Additional parameters for legacy support

### CEntityInstance_AcceptInput

- **Purpose**: Handles entity input events (like "CTsWin", "TerroristsWin")
- **Prototype**: `void CEntityInstance_AcceptInput(CEntityInstance* this, const char* inputName, int param1, int param2, variant_t* value, int param4, void* reserved)`
- **Parameters**:
  - `this` - CEntityInstance pointer
  - `inputName` - Name of the input event (e.g., "CTsWin", "TerroristsWin")
  - `param1` - Additional parameter (usually 0)
  - `param2` - Additional parameter (usually 0)
  - `value` - Variant value pointer
  - `param4` - Additional parameter (usually 0)
  - `reserved` - Reserved parameter (usually NULL)

## Round End Reason IDs

Common values (may vary by game version):
- `1`: CTs win (triggers "CTsWin" input)
- `2`: Terrorists win (triggers "TerroristsWin" input)
- `0`: Target bombed
- `3`: Terrorists escaped
- `4`: CTs prevented escape
- `5`: Escaping terrorists neutralized
- `6`: Bomb defused
- `7`: CTs win (alternative)
- `8`: Terrorists win (alternative)
- `9`: Round draw
- `10`: All hostages rescued
- `11`: Target saved
- `12`: Hostages not rescued
- `13`: Terrorists not escaped
- `14`: VIP not escaped
- `15`: Game commencing
- `16`: Terrorists surrender
- `17`: CTs surrender

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- Both functions are regular functions, NOT virtual functions
- `CEntityInstance_AcceptInput` is called within `CCSGameRules_TerminateRound` to notify entities about round results
- The "CTsWin" input is sent when reason == 1 (CTs win)
- The "TerroristsWin" input is sent when reason == 2 (Terrorists win)

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `CCSGameRules_TerminateRound.windows.yaml`, `CEntityInstance_AcceptInput.windows.yaml`
- `server.so` -> `CCSGameRules_TerminateRound.linux.yaml`, `CEntityInstance_AcceptInput.linux.yaml`
