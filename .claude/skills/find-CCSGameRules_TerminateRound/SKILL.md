---
name: find-CCSGameRules_TerminateRound
description: Find and identify the CCSGameRules_TerminateRound function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the TerminateRound function by searching for known debug string references and analyzing cross-references.
---

# Find CCSGameRules_TerminateRound

Locate `CCSGameRules_TerminateRound` in CS2 server.dll or server.so using IDA Pro MCP tools.

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

5. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CCSGameRules_TerminateRound`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

## Signature Pattern

The function has a distinctive prologue pattern:
- Uses `xmm6` register for floating-point parameter handling
- Has a unique combination of `movaps` instructions in prologue
- References the string "TerminateRound" for debug logging

## Function Characteristics

- **Purpose**: Terminates the current round with a specified reason and delay
- **Parameters**:
  - `this` - CCSGameRules pointer
  - `delay` (xmm1) - Float delay before round ends
  - `reason` (r8d) - Round end reason ID
  - Additional parameters for legacy support

## Round End Reason IDs

Common values (may vary by game version):
- `0`: Target bombed
- `1`: VIP escaped
- `2`: VIP killed
- `3`: Terrorists escaped
- `4`: CTs prevented escape
- `5`: Escaping terrorists neutralized
- `6`: Bomb defused
- `7`: CTs win
- `8`: Terrorists win
- `9`: Round draw
- `10`: All hostages rescued
- `11`: Target saved
- `12`: Hostages not rescued
- `13`: Terrorists not escaped
- `14`: VIP not escaped
- `15`: Game commencing
- `16`: Terrorists surrender
- `17`: CTs surrender
- `18`: Terrorists planted bomb
- `19`: CTs reached hostage

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CCSGameRules_TerminateRound.windows.yaml`
- `server.so` / `libserver.so` → `CCSGameRules_TerminateRound.linux.yaml`

```yaml
func_va: 0x1808AF770   # Virtual address - changes with game updates
func_rva: 0x8AF770     # Relative virtual address (VA - image base) - changes with game updates
func_size: 0x165C      # Function size in bytes - changes with game updates
func_sig: XX XX XX XX  # Unique byte signature for pattern scanning
```

Note: This is NOT a virtual function, so no vtable information is included.
