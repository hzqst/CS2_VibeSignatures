---
name: find-LegacyGameEventListener
description: Find and identify the LegacyGameEventListener function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the LegacyGameEventListener function by searching for the "CSource2GameClients::StartHLTVServer: game event %s not found" string reference and analyzing cross-references.
disable-model-invocation: true
---

# Find LegacyGameEventListener

Locate `LegacyGameEventListener` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

1. Search for the debug string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="CSource2GameClients::StartHLTVServer: game event %s not found"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Identify the LegacyGameEventListener function:
   - Look for a function call that takes a single integer parameter (a2) and returns a pointer
   - The pattern looks like:
     ```c
     v5 = sub_XXXXXX(a2);  // This is LegacyGameEventListener
     v6 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v4 + 80LL))(v4);
     v7 = *(const char **)v6;
     if ( *(_QWORD *)v6 )
     {
       do
       {
         v8 = sub_YYYYYYYY(off_ZZZZZZZ, v7, 0LL);
         if ( v8 )
           sub_WWWWWWWW(off_ZZZZZZZ, v5, v8, 2LL);
         else
           DevMsg("CSource2GameClients::StartHLTVServer: game event %s not found.\n", v7);
     ```
   - The function `sub_XXXXXX` called with parameter `a2` is `LegacyGameEventListener`

5. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "LegacyGameEventListener"}]}
   ```

6. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

7. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `LegacyGameEventListener`
   - `func_addr`: The function address from step 4
   - `func_sig`: The validated signature from step 6

## String References

The function is identified by finding code that:
- Calls `LegacyGameEventListener` with an integer parameter
- Then iterates through game events, calling functions with the result
- Uses `DevMsg` to log when a game event is not found

## Function Characteristics

- **Parameters**:
  - `arg0`: Integer (unsigned int) - event listener index

- **Return Value**: Pointer to game event listener structure or 0 if invalid

- **Purpose**: Retrieves a legacy game event listener by index from a global array

## Code Pattern Details

The function performs bounds checking:
1. Checks if a global pointer is valid
2. Validates that the index is <= 0x3F (63)
3. Calculates the address: `base + (index + 4) * 16`
4. Returns the calculated address or 0 if validation fails

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `LegacyGameEventListener.windows.yaml`
- `libserver.so` → `LegacyGameEventListener.linux.yaml`
