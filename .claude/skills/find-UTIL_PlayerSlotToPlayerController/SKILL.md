---
name: find-UTIL_PlayerSlotToPlayerController
description: Find and identify the UTIL_PlayerSlotToPlayerController function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the function by searching for the "splitscreenplayer" string reference.
---

# Find UTIL_PlayerSlotToPlayerController

Locate `UTIL_PlayerSlotToPlayerController` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="splitscreenplayer"
   ```

   Look for the exact string `"splitscreenplayer"` (not the ones with prefixes).

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function and verify it matches:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

   The target function should contain:
   - A vtable assignment: `*(_QWORD *)a1 = &CGameEvent::\`vftable';`
   - String reference: `"splitscreenplayer"`
   - CBufferString operations

   Example pattern:
   ```cpp
   v3 = (_QWORD *)(a1 + 24);
   *(_DWORD *)(a1 + 20) = -1073741760;
   v4 = a3;
   *(_QWORD *)a1 = &CGameEvent::`vftable';
   // ...
   v11 = "splitscreenplayer";
   // ...
   return a1;
   ```

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "UTIL_PlayerSlotToPlayerController"}]}
   ```

5. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

   Note: This function contains RIP-relative addresses (LEA to CGameEvent vtable), so use `??` wildcards for those bytes.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `UTIL_PlayerSlotToPlayerController`
   - `func_addr`: The function address
   - `func_sig`: The validated signature with wildcards

## Function Characteristics

- **Parameters**:
  - `a1`: Output event object pointer
  - `a2`: Event data
  - `a3`: String parameter (const char*)
- **Return**: Event object pointer (a1)

## Key Behaviors

1. Initializes a CGameEvent object with vtable
2. Sets up CBufferString operations
3. Uses "splitscreenplayer" string for event data
4. Returns the initialized event object

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- This is NOT a virtual function
- The function references CGameEvent vtable
- Contains CBufferString operations for string handling
- The signature requires wildcards for RIP-relative addresses

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `UTIL_PlayerSlotToPlayerController.windows.yaml`
- `server.so` → `UTIL_PlayerSlotToPlayerController.linux.yaml`

```yaml
func_va: 0x180XXXXXX      # Virtual address of the function - This can change when game updates.
func_rva: 0xXXXXXX        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xXX           # Function size in bytes - This can change when game updates.
func_sig: XX XX ?? ?? XX  # Unique byte signature with wildcards for RIP-relative addresses
```
