---
name: find-UTIL_SayTextFilter2
description: Find and identify the UTIL_SayTextFilter2 function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the UTIL_SayTextFilter2 function by searching for the "%s %s @ %s:" string reference and analyzing cross-references.
---

# Find UTIL_SayTextFilter2

Locate `UTIL_SayTextFilter2` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="%s %s @ %s:"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. In the decompiled code, look for the characteristic if-else pattern:
   ```c
   if ( v61 )
   {
     v15 = 0LL;
     LOBYTE(v44) = 1;
     sub_180975940((unsigned int)v63, (_DWORD)a1, v44, v61, (__int64)v60, (__int64)v12, (__int64)v62, 0LL);  // <-- UTIL_SayTextFilter2
   }
   else
   {
     LOBYTE(v45) = 1;
     sub_180975CE0(v63, v69, a1, v45);  // UTIL_SayTextFilter
     v15 = 0LL;
   }
   ```

   Or on Windows:
   ```c
   if ( v59 )
   {
       UTIL_SayTextFilter2((__int64)&v61, (__int64)v8, 1, v59, v19, v12, v60, 0i64);  // <-- Target function
   }
   else
   {
       LOBYTE(v42) = 1;
       UTIL_SayTextFilter(&v61, v73, v8, v42);
   }
   ```

5. Identify UTIL_SayTextFilter2:
   - It's called in the `if` branch (when v59/v61 is non-null/true)
   - It takes 8 parameters: (filter, player, chat_flag, extra_param, text1, text2, text3, zero)

6. Decompile the UTIL_SayTextFilter2 function to verify:
   ```
   mcp__ida-pro-mcp__decompile addr="<util_saytextfilter2_addr>"
   ```

7. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<util_saytextfilter2_addr>", "name": "UTIL_SayTextFilter2"}]}
   ```

8. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

9. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `UTIL_SayTextFilter2`
   - `func_addr`: The function address from step 6
   - `func_sig`: The validated signature from step 8

   Note: This is NOT a virtual function, so no vtable parameters are needed.

## Function Characteristics

- **Prototype**: `void UTIL_SayTextFilter2(IRecipientFilter* filter, CBasePlayerController* pPlayer, bool chat, const char* param, const char* text1, const char* text2, const char* text3, void* reserved)`
- **Parameters**:
  - `filter`: Recipient filter for message targets
  - `pPlayer`: The player controller sending the message
  - `chat`: Boolean flag indicating if this is a chat message
  - `param`: Additional parameter string
  - `text1`: First text parameter
  - `text2`: Second text parameter
  - `text3`: Third text parameter
  - `reserved`: Reserved parameter (usually 0/null)

## Related Functions

- `UTIL_SayTextFilter` - Simpler version with fewer parameters (called in the else branch)
- `Host_Say` - Higher-level function that calls these utilities

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- This is a regular function, NOT a virtual function
- No vtable information is needed for this function
- This is the extended version of UTIL_SayTextFilter with more parameters
- It's always found in the if branch paired with UTIL_SayTextFilter in the else branch

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `UTIL_SayTextFilter2.windows.yaml`
- `server.so` -> `UTIL_SayTextFilter2.linux.yaml`

```yaml
func_va: 0x180XXXXXX      # Virtual address of the function - This can change when game updates.
func_rva: 0xXXXXXX        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xXXX          # Function size in bytes - This can change when game updates.
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - This can change when game updates.
```
