---
name: find-UTIL_SayTextFilter
description: Find and identify the UTIL_SayTextFilter function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the UTIL_SayTextFilter function by first finding UTIL_SayTextFilter2 references and analyzing the else branch that calls UTIL_SayTextFilter.
---

# Find UTIL_SayTextFilter

Locate `UTIL_SayTextFilter` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. First, search for the string used to locate UTIL_SayTextFilter2:
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
   if ( v59 )
   {
       UTIL_SayTextFilter2((__int64)&v61, (__int64)v8, 1, v59, v19, v12, v60, 0i64);
   }
   else
   {
       LOBYTE(v42) = 1;
       UTIL_SayTextFilter(&v61, v73, v8, v42);  // <-- Target function
   }
   ```

   Or on Linux:
   ```c
   if ( v61 )
   {
     v15 = 0LL;
     LOBYTE(v44) = 1;
     sub_XXXXXXX((unsigned int)v63, (_DWORD)a1, v44, v61, (__int64)v60, (__int64)v12, (__int64)v62, 0LL);  // UTIL_SayTextFilter2
   }
   else
   {
     LOBYTE(v45) = 1;
     sub_XXXXXXX(v63, v69, a1, v45);  // <-- UTIL_SayTextFilter (target)
     v15 = 0LL;
   }
   ```

5. Identify UTIL_SayTextFilter:
   - It's called in the `else` branch (when v59/v61 is null/false)
   - It takes 4 parameters: (filter, text, player, chat_flag)

6. Decompile the UTIL_SayTextFilter function to verify:
   ```
   mcp__ida-pro-mcp__decompile addr="<util_saytextfilter_addr>"
   ```

7. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<util_saytextfilter_addr>", "name": "UTIL_SayTextFilter"}]}
   ```

8. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

9. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `UTIL_SayTextFilter`
   - `func_addr`: The function address from step 6
   - `func_sig`: The validated signature from step 8

   Note: This is NOT a virtual function, so no vtable parameters are needed.

## Function Characteristics

- **Prototype**: `void UTIL_SayTextFilter(IRecipientFilter* filter, const char* pText, CBasePlayerController* pPlayer, bool chat)`
- **Parameters**:
  - `filter`: Recipient filter for message targets
  - `pText`: The text message to send
  - `pPlayer`: The player controller sending the message
  - `chat`: Boolean flag indicating if this is a chat message

## Related Functions

- `UTIL_SayTextFilter2` - Extended version with more parameters (called in the if branch)
- `Host_Say` - Higher-level function that calls these utilities

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- This is a regular function, NOT a virtual function
- No vtable information is needed for this function
- The function is simpler than UTIL_SayTextFilter2 and used when extra parameters aren't needed
- It's always found in the else branch paired with UTIL_SayTextFilter2

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `UTIL_SayTextFilter.windows.yaml`
- `server.so` -> `UTIL_SayTextFilter.linux.yaml`

```yaml
func_va: 0x180XXXXXX      # Virtual address of the function - This can change when game updates.
func_rva: 0xXXXXXX        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xXXX          # Function size in bytes - This can change when game updates.
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - This can change when game updates.
```
