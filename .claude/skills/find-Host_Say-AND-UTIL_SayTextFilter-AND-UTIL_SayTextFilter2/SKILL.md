---
name: find-Host_Say-AND-UTIL_SayTextFilter-AND-UTIL_SayTextFilter2
description: Find and identify the Host_Say, UTIL_SayTextFilter and UTIL_SayTextFilter2 in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the Host_Say, UTIL_SayTextFilter and UTIL_SayTextFilter2 function by searching for the "%s %s @ %s:" string reference and analyzing cross-references.
disable-model-invocation: true
---

# Find Host_Say, UTIL_SayTextFilter and UTIL_SayTextFilter2

Locate `Host_Say`, `UTIL_SayTextFilter` and `UTIL_SayTextFilter2` in CS2 `server.dll` or `server.so` using IDA Pro MCP tools.

## Method

1. Search for the string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="%s %s @ %s:"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile and rename the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

   * The decompiled function is `Host_Say`, and it needs to be renamed.

   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "Host_Say"}]}
   ```

   - Key Behaviors of Host_Say:

      1. Parses "say" or "say_team" commands
      2. Validates and sanitizes chat message
      3. Truncates message if too long (Unicode-aware)
      4. Broadcasts message to appropriate recipients (all or team)
      5. Logs chat to console with format `[All Chat][PlayerName (userid)]: message`
      6. Handles console-originated messages specially


4. In the decompiled code, look for the characteristic if-else pattern:
   ```c
   if ( v61 )
   {
     v15 = 0LL;
     LOBYTE(v44) = 1;
     sub_XXXXXXX((unsigned int)v63, (_DWORD)a1, v44, v61, (__int64)v60, (__int64)v12, (__int64)v62, 0LL);  // <-- UTIL_SayTextFilter2
   }
   else
   {
     LOBYTE(v45) = 1;
     sub_XXXXXXX(v63, v69, a1, v45);  // UTIL_SayTextFilter
     v15 = 0LL;
   }
   ```

   Or on Windows:
   ```c
   if ( v59 )
   {
       sub_XXXXXXX((__int64)&v61, (__int64)v8, 1, v59, v19, v12, v60, 0i64);  // <-- UTIL_SayTextFilter2
   }
   else
   {
       LOBYTE(v42) = 1;
       sub_XXXXXXX(&v61, v73, v8, v42);// UTIL_SayTextFilter
   }
   ```

5. Identify UTIL_SayTextFilter and UTIL_SayTextFilter2:
   - `UTIL_SayTextFilter2` is called in the `if` branch (when v59/v61 is non-null/true)
   - It takes 8 parameters: (filter, player, chat_flag, extra_param, text1, text2, text3, zero)
   - the one in else branch is `UTIL_SayTextFilter`

6. Rename them:

   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<util_saytextfilter_addr>", "name": "UTIL_SayTextFilter"}]}
   ```

   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<util_saytextfilter2_addr>", "name": "UTIL_SayTextFilter2"}]}
   ```

7. Generate and validate unique signature for `Host_Say`:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

8. Write IDA analysis output for `Host_Say` as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `Host_Say`
   - `func_addr`: The function address of `Host_Say` from step 3
   - `func_sig`: The validated signature from step 7

   Note: This is NOT a virtual function, so no vtable parameters are needed.

9. Generate and validate unique signature for `UTIL_SayTextFilter`:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

10. Write IDA analysis output for `UTIL_SayTextFilter` as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `UTIL_SayTextFilter`
   - `func_addr`: The function address of `UTIL_SayTextFilter` from step 5
   - `func_sig`: The validated signature from step 9

   Note: This is NOT a virtual function, so no vtable parameters are needed.

11. Generate and validate unique signature for `UTIL_SayTextFilter2`:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

12. Write IDA analysis output for `UTIL_SayTextFilter2` as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `UTIL_SayTextFilter2`
   - `func_addr`: The function address of `UTIL_SayTextFilter2` from step 5
   - `func_sig`: The validated signature from step 11

   Note: This is NOT a virtual function, so no vtable parameters are needed.

## Function Characteristics

- **Prototype**: `void Host_Say(CBasePlayerController *pController, CCommand &args, bool teamonly, int unk1, const char *unk2)`
- **Parameters**:
  - `pController`: Player controller sending the message (can be null for console)
  - `args`: Command arguments containing the message
  - `teamonly`: True for team chat, false for all chat
  - `unk1`: Unknown parameter
  - `unk2`: Unknown parameter (alternative command name)

- **Prototype**: `void UTIL_SayTextFilter(IRecipientFilter* filter, const char* pText, CBasePlayerController* pPlayer, bool chat)`
- **Parameters**:
  - `filter`: Recipient filter for message targets
  - `pText`: The text message to send
  - `pPlayer`: The player controller sending the message
  - `chat`: Boolean flag indicating if this is a chat message

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

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- Those are regular functions, NOT virtual functions
- `UTIL_SayTextFilter2` is the extended version of `UTIL_SayTextFilter` with more parameters

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `UTIL_SayTextFilter.windows.yaml`, `UTIL_SayTextFilter2.windows.yaml`
- `server.so` -> `UTIL_SayTextFilter.linux.yaml`, `UTIL_SayTextFilter2.linux.yaml`
