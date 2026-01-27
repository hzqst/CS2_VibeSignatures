---
name: find-Host_Say
description: Find and identify the Host_Say function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the Host_Say function by searching for chat-related string references like "All Chat" or "Allies Chat" and analyzing cross-references.
---

# Find Host_Say

Locate `Host_Say` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="All Chat"
   ```

   Or alternatively:
   ```
   mcp__ida-pro-mcp__find_regex pattern="Allies Chat"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function and verify it matches:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

   The target function should contain:
   - Strings: `"All Chat"` and `"Allies Chat"`
   - Command checks: `"say"` and `"say_team"`
   - Log format: `"[%s][%s (%u)]: %s\n"`
   - Console format: `"\"Console<0>\" say \"%s\"\n"` and `"\"Console<0>\" say_team \"%s\"\n"`
   - Unicode validation via `V_UnicodeValidate`

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "Host_Say"}]}
   ```

5. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `Host_Say`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

   Note: This is NOT a virtual function, so no vtable parameters are needed.

## Signature Pattern

The function has a distinctive prologue:
- Saves r9d and r8b to stack
- Pushes rbp, rbx, rsi, rdi, r12, r14
- Large stack frame allocation (0x288 bytes)
- Accesses CCommand structure at offset 0x438

## Function Characteristics

- **Prototype**: `void Host_Say(CBasePlayerController *pController, CCommand &args, bool teamonly, int unk1, const char *unk2)`
- **Parameters**:
  - `pController`: Player controller sending the message (can be null for console)
  - `args`: Command arguments containing the message
  - `teamonly`: True for team chat, false for all chat
  - `unk1`: Unknown parameter
  - `unk2`: Unknown parameter (alternative command name)

## Key Behaviors

1. Parses "say" or "say_team" commands
2. Validates and sanitizes chat message
3. Truncates message if too long (Unicode-aware)
4. Broadcasts message to appropriate recipients (all or team)
5. Logs chat to console with format `[All Chat][PlayerName (userid)]: message`
6. Handles console-originated messages specially

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- This is a regular function, NOT a virtual function
- No vtable information is needed for this function
- Large function (~0x7B4 bytes) with complex chat handling logic

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `Host_Say.windows.yaml`
- `server.so` → `Host_Say.linux.yaml`

```yaml
func_va: 0x180XXXXXX      # Virtual address of the function - This can change when game updates.
func_rva: 0xXXXXXX        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xXXX          # Function size in bytes - This can change when game updates.
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - This can change when game updates.
```
