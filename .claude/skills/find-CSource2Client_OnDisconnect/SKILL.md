---
name: find-CSource2Client_OnDisconnect
description: Find and identify the CSource2Client_OnDisconnect function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 client.dll or libclient.so to locate the OnDisconnect function by searching for the "client_disconnect" and "reason_code" debug strings and analyzing cross-references to find the matching code pattern.
disable-model-invocation: true
---

# Find CSource2Client_OnDisconnect

Locate `CSource2Client_OnDisconnect` in CS2 client.dll or libclient.so using IDA Pro MCP tools.

## Method

### 1. Search for the Debug Strings

```
mcp__ida-pro-mcp__find_regex pattern="client_disconnect"
mcp__ida-pro-mcp__find_regex pattern="reason_code"
```

### 2. Get Cross-References to Both Strings

```
mcp__ida-pro-mcp__xrefs_to addrs="<client_disconnect_string_addr>"
mcp__ida-pro-mcp__xrefs_to addrs="<reason_code_string_addr>"
```

### 3. Identify the Target Function

Find the function that has cross-references to BOTH "client_disconnect" and "reason_code" strings. This is `CSource2Client_OnDisconnect`.

Decompile the candidate function and verify it matches this code pattern:

```c
__int64 __fastcall CSource2Client_OnDisconnect(__int64 a1, unsigned int a2)
{
  // ...
  if ( (*(unsigned int (__fastcall **)(__int64, const char *))(*(_QWORD *)qword_XXXXXXXX + 104LL))(
         qword_XXXXXXXX,
         "client_disconnect") != -1 )
  {
    v3 = (*(__int64 (__fastcall **)(__int64, const char *, _QWORD, _QWORD))(*(_QWORD *)qword_XXXXXXXX + 48LL))(
           qword_XXXXXXXX,
           "client_disconnect",
           0LL,
           0LL);
    // ...
    LODWORD(v11) = sub_XXXXXXXX("reason_code", 11LL, ...);
    // ...
  }
  // ...
}
```

**Identification criteria:**
- The function references both "client_disconnect" and "reason_code" strings
- It takes two parameters: `(this_ptr, reason_code_value)` where `reason_code_value` is an unsigned int
- "client_disconnect" is used to check and create a game event
- "reason_code" is used as a key name to set the reason code field on the event

### 4. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CSource2Client_OnDisconnect"}]}
```

### 5. Generate Signature

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 6. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CSource2Client_OnDisconnect`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 5

## Function Characteristics

- **Type**: Non-virtual (regular) function
- **Parameters**: `(this_ptr, reason_code)` — this_ptr is the CSource2Client instance, reason_code is an unsigned int disconnect reason
- **Purpose**: Handles client disconnect by firing a "client_disconnect" game event with the given reason code

## Output YAML Format

The output YAML filename depends on the platform:
- `client.dll` → `CSource2Client_OnDisconnect.windows.yaml`
- `libclient.so` → `CSource2Client_OnDisconnect.linux.yaml`
