---
name: find-CNetworkMessages_Serialize
description: |
  Find and identify the CNetworkMessages_Serialize virtual function call in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 engine2.dll or libengine2.so to locate the Serialize vfunc call
  by decompiling CNetworkGameClient_SendMovePacket and identifying the virtual call through g_pNetworkMessages.
  Trigger: CNetworkMessages_Serialize
disable-model-invocation: true
---

# Find CNetworkMessages_Serialize

Locate `CNetworkMessages_Serialize` vfunc call in CS2 engine2.dll or libengine2.so using IDA Pro MCP tools.

## Method

### 1. Get CNetworkGameClient_SendMovePacket Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetworkGameClient_SendMovePacket`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `func_va` for subsequent steps.

### 2. Decompile CNetworkGameClient_SendMovePacket

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 3. Identify CNetworkMessages_Serialize VFunc Offset from Code Pattern

In the decompiled output, look for the **virtual function call through `g_pNetworkMessages`** pattern. There are two call sites with the same pattern:

**Pattern 1:**
```c
                    if ( (*(unsigned __int8 (__fastcall **)(__int64, __int64, void ***))(*(_QWORD *)qword_XXXXXXXX
                                                                                       + <VFUNC_OFFSET>))(
                           qword_XXXXXXXX,
                           a1 + 2936656,
                           &v42) )
                    {
                      if ( !*(_BYTE *)(a1 + 2936688) )
                        break;
                    }
```

**Pattern 2:**
```c
      if ( !(*(unsigned __int8 (__fastcall **)(__int64, __int64, __int64 (__fastcall ***)()))(*(_QWORD *)qword_XXXXXX
                                                                                            + <VFUNC_OFFSET>))(
              qword_XXXXXX,
              a1 + 2936672,
              &v44)
        || *(_BYTE *)(a1 + 2936704) )
      {
```

The `qword_XXXXXXXX` is `g_pNetworkMessages`, and `<VFUNC_OFFSET>` (e.g. `24LL` = `0x18`) is the vfunc offset of `CNetworkMessages_Serialize`.

Extract `<VFUNC_OFFSET>` from either call site. Both call sites use the same offset. Calculate the vtable index: `index = <VFUNC_OFFSET> / 8` (e.g. `24 / 8 = 3`).

### 4. Generate VFunc Offset Signature

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET>]` or `call qword ptr [rcx+<VFUNC_OFFSET>]` at either call site.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_Serialize`, with `inst_addr` and `vfunc_offset` from this step.

### 5. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_Serialize`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET>` in hex (e.g. `0x18`)
- `vfunc_index`: The calculated index (e.g. `3`)

## Function Characteristics

- **Purpose**: Serializes a network message for transmission
- **Called from**: `CNetworkGameClient_SendMovePacket` — the function that packs user commands into network packets
- **Call context**: Called through `g_pNetworkMessages` vtable pointer with message buffer and output parameters
- **Parameters**: `(this, message_buffer, output_ptr)` where `this` is the `g_pNetworkMessages` global pointer

## VTable Information

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the `CNetworkGameClient_SendMovePacket` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET> / 8`.

## Identification Pattern

The function is identified by locating the virtual call through `g_pNetworkMessages` inside `CNetworkGameClient_SendMovePacket`:
1. A global pointer `qword_XXXXXXXX` (`g_pNetworkMessages`) is dereferenced to get a vtable
2. A virtual call is made at `vtable + <VFUNC_OFFSET>`
3. The call passes message data and an output buffer
4. The return value (bool) is checked to determine if serialization succeeded

This is robust because:
- `CNetworkGameClient_SendMovePacket` is reliably found via its own xref strings
- The Serialize vfunc call pattern through `g_pNetworkMessages` is distinctive
- There are two call sites with the same offset, providing cross-validation

## Output YAML Format

The output YAML filename depends on the platform:
- `engine2.dll` -> `CNetworkMessages_Serialize.windows.yaml`
- `libengine2.so` -> `CNetworkMessages_Serialize.linux.yaml`
