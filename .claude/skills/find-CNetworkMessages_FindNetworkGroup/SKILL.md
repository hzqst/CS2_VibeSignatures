---
name: find-CNetworkMessages_FindNetworkGroup
description: |
  Find and identify the CNetworkMessages_FindNetworkGroup virtual function call in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 engine2.dll or libengine2.so to locate the FindNetworkGroup vfunc call
  by decompiling CNetworkGameClient_RecordEntityBandwidth and identifying the virtual call through g_pNetworkMessages.
  Trigger: CNetworkMessages_FindNetworkGroup
disable-model-invocation: true
---

# Find CNetworkMessages_FindNetworkGroup

Locate `CNetworkMessages_FindNetworkGroup` vfunc call in CS2 engine2.dll or libengine2.so using IDA Pro MCP tools.

## Method

### 1. Get CNetworkGameClient_RecordEntityBandwidth Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetworkGameClient_RecordEntityBandwidth`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `func_va` for subsequent steps.

### 2. Decompile CNetworkGameClient_RecordEntityBandwidth

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 3. Identify CNetworkMessages_FindNetworkGroup VFunc Offset from Code Pattern

In the decompiled output, look for the **virtual function call through `g_pNetworkMessages`** pattern with the string `"Local Player"`:

**Pattern:**
```c
    if ( dword_XXXXXXXX > *v7 )
    {
      sub_XXXXXXXXX(&dword_XXXXXXXX);
      if ( dword_XXXXXXXX == -1 )
      {
        LOBYTE(v11) = 1;
        dword_XXXXXXXX = (*(__int64 (__fastcall **)(__int64, const char *, __int64))(*(_QWORD *)g_pNetworkMessages
                                                                                    + <VFUNC_OFFSET>))(
                            g_pNetworkMessages,
                            "Local Player",
                            v11);
        sub_XXXXXXXXX(&dword_XXXXXXXX);
      }
    }
```

The `g_pNetworkMessages` (or `qword_XXXXXXXX`) is dereferenced to get a vtable, and `<VFUNC_OFFSET>` (e.g. `120LL` = `0x78`) is the vfunc offset of `CNetworkMessages_FindNetworkGroup`.

Extract `<VFUNC_OFFSET>` from the call site. Calculate the vtable index: `index = <VFUNC_OFFSET> / 8` (e.g. `120 / 8 = 15`).

### 4. Generate VFunc Offset Signature

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET>]` or `call qword ptr [rcx+<VFUNC_OFFSET>]` at the call site near the `"Local Player"` string reference.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_FindNetworkGroup`, with `inst_addr` and `vfunc_offset` from this step.

### 5. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_FindNetworkGroup`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET>` in hex (e.g. `0x78`)
- `vfunc_index`: The calculated index (e.g. `15`)

## Function Characteristics

- **Purpose**: Finds a network message group by name and returns its group index
- **Called from**: `CNetworkGameClient_RecordEntityBandwidth` -- the function that records per-entity network bandwidth
- **Call context**: Called through `g_pNetworkMessages` vtable pointer with the string `"Local Player"` and a boolean flag
- **Parameters**: `(this, group_name, create_if_missing)` where `this` is the `g_pNetworkMessages` global pointer

## VTable Information

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the `CNetworkGameClient_RecordEntityBandwidth` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET> / 8`.

## Identification Pattern

The function is identified by locating the virtual call through `g_pNetworkMessages` inside `CNetworkGameClient_RecordEntityBandwidth`:
1. A global pointer `qword_XXXXXXXX` (`g_pNetworkMessages`) is dereferenced to get a vtable
2. A virtual call is made at `vtable + <VFUNC_OFFSET>`
3. The call passes the string `"Local Player"` and a boolean flag
4. The return value (int) is stored as a cached network group index (guarded by a `-1` sentinel check)

This is robust because:
- `CNetworkGameClient_RecordEntityBandwidth` is reliably found via its own skill
- The `"Local Player"` string literal at the call site is distinctive
- The sentinel pattern (`== -1` check before calling FindNetworkGroup) is unique

## Output YAML Format

The output YAML filename depends on the platform:
- `engine2.dll` -> `CNetworkMessages_FindNetworkGroup.windows.yaml`
- `libengine2.so` -> `CNetworkMessages_FindNetworkGroup.linux.yaml`
