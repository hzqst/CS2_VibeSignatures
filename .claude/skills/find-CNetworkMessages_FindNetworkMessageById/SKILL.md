---
name: find-CNetworkMessages_FindNetworkMessageById
description: |
  Find and identify the CNetworkMessages_FindNetworkMessageById virtual function call in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 engine2.dll or libengine2.so to locate the FindNetworkMessageById vfunc call
  by decompiling CDemoRecorder_WriteSpawnGroups and identifying the virtual call through g_pNetworkMessages.
  Trigger: CNetworkMessages_FindNetworkMessageById
disable-model-invocation: true
---

# Find CNetworkMessages_FindNetworkMessageById

Locate `CNetworkMessages_FindNetworkMessageById` vfunc call in CS2 engine2.dll or libengine2.so using IDA Pro MCP tools.

## Method

### 1. Get CDemoRecorder_WriteSpawnGroups Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CDemoRecorder_WriteSpawnGroups`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `func_va` for subsequent steps.

### 2. Decompile CDemoRecorder_WriteSpawnGroups

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 3. Identify CNetworkMessages_FindNetworkMessageById VFunc Offset from Code Pattern

In the decompiled output, look for the **virtual function call through `g_pNetworkMessages`** pattern inside a do-while loop that iterates over spawn groups:

```c
      do
      {
        v11 = *v9;
        v31 = 0;
        v38 = 0LL;
        v37 = 0LL;
        ...
        v30[0] = &CNETMsg_SpawnGroup_Load_t::`vftable';
        ...

        //g_pNetworkMessages->FindNetworkMessageById(8)
        v12 = (*(__int64 (__fastcall **)(__int64, __int64))(*(_QWORD *)g_pNetworkMessages + <VFUNC_OFFSET>))(
                g_pNetworkMessages,
                8LL);
        ...
```

The `g_pNetworkMessages` is the global pointer, and `<VFUNC_OFFSET>` (e.g. `248LL` = `0xF8`) is the vfunc offset of `CNetworkMessages_FindNetworkMessageById`.

The second argument `8LL` is the message ID for `CNETMsg_SpawnGroup_Load`. This is the key distinguishing feature of this call site.

Extract `<VFUNC_OFFSET>` from the call site. Calculate the vtable index: `index = <VFUNC_OFFSET> / 8` (e.g. `248 / 8 = 31`).

### 4. Generate VFunc Offset Signature

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET>]` or `call qword ptr [rcx+<VFUNC_OFFSET>]` at the call site.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_FindNetworkMessageById`, with `inst_addr` and `vfunc_offset` from this step.

### 5. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_FindNetworkMessageById`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET>` in hex (e.g. `0xF8`)
- `vfunc_index`: The calculated index (e.g. `31`)

## Function Characteristics

- **Purpose**: Finds a registered network message by its numeric ID
- **Called from**: `CDemoRecorder_WriteSpawnGroups` -- the function that writes spawn group data during demo recording
- **Call context**: Called through `g_pNetworkMessages` vtable pointer with a message ID parameter (8 = CNETMsg_SpawnGroup_Load)
- **Parameters**: `(this, msg_id)` where `this` is the `g_pNetworkMessages` global pointer

## VTable Information

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the `CDemoRecorder_WriteSpawnGroups` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET> / 8`.

## Identification Pattern

The function is identified by locating the virtual call through `g_pNetworkMessages` inside `CDemoRecorder_WriteSpawnGroups`:
1. A global pointer `g_pNetworkMessages` is dereferenced to get a vtable
2. A virtual call is made at `vtable + <VFUNC_OFFSET>`
3. The call passes a constant message ID (8) as the second argument
4. The result is used together with spawn group data to serialize `CNETMsg_SpawnGroup_Load` messages

This is robust because:
- `CDemoRecorder_WriteSpawnGroups` is reliably found via its xref string "CDemoRecorder::WriteSpawnGroups()"
- The FindNetworkMessageById vfunc call pattern through `g_pNetworkMessages` with constant argument 8 is distinctive
- The nearby CNETMsg_SpawnGroup_Load vftable reference provides cross-validation

## Output YAML Format

The output YAML filename depends on the platform:
- `engine2.dll` -> `CNetworkMessages_FindNetworkMessageById.windows.yaml`
- `libengine2.so` -> `CNetworkMessages_FindNetworkMessageById.linux.yaml`
