---
name: find-IGameSystem_GetName
description: |
  Find and identify the IGameSystem_GetName virtual function call in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 client.dll or libclient.so to locate the GetName vfunc call
  by decompiling CSteamworksGameStats_OnReceivedSessionID and identifying the virtual call through an IGameSystem vtable pointer.
  Trigger: IGameSystem_GetName
disable-model-invocation: true
---

# Find IGameSystem_GetName

Locate `IGameSystem_GetName` vfunc call in CS2 client.dll or libclient.so using IDA Pro MCP tools.

## Method

### 1. Get CSteamworksGameStats_OnReceivedSessionID Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CSteamworksGameStats_OnReceivedSessionID`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `func_va` for subsequent steps.

### 2. Decompile CSteamworksGameStats_OnReceivedSessionID

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 3. Identify IGameSystem_GetName VFunc Offset from Code Pattern

In the decompiled output, look for the **virtual function call through an IGameSystem vtable pointer** near the `DevMsg` calls with strings like `"Steamworks Stats: %s session id not available.\n"` and `"Steamworks Stats: %s Received %s session id: %llu\n"`:

**Pattern:**
```c
    if ( *((_DWORD *)a2 + 2) != 1 )
    {
      v7 = (const char *)(*(__int64 (**)(void))(v6 + <VFUNC_OFFSET>))();// IGameSystem::GetName()
      DevMsg(2, "Steamworks Stats: %s session id not available.\n", v7);
      ...
      goto LABEL_4;
    }
    v8 = *a2;
    v9 = (const char *)(*(__int64 (**)(void))(v6 + <VFUNC_OFFSET>))();// IGameSystem::GetName()
    DevMsg(2, "Steamworks Stats: %s Received %s session id: %llu\n", v9, "CLIENT", v8);
```

The `v6` is loaded from the object's vtable pointer (the IGameSystem vtable), and `<VFUNC_OFFSET>` (e.g. `456` = `0x1C8`) is the vfunc offset of `IGameSystem_GetName`.

Extract `<VFUNC_OFFSET>` from the call site. Calculate the vtable index: `index = <VFUNC_OFFSET> / 8` (e.g. `456 / 8 = 57`).

### 4. Generate VFunc Offset Signature

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET>]` or `call qword ptr [rcx+<VFUNC_OFFSET>]` at the call site near the `"Steamworks Stats: %s session id not available."` string reference.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `IGameSystem_GetName`, with `inst_addr` and `vfunc_offset` from this step.

### 5. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `IGameSystem_GetName`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `IGameSystem`
- `vfunc_offset`: `<VFUNC_OFFSET>` in hex (e.g. `0x1C8`)
- `vfunc_index`: The calculated index (e.g. `57`)

## Function Characteristics

- **Purpose**: Returns the name of an IGameSystem instance as a const char*
- **Called from**: `CSteamworksGameStats_OnReceivedSessionID` -- the callback that handles Steam session ID reception
- **Call context**: Called through the IGameSystem vtable pointer with no parameters (besides `this`), the return value is passed to `DevMsg` as the `%s` format argument
- **Parameters**: `(this)` where `this` is the IGameSystem instance pointer

## VTable Information

- **VTable Name**: `IGameSystem`
- **VTable Offset**: Changes with game updates. Extract from the `CSteamworksGameStats_OnReceivedSessionID` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET> / 8`.

## Identification Pattern

The function is identified by locating the virtual call through the IGameSystem vtable inside `CSteamworksGameStats_OnReceivedSessionID`:
1. The function loads a vtable pointer `v6` from the object (the IGameSystem instance)
2. A virtual call is made at `vtable + <VFUNC_OFFSET>`
3. The return value (const char*) is passed directly to `DevMsg` with the format string `"Steamworks Stats: %s session id not available.\n"` or `"Steamworks Stats: %s Received %s session id: %llu\n"`
4. The same vfunc offset appears at two call sites within the function

This is robust because:
- `CSteamworksGameStats_OnReceivedSessionID` is reliably found via its own skill (identified by the `"Steamworks Stats: %s Received %s session id: %llu"` string)
- The `DevMsg` format strings at the call sites are distinctive
- The pattern of calling `GetName()` on `this` (the IGameSystem instance) to produce a display name for logging is unique

## Output YAML Format

The output YAML filename depends on the platform:
- `client.dll` -> `IGameSystem_GetName.windows.yaml`
- `libclient.so` -> `IGameSystem_GetName.linux.yaml`
