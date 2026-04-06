---
name: find-CNetworkMessages_SetNetworkSerializationContextData-AND-CFlattenedSerializers_CreateFieldChangedEventQueue
description: |
  Find and identify CNetworkMessages_SetNetworkSerializationContextData and CFlattenedSerializers_CreateFieldChangedEventQueue
  virtual function calls in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so
  to locate both vfunc calls by decompiling CEntitySystem_Activate and identifying virtual calls through g_pNetworkMessages
  and g_pFlattenedSerializers.
  Trigger: CNetworkMessages_SetNetworkSerializationContextData, CFlattenedSerializers_CreateFieldChangedEventQueue
disable-model-invocation: true
---

# Find CNetworkMessages_SetNetworkSerializationContextData and CFlattenedSerializers_CreateFieldChangedEventQueue

Locate `CNetworkMessages_SetNetworkSerializationContextData` and `CFlattenedSerializers_CreateFieldChangedEventQueue` vfunc calls in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

### 1. Get CEntitySystem_Activate Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CEntitySystem_Activate`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `func_va` for subsequent steps.

### 2. Decompile CEntitySystem_Activate

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 3. Identify CNetworkMessages_SetNetworkSerializationContextData VFunc Offset from Code Pattern

In the decompiled output, look for the **virtual function call through `g_pNetworkMessages`** pattern near the `"EntitySystem - Class Tables"` string reference:

```c
  COM_TimestampedLog("EntitySystem - Class Tables", v9, m);
  if ( g_pNetworkMessages )
  {
    (*(void (__fastcall **)(__int64, const char *, _QWORD, __int64))(*(_QWORD *)g_pNetworkMessages + <VFUNC_OFFSET_A>))(
      g_pNetworkMessages,
      "string_t_table",
      *(unsigned int *)(a1 + 3012),
      a1 + 7888);
```

The `g_pNetworkMessages` is the global pointer, and `<VFUNC_OFFSET_A>` (e.g. `168LL` = `0xA8`) is the vfunc offset of `CNetworkMessages_SetNetworkSerializationContextData`.

Extract `<VFUNC_OFFSET_A>` from the call site. Calculate the vtable index: `index = <VFUNC_OFFSET_A> / 8` (e.g. `168 / 8 = 21`).

### 4. Generate VFunc Offset Signature for SetNetworkSerializationContextData

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET_A>]` or `call qword ptr [rcx+<VFUNC_OFFSET_A>]` at the call site.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_SetNetworkSerializationContextData`, with `inst_addr` and `vfunc_offset` from this step.

### 5. Write IDA Analysis Output as YAML for SetNetworkSerializationContextData

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_SetNetworkSerializationContextData`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET_A>` in hex (e.g. `0xA8`)
- `vfunc_index`: The calculated index (e.g. `21`)

### 6. Identify CFlattenedSerializers_CreateFieldChangedEventQueue VFunc Offset from Code Pattern

Further down in the same `CEntitySystem_Activate` decompiled output, after the `g_pNetworkMessages` block, look for the **virtual function call through `g_pFlattenedSerializers`**. The pattern appears inside a conditional block that allocates a `CNetworkFieldScratchData` object:

```c
  if ( *(_BYTE *)(a1 + 3042) )
  {
    // ... allocation of CNetworkFieldScratchData ...
    *(_QWORD *)(a1 + 3216) = v37;
    (*(void (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)v37 + 8LL))(
      v37,
      0x10000,
      (unsigned int)dword_XXXXXXXX);
    result = (*(__int64 (__fastcall **)(__int64, _QWORD, _QWORD))(*(_QWORD *)g_pFlattenedSerializers
                                                                + <VFUNC_OFFSET_B>))(
               g_pFlattenedSerializers,
               *(_QWORD *)(a1 + 3216),
               *(_QWORD *)(a1 + 3224));
    *(_QWORD *)(a1 + 3208) = result;
  }
```

The `g_pFlattenedSerializers` is the global pointer, and `<VFUNC_OFFSET_B>` (e.g. `280LL` = `0x118`) is the vfunc offset of `CFlattenedSerializers_CreateFieldChangedEventQueue`.

Extract `<VFUNC_OFFSET_B>` from the call site. Calculate the vtable index: `index = <VFUNC_OFFSET_B> / 8` (e.g. `280 / 8 = 35`).

### 7. Generate VFunc Offset Signature for CreateFieldChangedEventQueue

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET_B>]` or `call qword ptr [rcx+<VFUNC_OFFSET_B>]` at the call site.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CFlattenedSerializers_CreateFieldChangedEventQueue`, with `inst_addr` and `vfunc_offset` from this step.

### 8. Write IDA Analysis Output as YAML for CreateFieldChangedEventQueue

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CFlattenedSerializers_CreateFieldChangedEventQueue`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 7

VTable parameters:
- `vtable_name`: `CFlattenedSerializers`
- `vfunc_offset`: `<VFUNC_OFFSET_B>` in hex (e.g. `0x118`)
- `vfunc_index`: The calculated index (e.g. `35`)

## Function Characteristics

### CNetworkMessages_SetNetworkSerializationContextData

- **Purpose**: Sets network serialization context data for entity class tables, including string table registration
- **Called from**: `CEntitySystem_Activate` — the function that activates the entity system and registers network class tables
- **Call context**: Called through `g_pNetworkMessages` vtable pointer with string table name, parameter, and entity system data
- **Parameters**: `(this, "string_t_table", string_table_param, entity_system_data)` where `this` is the `g_pNetworkMessages` global pointer

### CFlattenedSerializers_CreateFieldChangedEventQueue

- **Purpose**: Creates a field-changed event queue used by the network serialization system to track entity field changes
- **Called from**: `CEntitySystem_Activate` — after the `g_pNetworkMessages` block, inside a conditional that checks entity system state
- **Call context**: Called through `g_pFlattenedSerializers` vtable pointer after allocating and initializing a `CNetworkFieldScratchData` object
- **Parameters**: `(this, network_field_scratch_data, entity_system_field)` where `this` is the `g_pFlattenedSerializers` global pointer
- **Return**: Pointer stored back into the entity system structure

## VTable Information

### CNetworkMessages (SetNetworkSerializationContextData)

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the `CEntitySystem_Activate` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET_A> / 8`.

### CFlattenedSerializers (CreateFieldChangedEventQueue)

- **VTable Name**: `CFlattenedSerializers`
- **VTable Offset**: Changes with game updates. Extract from the `CEntitySystem_Activate` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET_B> / 8`.

## Identification Pattern

Both functions are identified from `CEntitySystem_Activate`:

1. The xref string `"EntitySystem - Class Tables"` is passed to `COM_TimestampedLog`
2. A null check on `g_pNetworkMessages` follows
3. The first virtual call after the null check at `vtable + <VFUNC_OFFSET_A>` is `SetNetworkSerializationContextData`
4. The call passes `"string_t_table"` as the second argument
5. Further down, after `CNetworkFieldScratchData` allocation, a virtual call through `g_pFlattenedSerializers` at `vtable + <VFUNC_OFFSET_B>` is `CreateFieldChangedEventQueue`
6. The `CreateFieldChangedEventQueue` call takes the newly allocated scratch data and an entity system field as arguments

This is robust because:
- `CEntitySystem_Activate` is reliably found via xref string `"EntitySystem - Class Tables"`
- The `SetNetworkSerializationContextData` vfunc call pattern through `g_pNetworkMessages` with `"string_t_table"` is distinctive
- The `CreateFieldChangedEventQueue` vfunc call through `g_pFlattenedSerializers` follows a distinctive `CNetworkFieldScratchData` allocation pattern
- Both calls appear in a well-defined sequence within the same function

## Output YAML Format

The output YAML filenames depend on the platform:
- `server.dll` -> `CNetworkMessages_SetNetworkSerializationContextData.windows.yaml`, `CFlattenedSerializers_CreateFieldChangedEventQueue.windows.yaml`
- `libserver.so` -> `CNetworkMessages_SetNetworkSerializationContextData.linux.yaml`, `CFlattenedSerializers_CreateFieldChangedEventQueue.linux.yaml`
