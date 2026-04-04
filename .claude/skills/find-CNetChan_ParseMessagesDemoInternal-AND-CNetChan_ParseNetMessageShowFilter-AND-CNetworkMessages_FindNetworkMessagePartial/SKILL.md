---
name: find-CNetChan_ParseMessagesDemoInternal-AND-CNetChan_ParseNetMessageShowFilter-AND-CNetworkMessages_FindNetworkMessagePartial
description: |
  Find and identify CNetChan_ParseMessagesDemoInternal, CNetChan_ParseNetMessageShowFilter, and CNetworkMessages_FindNetworkMessagePartial
  in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 networksystem.dll or libnetworksystem.so to locate these
  functions by decompiling CNetChan_ParseMessagesDemo and following the call chain.
  Trigger: CNetChan_ParseMessagesDemoInternal, CNetChan_ParseNetMessageShowFilter, CNetworkMessages_FindNetworkMessagePartial
disable-model-invocation: true
---

# Find CNetChan_ParseMessagesDemoInternal, CNetChan_ParseNetMessageShowFilter, and CNetworkMessages_FindNetworkMessagePartial

Locate `CNetChan_ParseMessagesDemoInternal`, `CNetChan_ParseNetMessageShowFilter`, and `CNetworkMessages_FindNetworkMessagePartial` in CS2 `networksystem.dll` or `libnetworksystem.so` using IDA Pro MCP tools.

## Method

### 1. Get CNetChan_ParseMessagesDemo Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetChan_ParseMessagesDemo`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `func_va` for subsequent steps.

### 2. Get CNetworkMessages Vtable Info

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CNetworkMessages`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `vtable_va` for subsequent steps.

### 3. Decompile CNetChan_ParseMessagesDemo

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 4. Identify CNetChan_ParseMessagesDemoInternal

In the decompiled output, look for the characteristic code pattern. `CNetChan_ParseMessagesDemoInternal` is the **last call** in the function, appearing in the return statement:

```c
bool __fastcall CNetChan_ParseMessagesDemo(__int64 a1, __int64 a2)
{
  //........others
  if ( *v5 && (unsigned __int8)LoggingSystem_IsChannelEnabled((unsigned int)g_pLoggingChanel, 2LL) )
  {
    v6 = &unk_XXXXXXXX;
    v7 = (*(_DWORD *)(a2 + 44) - *(_DWORD *)(a2 + 48)) >> 3;
    if ( *(_QWORD *)(a1 + 29368) )
      v6 = *(void **)(a1 + 29368);
    v8 = Plat_FloatTime();
    v11 = v7;
    LoggingSystem_Log(
      (unsigned int)g_pLoggingChanel,
      2LL,
      "%8.3f: %s: ParseMessagesDemo UNRELIABLE %d bytes\n",
      v8,
      v6,
      v11);
  }
  v9 = Plat_FloatTime();
  return (unsigned __int8)sub_XXXXXXXX(          // <-- CNetChan_ParseMessagesDemoInternal
                            a1,
                            a2 + 32,
                            0,
                            v9,
                            0,
                            -1082130432,
                            *(void (__fastcall ***)(_QWORD, __int64))(a2 + 104)) != 0;
}
```

The `sub_XXXXXXXX` in the return statement is `CNetChan_ParseMessagesDemoInternal`.

### 5. Rename CNetChan_ParseMessagesDemoInternal

Check if the function is already renamed:
```
mcp__ida-pro-mcp__lookup_funcs queries="<CNetChan_ParseMessagesDemoInternal_addr>"
```

Rename if still unnamed (`sub_` prefix):
```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<addr>", "name": "CNetChan_ParseMessagesDemoInternal"}]}
```

### 6. Generate Signature for CNetChan_ParseMessagesDemoInternal

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CNetChan_ParseMessagesDemoInternal`.

### 7. Write YAML for CNetChan_ParseMessagesDemoInternal

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetChan_ParseMessagesDemoInternal`
- `func_addr`: The function address from step 4
- `func_sig`: The validated signature from step 6

Note: This is NOT a virtual function, so no vtable parameters are needed.

### 8. Decompile CNetChan_ParseMessagesDemoInternal

```
mcp__ida-pro-mcp__decompile addr="<CNetChan_ParseMessagesDemoInternal_addr>"
```

### 9. Identify CNetChan_ParseNetMessageShowFilter

In the decompiled output, look for `CNetChan_ParseNetMessageShowFilter`. It is called **twice** in the function body, early in the function:

```c
  sub_XXXXXXXX(v17, &v97, (int *)&v107);             // <-- CNetChan_ParseNetMessageShowFilter (1st call)
  v18 = (char **)sub_YYYYYYYY((__int64)&unk_ZZZZZZZZ, -1);
  if ( !v18 )
    v18 = *(char ***)(qword_ZZZZZZZZ + 8);
  v19 = *v18;
  v20 = (char *)&unk_XXXXXXXX;
  if ( v19 )
    v20 = v19;
  sub_XXXXXXXX(v20, &v103, (int *)&v105);             // <-- CNetChan_ParseNetMessageShowFilter (2nd call)
```

Both calls share the **same function address** (`sub_XXXXXXXX`). The function takes 3 parameters: `(const char*, int*, int*)`.

### 10. Rename CNetChan_ParseNetMessageShowFilter

Check if already renamed:
```
mcp__ida-pro-mcp__lookup_funcs queries="<CNetChan_ParseNetMessageShowFilter_addr>"
```

Rename if still unnamed:
```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<addr>", "name": "CNetChan_ParseNetMessageShowFilter"}]}
```

### 11. Generate Signature for CNetChan_ParseNetMessageShowFilter

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CNetChan_ParseNetMessageShowFilter`.

### 12. Write YAML for CNetChan_ParseNetMessageShowFilter

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetChan_ParseNetMessageShowFilter`
- `func_addr`: The function address from step 9
- `func_sig`: The validated signature from step 11

Note: This is NOT a virtual function, so no vtable parameters are needed.

### 13. Decompile CNetChan_ParseNetMessageShowFilter

```
mcp__ida-pro-mcp__decompile addr="<CNetChan_ParseNetMessageShowFilter_addr>"
```

### 14. Identify CNetworkMessages_FindNetworkMessagePartial VFunc Call

In the decompiled output, look for the **virtual function call through `g_NetworkMessages`**:

```c
if ( v21 != v20 + 8LL * v6 )
  {
    v22 = (const char **)(v20 + 8LL * v6);
    do
    {
      v23 = (const char *)&unk_XXXXXXXX;
      if ( *v19 )
        v23 = *v19;
      v24 = (*(__int64 (__fastcall **)(__int64, const char *))(*(_QWORD *)&g_NetworkMessages + <VFUNC_OFFSET>))(&g_NetworkMessages, v23);
      if ( v24 )
      {
```

The `<VFUNC_OFFSET>` (e.g. `0xXX`) is the vfunc offset of `CNetworkMessages_FindNetworkMessagePartial`.

Extract `<VFUNC_OFFSET>` from the call site. Calculate the vtable index: `index = <VFUNC_OFFSET> / 8`.

### 15. Resolve Actual Function Address from Vtable

Using the `vtable_va` from step 2 and the `<VFUNC_OFFSET>` from step 14, read the actual function pointer:

```
mcp__ida-pro-mcp__get_int queries={"addr": "<vtable_va + VFUNC_OFFSET>", "ty": "u64le"}
```

The returned value is the address of the `CNetworkMessages_FindNetworkMessagePartial` implementation.

### 16. Rename CNetworkMessages_FindNetworkMessagePartial

Check if already renamed:
```
mcp__ida-pro-mcp__lookup_funcs queries="<resolved_func_addr>"
```

Rename if still unnamed:
```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<resolved_func_addr>", "name": "CNetworkMessages_FindNetworkMessagePartial"}]}
```

### 17. Generate Signature for CNetworkMessages_FindNetworkMessagePartial

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CNetworkMessages_FindNetworkMessagePartial`.

### 18. Write YAML for CNetworkMessages_FindNetworkMessagePartial

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_FindNetworkMessagePartial`
- `func_addr`: The resolved function address from step 15
- `func_sig`: The validated signature from step 17

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET>` in hex from step 14
- `vfunc_index`: The calculated index from step 14

## Function Characteristics

### CNetChan_ParseMessagesDemoInternal

- **Type**: Regular function (non-virtual)
- **Purpose**: Internal implementation of demo message parsing for a network channel
- **Called from**: `CNetChan_ParseMessagesDemo` - the last call in its return statement
- **Parameters**: `(CNetChan* this, buf_ptr, int, float time, int, float, callback_vtable)`

### CNetChan_ParseNetMessageShowFilter

- **Type**: Regular function (non-virtual)
- **Purpose**: Parses network message show/filter configuration (determines which messages to display/filter)
- **Called from**: `CNetChan_ParseMessagesDemoInternal` - called twice early in the function
- **Parameters**: `(const char* filter_string, int* out_param1, int* out_param2)`

### CNetworkMessages_FindNetworkMessagePartial

- **Type**: Virtual function of `CNetworkMessages`
- **Purpose**: Finds a registered network message by partial name match
- **Called from**: `CNetChan_ParseNetMessageShowFilter` - called through `g_NetworkMessages` vtable
- **Parameters**: `(this, const char* partial_name)` where `this` is the `g_NetworkMessages` global

## VTable Information (CNetworkMessages_FindNetworkMessagePartial only)

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the `CNetChan_ParseNetMessageShowFilter` decompiled code.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET> / 8`.

## DLL Information

- **DLL**: `networksystem.dll` (Windows) / `libnetworksystem.so` (Linux)

## Notes

- `CNetChan_ParseMessagesDemoInternal` and `CNetChan_ParseNetMessageShowFilter` are regular functions, NOT virtual functions
- `CNetworkMessages_FindNetworkMessagePartial` IS a virtual function of `CNetworkMessages` - it requires vtable parameters
- The call chain is: `CNetChan_ParseMessagesDemo` -> `CNetChan_ParseMessagesDemoInternal` -> `CNetChan_ParseNetMessageShowFilter` -> `CNetworkMessages_FindNetworkMessagePartial` (vfunc)

## Output YAML Format

The output YAML filenames depend on the platform:
- `networksystem.dll` -> `CNetChan_ParseMessagesDemoInternal.windows.yaml`, `CNetChan_ParseNetMessageShowFilter.windows.yaml`, `CNetworkMessages_FindNetworkMessagePartial.windows.yaml`
- `libnetworksystem.so` -> `CNetChan_ParseMessagesDemoInternal.linux.yaml`, `CNetChan_ParseNetMessageShowFilter.linux.yaml`, `CNetworkMessages_FindNetworkMessagePartial.linux.yaml`
