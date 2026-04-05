---
name: find-CNetworkMessages_RegisterSchemaTypeOverride
description: |
  Find and identify the CNetworkMessages_RegisterSchemaTypeOverride virtual function call in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the RegisterSchemaTypeOverride vfunc call
  by cross-referencing the "CEntityHandle" and "ehandle" strings and identifying the virtual call through g_pNetworkMessages.
  Trigger: CNetworkMessages_RegisterSchemaTypeOverride
disable-model-invocation: true
---

# Find CNetworkMessages_RegisterSchemaTypeOverride

Locate `CNetworkMessages_RegisterSchemaTypeOverride` vfunc call in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

### 1. Search for the "CEntityHandle" String

```
mcp__ida-pro-mcp__find_regex pattern="CEntityHandle"
```

Find the exact string `"CEntityHandle"` and get its address.

### 2. Find Cross-References to "CEntityHandle"

```
mcp__ida-pro-mcp__xrefs_to addrs="<CEntityHandle_string_addr>"
```

Collect all functions that reference the `"CEntityHandle"` string.

### 3. Search for the "ehandle" String

```
mcp__ida-pro-mcp__find_regex pattern="ehandle"
```

Find the exact string `"ehandle"` and get its address.

### 4. Find Cross-References to "ehandle"

```
mcp__ida-pro-mcp__xrefs_to addrs="<ehandle_string_addr>"
```

Collect all functions that reference the `"ehandle"` string.

### 5. Find the Intersection

Find the function that appears in **both** xref sets. This is the function that calls `CNetworkMessages_RegisterSchemaTypeOverride` through the `g_pNetworkMessages` vtable. It looks like:

```c
__int64 sub_XXXXXXXX()
{
  return (*(__int64 (__fastcall **)(__int64, const char *, __int64, const char *))(*(_QWORD *)g_pNetworkMessages
                                                                                 + <VFUNC_OFFSET>))(
           g_pNetworkMessages,
           "CEntityHandle",
           2519767464LL,
           "ehandle");
}
```

Decompile the intersection function to confirm the pattern and extract `<VFUNC_OFFSET>` (e.g., `272LL` = `0x110`).

Calculate the vtable index: `index = <VFUNC_OFFSET> / 8`.

### 6. Generate VFunc Offset Signature

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<VFUNC_OFFSET>]` or `call qword ptr [rcx+<VFUNC_OFFSET>]` at the call site.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_RegisterSchemaTypeOverride`, with `inst_addr` and `vfunc_offset` from this step.

### 7. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_RegisterSchemaTypeOverride`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 6

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET>` in hex (e.g. `0x110`)
- `vfunc_index`: The calculated index (e.g. `34`)

## Function Characteristics

- **Purpose**: Registers a schema type override for network serialization, mapping a schema type name to a network-compatible type alias
- **Called from**: A small wrapper function in server.dll that passes `"CEntityHandle"` and `"ehandle"` to the virtual call
- **Call context**: Called through `g_pNetworkMessages` vtable pointer with schema type name, hash, and override name
- **Parameters**: `(this, "CEntityHandle", hash, "ehandle")` where `this` is the `g_pNetworkMessages` global pointer

## VTable Information

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the decompiled intersection function.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET> / 8`.

## Identification Pattern

The function is identified by locating the intersection of xrefs to two unique strings:
1. Find all functions referencing `"CEntityHandle"`
2. Find all functions referencing `"ehandle"`
3. The intersection function contains a virtual call through `g_pNetworkMessages` at `vtable + <VFUNC_OFFSET>`
4. That `<VFUNC_OFFSET>` is the vfunc offset for `RegisterSchemaTypeOverride`

This is robust because:
- Both `"CEntityHandle"` and `"ehandle"` are distinctive strings with limited xrefs
- Their intersection uniquely identifies the wrapper function
- The virtual call pattern through `g_pNetworkMessages` is distinctive
- No byte-pattern signatures needed for discovery -- the approach is entirely semantic

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `CNetworkMessages_RegisterSchemaTypeOverride.windows.yaml`
- `libserver.so` -> `CNetworkMessages_RegisterSchemaTypeOverride.linux.yaml`
