---
name: find-CBaseEntity_GetHammerUniqueId
description: Find and identify the CBaseEntity_GetHammerUniqueId virtual function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the GetHammerUniqueId vfunc by searching for the "hammerUniqueId" string and identifying the function that calls a vtable method guarded by an OR condition, then writes the result to a CUtlString member.
disable-model-invocation: true
---

# Find CBaseEntity_GetHammerUniqueId

Locate `CBaseEntity_GetHammerUniqueId` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Search for Reference String

Search for the string `"hammerUniqueId"`:

```
mcp__ida-pro-mcp__find_regex pattern="hammerUniqueId"
```

Note the string address.

### 2. Find Cross-References

Get xrefs to the string address:

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_address>"
```

There may be multiple xrefs. The target function is a small function (~0x146 bytes) that matches the code pattern below. Decompile each candidate to find the match.

### 3. Identify the Target Function

Decompile each candidate and look for this code pattern:

Windows binary:

```c
void __fastcall sub_180XXXXXX(__int64 a1, _QWORD *a2)
{
  //...

  if ( (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)qword_XXXXXXXXX + 176LL))(qword_XXXXXXXXX)
    || (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)a1 + <vfunc_offset>LL))(a1) )  // <-- vfunc_offset for CBaseEntity_GetHammerUniqueId
  {
    v7[0] = -1453088712LL;
    v7[1] = "hammerUniqueId";
    v5 = (_QWORD *)sub_XXXXXXXXX(a2, (int *)v7, 0LL);
    if ( v5 && ((*(_BYTE *)v5 >> 2) & 0xF) == 6 )
      v6 = sub_XXXXXXXXX(v5, (__int64)byte_XXXXXXXXX);
    else
      v6 = byte_XXXXXXXXX;
    CUtlString::Set((CUtlString *)(a1 + <member_offset>), v6);
  }
}
```

Linux binary:

```c
__int64 __fastcall sub_XXXXXX(_BYTE *a1, __int64 a2)
{
  //...

  if ( (*(unsigned __int8 (__fastcall **)(_QWORD *))(*qword_XXXXXXX + 184LL))(qword_XXXXXXX)
    || (result = (*(__int64 (__fastcall **)(_BYTE *))(*(_QWORD *)a1 + <vfunc_offset>LL))(a1), (_BYTE)result) )  // <-- vfunc_offset for CBaseEntity_GetHammerUniqueId
  {
    v8 = -1453088712LL;
    v9 = "hammerUniqueId";
    v6 = (_WORD *)sub_XXXXXXX(a2, &v8, 0LL);
    v7 = &byte_XXXXXXX;
    if ( v6 )
    {
      if ( ((*v6 >> 2) & 0xF) == 6 )
        v7 = (const char *)sub_XXXXXXX(v6, &byte_XXXXXXX);
    }
    return sub_XXXXXXX(a1 + <member_offset>, v7);
  }
  return result;
}
```

Key identifying traits:
- OR condition: a global vtable call (offset ~176/184) **OR** a vtable call on `a1` at `<vfunc_offset>`
- Constant `-1453088712` (0xA9540B48) used as a hash/key
- String `"hammerUniqueId"` stored immediately after
- Result written via `CUtlString::Set` to a member of `a1`

Extract `<vfunc_offset>` from the **second branch** of the OR condition (the call on `a1`). This is the `CBaseEntity_GetHammerUniqueId` vtable offset.

Note the instruction address of that vtable call for signature generation.

Calculate:
- **VTable Offset**: The value from the pattern (e.g., Windows: 888 = 0x378, Linux: 880 = 0x370)
- **VTable Index**: offset / 8 (e.g., 888 / 8 = **111**)

### 4. Generate vfunc offset signature for CBaseEntity_GetHammerUniqueId

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CBaseEntity_GetHammerUniqueId`, with `inst_addr` and `vfunc_offset` from step 3.

### 5. Write Analysis Results as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for `CBaseEntity_GetHammerUniqueId`.

Required parameters:
- `func_name`: `CBaseEntity_GetHammerUniqueId`
- `vfunc_sig`: `<vfunc_sig>` from step 4

VTable parameters:
- `vtable_name`: `CBaseEntity`
- `vfunc_index`: The vtable index from step 3
- `vfunc_offset`: The vtable offset from step 3

## VTable Information

- **VTable Name**: `CBaseEntity::`vftable'`
- **VTable Mangled Name (Windows)**: `??_7CBaseEntity@@6B@`
- **VTable Mangled Name (Linux)**: `_ZTV11CBaseEntity`
- **VTable Index**: 111 - This can change when game updates.
- **VTable Offset**: 0x378 (111 * 8 = 888) - This can change when game updates.

* Note that for `server.so`, the first 16 bytes of "vftable" are for RTTI. The real vftable = `_ZTV11CBaseEntity` + `0x10`.

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `CBaseEntity_GetHammerUniqueId.windows.yaml`
- `server.so` -> `CBaseEntity_GetHammerUniqueId.linux.yaml`

```yaml
func_name: CBaseEntity_GetHammerUniqueId
vfunc_sig: <vfunc_sig>
vtable_name: CBaseEntity
vfunc_offset: '0x378'
vfunc_index: 111
```

## Notes

- This virtual function returns a boolean indicating whether the entity has a Hammer unique ID.
- The containing function uses the result to conditionally read a `"hammerUniqueId"` key from KeyValues and store it as a CUtlString member on the entity.
- Windows and Linux have slightly different vfunc offsets due to vtable layout differences (Windows: 888, Linux: 880 in recent builds).
