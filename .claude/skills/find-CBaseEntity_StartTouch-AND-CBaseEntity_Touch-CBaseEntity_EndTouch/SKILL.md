---
name: find-CBaseEntity_StartTouch-AND-CBaseEntity_Touch-CBaseEntity_EndTouch
description: Find and identify the CBaseEntity_StartTouch, CBaseEntity_Touch, and CBaseEntity_EndTouch virtual functions in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate these touch-related virtual functions by searching for the "INVALID CGameEventStartTouchCollideAdaptor" string reference and analyzing the touch event handler functions.
---

# Find CBaseEntity_StartTouch, CBaseEntity_Touch, and CBaseEntity_EndTouch

Locate these touch-related virtual functions in CS2 `server.dll` or `server.so` using IDA Pro MCP tools.

## Method

### 1. Search for Debug String

Search for the debug string used in the touch event handler:

```
mcp__ida-pro-mcp__find_regex pattern="INVALID CGameEventStartTouchCollideAdaptor"
```

### 2. Find Cross-References

Get cross-references to the string:

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
```

This will lead to a large function that processes touch events.

### 3. Decompile and Analyze the Touch Event Handler

```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

#### Locate helper function that calls into StartTouch+Touch

Look for a call with 4 args in the decompiled code:

Windows:

```cpp
sub_180XXXXXX(v12, v16, v18, v8);
```

Linux:

```cpp
sub_1XXXXXX(v8, v13, (__int64)v45, (__int64)v6);
```

The `sub_180XXXXXX` or `sub_1XXXXXX` should match following pattern:

Windows:

```cpp
double __fastcall sub_180D1AEE0(_QWORD *a1, _QWORD *a2, __int64 a3, __int64 a4)
{
  __int64 v8; // rax
  _BYTE v10[40]; // [rsp+20h] [rbp-28h] BYREF

  v8 = (*(__int64 (__fastcall **)(_QWORD, _BYTE *))(**(_QWORD **)(a4 + 8) + 408LL))(*(_QWORD *)(a4 + 8), v10);
  sub_18053B9A0(&unk_181BE1700, v8, a3);
  qword_181BE1708 = (__int64)a2;
  qword_181EC0DA0 = a4;
  if ( a2 && (*(_DWORD *)(a1[2] + 48LL) & 0x200) == 0 && (*(_DWORD *)(a2[2] + 48LL) & 0x200) == 0 )
  {
    (*(void (__fastcall **)(_QWORD *, _QWORD *))(*a1 + 1176LL))(a1, a2); //StartTouch
    (*(void (__fastcall **)(_QWORD *, _QWORD *))(*a1 + 1184LL))(a1, a2); //Touch
  }
  if ( a1 && (*(_DWORD *)(a2[2] + 48LL) & 0x200) == 0 && (*(_DWORD *)(a1[2] + 48LL) & 0x200) == 0 )
  {
    (*(void (__fastcall **)(_QWORD *, _QWORD *))(*a2 + 1176LL))(a2, a1); //StartTouch
    (*(void (__fastcall **)(_QWORD *, _QWORD *))(*a2 + 1184LL))(a2, a1); //Touch
  }
  return sub_18128D070(&unk_181BE1700);
}
```

Linux:

```cpp
__int64 __fastcall sub_177BE90(_QWORD *a1, _QWORD *a2, __int64 a3, __int64 a4)
{
  _BYTE v7[80]; // [rsp+0h] [rbp-50h] BYREF

  (*(void (__fastcall **)(_BYTE *))(**(_QWORD **)(a4 + 8) + 408LL))(v7);
  sub_E31300(&xmmword_25A3B00, v7, a3);
  *((_QWORD *)&xmmword_25A3B00 + 1) = a2;
  qword_25A3AF8 = a4;
  if ( a2 )
  {
    if ( (*(_BYTE *)(a1[2] + 49LL) & 2) != 0 || (*(_BYTE *)(a2[2] + 49LL) & 2) != 0 )
      return sub_1B5AAC0(&xmmword_25A3B00);
    (*(void (__fastcall **)(_QWORD *, _QWORD *))(*a1 + 1168LL))(a1, a2); //StartTouch
    (*(void (__fastcall **)(_QWORD *, _QWORD *))(*a1 + 1176LL))(a1, a2); //Touch
  }
  if ( (*(_BYTE *)(a2[2] + 49LL) & 2) == 0 && (*(_BYTE *)(a1[2] + 49LL) & 2) == 0 )
  {
    (*(void (__fastcall **)(_QWORD *, _QWORD *))(*a2 + 1168LL))(a2, a1); //StartTouch
    (*(void (__fastcall **)(_QWORD *, _QWORD *))(*a2 + 1176LL))(a2, a1); //Touch
  }
  return sub_1B5AAC0(&xmmword_25A3B00);
}
```

#### Pattern for EndTouch Helper Function

Find a call with comment or condition for "EndTouch":

Windows:

```cpp
if ( (*(_BYTE *)v8 & 0x10) != 0 )
    sub_180XXXXXX(v12, v16);
```

Linux:

```cpp
LABEL_4:
        if ( (v14 & 0x10) == 0 )
          goto LABEL_5;
LABEL_43:
        v5 += 256LL;
        sub_1XXXXXX((__int64)v8, (__int64)v13);
```

Windows:

```cpp
__int64 __fastcall sub_180D1AEA0(__int64 a1, __int64 a2)
{
  (*(void (__fastcall **)(__int64))(*(_QWORD *)a1 + 1192LL))(a1); //EndTouch
  return (*(__int64 (__fastcall **)(__int64, __int64))(*(_QWORD *)a2 + 1192LL))(a2, a1);
}
```

Linux:

```cpp
__int64 __fastcall sub_1XXXXXX(__int64 a1, __int64 a2)
{
  (*(void (__fastcall **)(__int64))(*(_QWORD *)a1 + 1184LL))(a1);  // EndTouch
  return (*(__int64 (__fastcall **)(__int64, __int64))(*(_QWORD *)a2 + 1184LL))(a2, a1);
}
```

### 4. Decompile StartTouch+Touch Helper Function

```
mcp__ida-pro-mcp__decompile addr="<starttouch_helper_addr>"
```

Look for these virtual function calls:

```cpp
// Offset 1176 = CBaseEntity_StartTouch (vtable index 147)
(*(void (__fastcall **)(_QWORD *, _QWORD *))(*a1 + 1176LL))(a1, a2);

// Offset 1184 = CBaseEntity_Touch (vtable index 148)
(*(void (__fastcall **)(_QWORD *, _QWORD *))(*a1 + 1184LL))(a1, a2);
```

### 5. Decompile EndTouch Helper Function

```
mcp__ida-pro-mcp__decompile addr="<endtouch_helper_addr>"
```

Look for this virtual function call:

```cpp
// Offset 1192 = CBaseEntity_EndTouch (vtable index 149)
(*(void (__fastcall **)(__int64))(*(_QWORD *)a1 + 1192LL))(a1);
```

### 6. Get CBaseEntity VTable 

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CBaseEntity`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract these values for subsequent steps:
- `vtable_va`: The vtable start address (use as `<VTABLE_START>`)
- `vtable_numvfunc`: The valid vtable entry count (last valid index = count - 1)
- `vtable_entries`: An array of virtual functions starting from vtable[0]

### 7. Read CBaseEntity VTable Entries

Read the virtual function addresses from the CBaseEntity vtable:

* Index 147, 148, 149 can change on game update.

```python
# Index 147 (offset 1176): CBaseEntity_StartTouch
# Index 148 (offset 1184): CBaseEntity_Touch
# Index 149 (offset 1192): CBaseEntity_EndTouch
vtable_addr = <CBaseEntity_vtable_addr>
starttouch_addr = vtable_addr + 147 * 8  # Read pointer at this address
touch_addr = vtable_addr + 148 * 8       # Read pointer at this address
endtouch_addr = vtable_addr + 149 * 8    # Read pointer at this address
```

```
mcp__ida-pro-mcp__get_int queries=[{"addr": "<starttouch_ptr_addr>", "ty": "u64le"}, {"addr": "<touch_ptr_addr>", "ty": "u64le"}, {"addr": "<endtouch_ptr_addr>", "ty": "u64le"}]
```

### 8. Verify by Decompiling the VTable Functions

Decompile each function to verify it matches the expected pattern:

#### CBaseEntity_StartTouch Pattern

```cpp
// Calls virtual function at offset 1176 on m_pParentEntity or similar
result = *(_QWORD **)(a1 + 632);  // Get some entity pointer
v4 = result[7];
if ( v4 )
{
    result = sub_XXXXXX(v4);  // GetEntity or similar
    if ( result )
    {
        // Check IsTouching (offset 0x4B0 = 1200)
        result = (*(__int64 (__fastcall **)(_QWORD *))(*result + 1200LL))(result);
        if ( result )
            // Forward to StartTouch (offset 0x498 = 1176)
            return (*(__int64 (__fastcall **)(_QWORD *, __int64))(*v5 + 1176LL))(v5, a2);
    }
}
```

#### CBaseEntity_Touch Pattern

```cpp
// Has optional callback call before the main logic
v2 = *(void (**)(void))(a1 + 696);  // Optional touch callback
if ( v2 )
    v2();
// Then similar forwarding pattern with offset 0x4A0 = 1184
```

#### CBaseEntity_EndTouch Pattern

```cpp
// Similar to StartTouch but forwards to offset 0x4A8 = 1192
return (*(__int64 (__fastcall **)(_QWORD *, __int64))(*v5 + 1192LL))(v5, a2);
```

### 9. Rename the CBaseEntity Functions

```
mcp__ida-pro-mcp__rename batch={"func": [
    {"addr": "<starttouch_addr>", "name": "CBaseEntity_StartTouch"},
    {"addr": "<touch_addr>", "name": "CBaseEntity_Touch"},
    {"addr": "<endtouch_addr>", "name": "CBaseEntity_EndTouch"}
]}
```

### 10. Generate Signatures for All Functions

**DO NOT** use `find_bytes` as it won't work for function.
**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for each function.

#### Signature Guidance

- **CBaseEntity_StartTouch**: Look for the final virtual call with offset `0x498` (98 04 00 00)
- **CBaseEntity_Touch**: Has unique prologue with offset `0x2B8` and `FF D0` (call rax)
- **CBaseEntity_EndTouch**: Look for the final virtual call with offset `0x4A8` (A8 04 00 00)

### 11. Write YAML Files

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for each function.

Required parameters for each function:

#### CBaseEntity_StartTouch
- `func_name`: `CBaseEntity_StartTouch`
- `vtable_name`: `CBaseEntity`
- `vfunc_offset`: `0x498`
- `vfunc_index`: `147`

#### CBaseEntity_Touch
- `func_name`: `CBaseEntity_Touch`
- `vtable_name`: `CBaseEntity`
- `vfunc_offset`: `0x4A0`
- `vfunc_index`: `148`

#### CBaseEntity_EndTouch
- `func_name`: `CBaseEntity_EndTouch`
- `vtable_name`: `CBaseEntity`
- `vfunc_offset`: `0x4A8`
- `vfunc_index`: `149`

## Function Characteristics

### CBaseEntity_StartTouch

- **VTable**: CBaseEntity
- **VTable Index**: 147 (offset 0x498 = 1176), can change on game update
- **Prototype**: `void CBaseEntity::StartTouch(CBaseEntity* pOther)`
- **Purpose**: Called when an entity starts touching another entity
- **Implementation**: Forwards the call to the parent entity's StartTouch if applicable

### CBaseEntity_Touch

- **VTable**: CBaseEntity
- **VTable Index**: 148 (offset 0x4A0 = 1184), can change on game update
- **Prototype**: `void CBaseEntity::Touch(CBaseEntity* pOther)`
- **Purpose**: Called continuously while entities are touching
- **Implementation**: May call optional touch callback, then forwards to parent entity's Touch

### CBaseEntity_EndTouch

- **VTable**: CBaseEntity
- **VTable Index**: 149 (offset 0x4A8 = 1192), can change on game update
- **Prototype**: `void CBaseEntity::EndTouch(CBaseEntity* pOther)`
- **Purpose**: Called when an entity stops touching another entity
- **Implementation**: Forwards the call to the parent entity's EndTouch if applicable

## VTable Offset Reference

| Function | VTable | Byte Offset | Index | Virtual Call Pattern |
|----------|--------|-------------|-------|---------------------|
| CBaseEntity_StartTouch | CBaseEntity | 1176 (0x498) | 147 | `41 FF 90 98 04 00 00` |
| CBaseEntity_Touch | CBaseEntity | 1184 (0x4A0) | 148 | `41 FF 90 A0 04 00 00` |
| CBaseEntity_EndTouch | CBaseEntity | 1192 (0x4A8) | 149 | `41 FF 90 A8 04 00 00` |

## Output YAML Format

The output YAML filenames depend on the platform:
- `server.dll` -> `CBaseEntity_StartTouch.windows.yaml`, `CBaseEntity_Touch.windows.yaml`, `CBaseEntity_EndTouch.windows.yaml`
- `server.so` -> `CBaseEntity_StartTouch.linux.yaml`, `CBaseEntity_Touch.linux.yaml`, `CBaseEntity_EndTouch.linux.yaml`

```yaml
func_va: 0x180XXXXXX      # Virtual address - changes with game updates
func_rva: 0xXXXXXX        # Relative virtual address - changes with game updates
func_size: 0xXX           # Function size in bytes - changes with game updates
func_sig: XX XX XX XX XX  # Unique byte signature - changes with game updates
vtable_name: CBaseEntity
vfunc_offset: 0x498       # Offset from vtable start - changes with game updates
vfunc_index: 147          # vtable index - changes with game updates
```

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- The touch event handler function uses helper functions to call these virtual functions
- CBaseEntity_StartTouch and CBaseEntity_EndTouch have very similar bytecode - the distinguishing factor is the final virtual call offset (0x498 vs 0x4A8)
- CBaseEntity_Touch has a unique callback call pattern before the forwarding logic
- When analyzing Linux binaries, vtable offsets may differ slightly due to ABI differences
