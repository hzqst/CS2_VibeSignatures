---
name: find-CSource2GameEntities_CheckTransmit-AND-CCheckTransmitInfo
description: Find and identify the CSource2GameEntities::CheckTransmit (virtual function) and CCheckTransmitInfo (struct) in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CSource2GameEntities::CheckTransmit function by searching for the assertion string pattern and analyzing xrefs.
---

# Find CSource2GameEntities::CheckTransmit

Locate `CSource2GameEntities::CheckTransmit` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Search for Assertion String

Search for the function name string in the binary:

```
mcp__ida-pro-mcp__find_regex pattern="CSource2GameEntities::CheckTransmit"
```

Expected result: A string like `"CSource2GameEntities::CheckTransmit(), C:\buildworker\csgo_rel_win64\build\src\game\server\gameinterface.cpp:XXXX"`

### 2. Find Cross-References to String

Get xrefs to the string address found in step 1:

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_address>"
```

The xref should point to a function - this is `CSource2GameEntities::CheckTransmit`.

### 3. Verify Function Pattern (Optional)

Decompile the function to verify it matches the expected pattern:

```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

#### Cross-Platform Identification Pattern

The function is a virtual function that handles entity transmission/visibility checks. Key characteristics:

| Platform | Characteristics |
|----------|-----------------|
| Windows  | References assertion string directly, complex visibility logic |
| Linux    | Same pattern, string path differs (`/build/src/game/server/gameinterface.cpp`) |

**Common identifying features:**
- References `"CSource2GameEntities::CheckTransmit()"` assertion string
- Part of CSource2GameEntities vtable
- Handles entity transmission/visibility checking

### 4. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CSource2GameEntities::CheckTransmit"}]}
```

### 5. Find VTable Offset and Index

**ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.

VTable class name: `CSource2GameEntities`

### 6. Generate and Validate Unique Signature

**DO NOT** use `find_bytes` as it won't work for function.
**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 7. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CSource2GameEntities_CheckTransmit`
- `func_addr`: The function address
- `func_sig`: The validated signature from step 6

VTable parameters:
- `vtable_name`: `CSource2GameEntities`
- `vfunc_offset`: The offset from step 5
- `vfunc_index`: The index from step 5

### 8. Look for code pattern that access CCheckTransmitInfo::m_nPlayerSlot

Look for following code pattern in `CSource2GameEntities_CheckTransmit`

Windows:

```c
    do
    {
        pInfo = a2[v24];
        v36 = sub_180BC3D60(*(_DWORD *)(pInfo + 576));
        if ( !v36 || v36 != v31 )
        {
            v37 = 0LL;
            if ( v34 > 0 )
            {
            do
            {
                v38 = *(_QWORD *)pInfo;
                sub_1811957A0(*(_QWORD *)&v77[8 * v37++], &v85);
                *(_DWORD *)(v38 + 4 * ((__int64)v85 >> 5)) &= ~(1 << (v85 & 0x1F));
            }
            while ( v37 < v34 );
            v31 = v68;
            }
        }
        ++v24;
    }
    while ( v24 < v7 );
```

Linux:

```c
  do
  {
    v20 = *(_QWORD *)(a2 + 8 * v19);
    v21 = sub_15CC080(*(unsigned int *)(v20 + 576));
    LOWORD(v22) = v147 & 0x7FFF;
    if ( !v21 )
      goto LABEL_33;
    v23 = (int)v162;
```

where `a2` is `CCheckTransmitInfo** ppInfoList`, `a3` is ` int infoCount`

the `*(int *)(v20 + 576)` is `CCheckTransmitInfo::m_nPlayerSlot`

* The offset 576 (0x240) can change on game update.

### 9. Write Struct Members for CCheckTransmitInfo as YAML

**ALWAYS** Use SKILL `/write-struct-as-yaml` to write CCheckTransmitInfo's struct member information:

For `CCheckTransmitInfo.{platform}.yaml`:
- Offset `0x240`: `m_nPlayerSlot` (size 4)

## Function Characteristics

- **VTable Index**: ~12 (may vary by platform and game version)
- **VTable Offset**: ~0x60 (may vary by platform and game version)
- **Parameters**: `(this, ...)` - handles entity transmission checks
- **Purpose**: Determines which entities should be transmitted to clients based on visibility and other criteria

### Platform Differences

| Aspect | Windows | Linux |
|--------|---------|-------|
| String path | `C:\buildworker\csgo_rel_win64\...` | `/build/src/game/server/...` |
| VTable index | ~12 | May differ slightly |

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CSource2GameEntities_CheckTransmit.windows.yaml`
- `server.so` → `CSource2GameEntities_CheckTransmit.linux.yaml`

### Example Output

```yaml
func_va: 0x180c8b2b0       # Virtual address - changes with game updates
func_rva: 0xc8b2b0         # Relative virtual address - changes with game updates
func_size: 0x8c1           # Function size in bytes - changes with game updates
func_sig: 48 8B C4 ...     # Unique byte signature - changes with game updates
vtable_name: CSource2GameEntities
vfunc_offset: 0x60         # Offset from vtable start - changes with game updates
vfunc_index: 12            # vtable index - changes with game updates
```
