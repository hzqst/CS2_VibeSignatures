---
name: find-CGameResourceService_BuildResourceManifest
description: Find and identify the CGameResourceService_BuildResourceManifest function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 engine2.dll or libengine2.so to locate the CGameResourceService::BuildResourceManifest function by searching for the log string pattern and analyzing xrefs.
---

# Find CGameResourceService_BuildResourceManifest

Locate `CGameResourceService::BuildResourceManifest` in CS2 engine2.dll or libengine2.so using IDA Pro MCP tools.

## Method

### 1. Search for Log String

Search for the function name string in the binary:

```
mcp__ida-pro-mcp__find_regex pattern="CGameResourceService::BuildResourceManifest\(start\)"
```

Expected results: Multiple strings like:
- `"CGameResourceService::BuildResourceManifest(start) [%d ekv - %s]"`
- `"CGameResourceService::BuildResourceManifest(start) [%d entities - %s]"`
- `"CGameResourceService::BuildResourceManifest(start) [callback 0x%p]"`
- `"CGameResourceService::BuildResourceManifest(start) [manifest group %s]"`

### 2. Find Cross-References to String

Get xrefs to the `CGameResourceService::BuildResourceManifest(start) [%d entities - %s]` variant string address:

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_address>"
```

The xref should point to a function - this is `CGameResourceService::BuildResourceManifest`.

### 3. Verify Function Pattern

Decompile the function to verify it matches the expected pattern:

```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

#### Cross-Platform Identification Pattern

The function handles resource manifest building for entities. Key characteristics:

| Platform | Characteristics |
|----------|-----------------|
| Windows  | References `COM_TimestampedLog` with start/finish messages |
| Linux    | Same pattern, may have slight differences in string format |

**Common identifying features:**
- References `"CGameResourceService::BuildResourceManifest(start) [%d entities - %s]"` log string
- References `"CGameResourceService::BuildResourceManifest(finish) [%d entities - %s]"` log string
- Accesses `CGameResourceService::m_pEntitySystem` at offset 0x58
- Calls a virtual function on `m_pEntitySystem` (vtable index 4, offset 0x20)

**Expected function signature:**
```c
void __fastcall CGameResourceService_BuildResourceManifest(
        CGameResourceService* this,
        unsigned int a2,
        unsigned int entityCount,
        __int64 a4,
        __int64 a5,
        __int64 a6,
        __int64 a7)
```

### 4. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CGameResourceService_BuildResourceManifest"}]}
```

### 5. Generate and Validate Unique Signature

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 6. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CGameResourceService_BuildResourceManifest`
- `func_addr`: The function address
- `func_sig`: The validated signature from step 5

### 7. Generate Struct Offset Signature and Write Struct Member YAML

For each struct member, **ALWAYS** generate a dedicated `offset_sig` first, then write a dedicated YAML file for that member.

For `CGameResourceService::m_pEntitySystem`:
- Offset: `0x58` (size `8`)
- Locate the instruction that accesses this member offset in `CGameResourceService_BuildResourceManifest` (for example: `*(_QWORD *)(a1 + 88)` where `88 = 0x58`)
- Use SKILL `/generate-signature-for-structoffset` with:
  - `inst_addr`: address of the instruction containing offset `0x58`
  - `struct_offset`: `0x58`
- Use SKILL `/write-structoffset-as-yaml` with:
  - `struct_name`: `CGameResourceService`
  - `member_name`: `m_pEntitySystem`
  - `offset`: `0x58`
  - `size`: `8`
  - `offset_sig`: validated signature from `/generate-signature-for-structoffset`

## Function Characteristics

- **Type**: Regular function (not virtual)
- **Parameters**: `(this, a2, entityCount, a4, a5, a6, a7)`
- **Purpose**: Builds resource manifest for entities, delegates to entity system

### Key Code Pattern

```c
// Access m_pEntitySystem at offset 0x58
v16 = *(_QWORD *)(a1 + 88);  // 88 = 0x58, This is CGameResourceService::m_pEntitySystem, and can change on game update.
if (v16)
    // Call virtual function at vtable index 4 (offset 0x20)
    (*(void**)(*v16 + 32))(v16, a2, a3, a4, a5, 0, a7);
```

### Platform Differences

| Aspect | Windows | Linux |
|--------|---------|-------|
| Binary | engine2.dll | libengine2.so |
| m_pEntitySystem offset | 0x58 | 0x58 (verify) |

## Output YAML Format

The output YAML filename depends on the platform:
- `engine2.dll` → `CGameResourceService_BuildResourceManifest.windows.yaml`, `CGameResourceService_m_pEntitySystem.windows.yaml`
- `libengine2.so` → `CGameResourceService_BuildResourceManifest.linux.yaml`, `CGameResourceService_m_pEntitySystem.linux.yaml`
