---
name: find-CGameSceneNode_GetSkeletonInstance
description: |
  Find and identify the CGameSceneNode_GetSkeletonInstance virtual function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the GetSkeletonInstance function in CGameSceneNode vtable.
  Trigger: CGameSceneNode_GetSkeletonInstance, GetSkeletonInstance, skeleton instance
---

# CGameSceneNode_GetSkeletonInstance Function Location Workflow

## Overview

This workflow locates the `CGameSceneNode_GetSkeletonInstance` virtual function in CS2 server binary. This function is called on `CBodyComponentSkeletonInstance::NetworkVar_m_skeletonInstance` (a multiple inheritance object: `CSkeletonInstance`, `CGameSceneNode`, `ISceneAnimatableProceduralBoneTransforms`) to retrieve the `CSkeletonInstance` pointer.

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the DevMsg string:

```
mcp__ida-pro-mcp__find_regex(pattern="\\[%s\\] playing sequence \\[%s\\] at time \\[%f\\]")
```

Expected result: Find string address (e.g., `0x1817731b0` for Windows)

### 2. Find Cross-References

Use `xrefs_to` to find locations that reference this string:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

Expected result: Find the function that references the string

### 3. Decompile and Locate Pattern

Decompile the referencing function and look for this code pattern:

```c
  if ( (unsigned __int8)sub_18119C7E0(*(_QWORD *)(a1 + 16), v14) )
  {
    sub_180878540(&v76, *(unsigned int *)(*(_QWORD *)(a1 + 16) + 56LL));
    sub_18019D560(&v76);
    v15 = &unk_181524F70;
    if ( *a3 )
      v15 = *a3;
    v16 = sub_18119C290(*(_QWORD *)(a2 + 16));
    DevMsg("[%s] playing sequence [%s] at time [%f]\n", v16, v15, v4);
  }
  v17 = CBaseAnimGraph_GetAnimationController(a2);// This is CBaseAnimGraph_GetAnimationController
  if ( *(int *)(v17 + 704) <= 0 && *(_BYTE *)(v17 + 24) == 4 )
  {
    *(_BYTE *)(sub_180A6D880(a2) + 748) = 0;
    v18 = sub_180A6D210(a2);
    v19 = 0LL;
```

The function called immediately after the DevMsg block is `CBaseAnimGraph_GetAnimationController`.

### 4. Analyze CBaseAnimGraph_GetAnimationController

Decompile the identified function. It should have this structure:

```c
__int64 __fastcall CBaseAnimGraph_GetAnimationController(__int64 a1) // CBaseAnimGraph *pEntity
{
  __int64 result; // rax

  // *(_QWORD *)(a1 + 632) = pEntity->m_skeletonInstance
  // Type: CBodyComponentSkeletonInstance::NetworkVar_m_skeletonInstance
  // Multiple inheritance: CSkeletonInstance, CGameSceneNode, ISceneAnimatableProceduralBoneTransforms
  result = (*(__int64 (__fastcall **)(_QWORD))(**(_QWORD **)(a1 + 632) + 64LL))(*(_QWORD *)(a1 + 632));
  if ( result )
    return *(_QWORD *)(result + 928); // CSkeletonInstance->m_animationController
  return result;
}
```

Key observations:
- `a1 + 632` (0x278) = `pEntity->m_skeletonInstance`
- vtable offset `64` (0x40) = `CGameSceneNode_GetSkeletonInstance` (vtable index 8)
- `result + 928` (0x3A0) = `CSkeletonInstance->m_animationController`

### 5. Rename Function

Use `rename` to give the function a meaningful name:

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<function_addr>", "name": "CBaseAnimGraph_GetAnimationController"}})
```

### 6. Write Struct Members as YAML

**ALWAYS** Use SKILL `/write-struct-as-yaml` to write the struct member information:

For `CSkeletonInstance`:
- Offset `0x3A0`: `m_animationController` (size 8)

For `CBaseAnimGraph`:
- Offset `0x278`: `m_skeletonInstance` (size 8)

### 7. Write Virtual Function as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CGameSceneNode_GetSkeletonInstance`
- `vtable_name`: `CGameSceneNode`
- `vfunc_offset`: `0x40` (can change on game update)
- `vfunc_index`: `8` (can change on game update)

Note: `func_addr` and `func_sig` are not needed for this virtual function.

## Function Characteristics

The `CGameSceneNode_GetSkeletonInstance` function:
- Is a virtual function at vtable index 8 (offset 0x40)
- Called on `CBodyComponentSkeletonInstance::NetworkVar_m_skeletonInstance`
- Returns a `CSkeletonInstance*` pointer

## VTable Information

- **VTable Name**: `CGameSceneNode`
- **VTable Offset**: `0x40` (change on game update)
- **VTable Index**: `8`

## Related Struct Offsets

| Struct | Offset | Member | Size |
|--------|--------|--------|------|
| `CBaseAnimGraph` | `0x278` | `m_skeletonInstance` | 8 |
| `CSkeletonInstance` | `0x3A0` | `m_animationController` | 8 |

## Output YAML Files

The output YAML filenames depend on the platform:
- `server.dll` → `*.windows.yaml`
- `server.so` / `libserver.so` → `*.linux.yaml`

### CGameSceneNode_GetSkeletonInstance.{platform}.yaml

Example output:

```yaml
vtable_name: CGameSceneNode
vfunc_offset: 0x40
vfunc_index: 8
```

### CBaseAnimGraph.{platform}.yaml

Example output:

```yaml
0x278: m_skeletonInstance 8
```

### CSkeletonInstance.{platform}.yaml

Example output:

```yaml
0x3A0: m_animationController 8
```

## Related Functions

- `CBaseAnimGraph_GetAnimationController` - Wrapper that calls `GetSkeletonInstance` and returns `m_animationController`
