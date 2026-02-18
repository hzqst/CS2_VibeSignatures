---
name: find-CDecalGameSystem_UpdateDecals-AND-CDecalGameSystem_ClientPreUpdate
description: |
  Find and identify CDecalGameSystem_UpdateDecals and CDecalGameSystem_ClientPreUpdate functions in CS2 client binary using IDA Pro MCP.
  CDecalGameSystem_UpdateDecals is located via the "CDecalGameSystem::UpdateDecals" string reference.
  CDecalGameSystem_ClientPreUpdate is the caller of UpdateDecals and a virtual function in the CDecalGameSystem vtable.
  Trigger: CDecalGameSystem_UpdateDecals, CDecalGameSystem_ClientPreUpdate, UpdateDecals, ClientPreUpdate
disable-model-invocation: true
---

# CDecalGameSystem_UpdateDecals & CDecalGameSystem_ClientPreUpdate Location Workflow

## Overview

Locate two related functions in CS2 client binary:
- `CDecalGameSystem_UpdateDecals` — Regular function that handles decal updates
- `CDecalGameSystem_ClientPreUpdate` — Virtual function that calls UpdateDecals

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the `CDecalGameSystem::UpdateDecals` string:

```
mcp__ida-pro-mcp__find_regex(pattern="CDecalGameSystem::UpdateDecals")
```

### 2. Find CDecalGameSystem_UpdateDecals via Cross-References

Use `xrefs_to` on the string address to find the function that references it:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

The function referencing this string is `CDecalGameSystem_UpdateDecals`.

### 3. Rename CDecalGameSystem_UpdateDecals

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<UpdateDecals_addr>", "name": "CDecalGameSystem_UpdateDecals"}})
```

### 4. Find CDecalGameSystem_ClientPreUpdate via Cross-References

Use `xrefs_to` on `CDecalGameSystem_UpdateDecals` to find its caller:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<UpdateDecals_addr>")
```

Look for a code xref (type="code"). The calling function is `CDecalGameSystem_ClientPreUpdate`.

Decompile to verify the pattern:
```c
__int64 __fastcall CDecalGameSystem_ClientPreUpdate(__int64 a1)
{
  __int64 v2; // rcx
  v2 = *(_QWORD *)(a1 + 312);
  if ( v2 )
    (*(void (__fastcall **)(__int64))(*(_QWORD *)v2 + 24LL))(v2);
  return CDecalGameSystem_UpdateDecals(a1);
}
```

### 5. Rename CDecalGameSystem_ClientPreUpdate

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<ClientPreUpdate_addr>", "name": "CDecalGameSystem_ClientPreUpdate"}})
```

### 6. Load CDecalGameSystem VTable and Get VTable Index

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CDecalGameSystem`

If the skill returns an error, **STOP** and report to user.

Find `CDecalGameSystem_ClientPreUpdate` address in `vtable_entries` to determine `vfunc_index`.

### 7. Generate Signatures

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CDecalGameSystem_UpdateDecals`.

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CDecalGameSystem_ClientPreUpdate`.

### 8. Write YAML Output

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results for `CDecalGameSystem_UpdateDecals`.

Required parameters:
- `func_name`: `CDecalGameSystem_UpdateDecals`
- `func_addr`: The function address from step 2
- `func_sig`: The validated signature from step 7

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for `CDecalGameSystem_ClientPreUpdate`.

Required parameters:
- `func_name`: `CDecalGameSystem_ClientPreUpdate`
- `func_addr`: The function address from step 4
- `func_sig`: The validated signature from step 7

VTable parameters:
- `vtable_name`: `CDecalGameSystem`
- `vfunc_offset`: calculated from vfunc_index * 8
- `vfunc_index`: from step 6

## Function Characteristics

### CDecalGameSystem_UpdateDecals

- Regular function (not virtual)
- References the string `CDecalGameSystem::UpdateDecals`
- Handles decal update logic

### CDecalGameSystem_ClientPreUpdate

- Virtual function in CDecalGameSystem vtable (index 21, offset 0xA8 — may change with game updates)
- Calls a virtual method on a member object at offset +312 (0x138), then tail-calls UpdateDecals
- Small function (~0x28 bytes)

## VTable Information

- **VTable Name**: `CDecalGameSystem`
- **VTable Mangled Name**:
  - Windows: `??_7CDecalGameSystem@@6B@`
- **ClientPreUpdate VTable Index**: `21` (may change with game updates)
- **ClientPreUpdate VTable Offset**: `0xA8` (may change with game updates)

## Output YAML Files

- `CDecalGameSystem_UpdateDecals.windows.yaml` / `.linux.yaml`
- `CDecalGameSystem_ClientPreUpdate.windows.yaml` / `.linux.yaml`
