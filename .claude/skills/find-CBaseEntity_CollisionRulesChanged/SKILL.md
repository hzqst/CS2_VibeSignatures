---
name: find-CBaseEntity_CollisionRulesChanged
description: Find and identify the CBaseEntity_CollisionRulesChanged virtual function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CollisionRulesChanged function by first finding CBaseEntity_SetOwner and extracting the very last virtual call offset from its decompiled code.
---

# Find CBaseEntity_CollisionRulesChanged

Locate `CBaseEntity_CollisionRulesChanged` in CS2 `server.dll` or `server.so` using IDA Pro MCP tools.

## Method

### 1. Get CBaseEntity_SetOwner Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CBaseEntity_SetOwner`.

If the skill returns an error, stop and report to user.

Otherwise, extract `func_va` for the next step.

### 2. Decompile CBaseEntity_SetOwner and Extract VTable Offset

Decompile `CBaseEntity_SetOwner` using `func_va` from step 1:

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

Look for the **very last virtual call** in the decompiled code:

```c
__int64 __fastcall CBaseEntity_SetOwner(__int64 a1, _QWORD *a2)
{

//at the end of the function body, there is a very last virtual call - CBaseEntity_CollisionRulesChanged
  (*(void (__fastcall **)(_DWORD *))(*(_QWORD *)a1 + 1480LL))(a1);
```

Extract the vtable offset from this last virtual call (e.g., `1480`). This is the `CBaseEntity_CollisionRulesChanged` vtable offset.

Calculate:
- **VTable Offset**: The value from the pattern (e.g., 1480 = 0x5C8)
- **VTable Index**: offset / 8 (e.g., 1480 / 8 = **185**)

Also note the `inst_addr` — the address of this virtual call instruction (shown as a comment like `/*0x180c0c3b4*/` in the decompiled output).

### 3. Generate vfunc offset signature for CBaseEntity_CollisionRulesChanged

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CBaseEntity_CollisionRulesChanged`, with `inst_addr` and `vfunc_offset` from step 2.

### 4. Write Analysis Results as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for `CBaseEntity_CollisionRulesChanged`.

Required parameters:
- `func_name`: `CBaseEntity_CollisionRulesChanged`
- `func_addr`: `None` (this is a virtual call target, not a directly resolved function)
- `func_sig`: `None`
- `vfunc_sig`: `<vfunc_sig>` from step 3

VTable parameters:
- `vtable_name`: `CBaseEntity`
- `vfunc_index`: The vtable index from step 2 (e.g., 185)
- `vfunc_offset`: The vtable offset from step 2 (e.g., 0x5C8)

## VTable Information

- **VTable Name**: `CBaseEntity::`vftable'`
- **VTable Mangled Name (Windows)**: `??_7CBaseEntity@@6B@`
- **VTable Mangled Name (Linux)**: `_ZTV11CBaseEntity`
- **VTable Index**: 185 - This can change when game updates.
- **VTable Offset**: 0x5C8 (185 * 8 = 1480) - This can change when game updates.

* Note that for `server.so`, the first 16 bytes of "vftable" are for RTTI. The real vftable = `_ZTV11CBaseEntity` + `0x10`.

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBaseEntity_CollisionRulesChanged.windows.yaml`
- `server.so` → `CBaseEntity_CollisionRulesChanged.linux.yaml`

```yaml
func_name: CBaseEntity_CollisionRulesChanged
vfunc_sig: FF 90 C8 05 00 00 48 8B 5C 24 ?? 48 8B 74 24 ?? 48 8B 7C 24 ?? 48 83 C4 ?? 41 5E C3 48 89 5C 24 ??
vtable_name: CBaseEntity
vfunc_offset: 0x5c8
vfunc_index: 185
```

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- `CBaseEntity_CollisionRulesChanged` is a virtual function called as the very last operation inside `CBaseEntity_SetOwner`. When the owner entity changes, this function is invoked to notify the collision system that collision rules need to be re-evaluated.
- The function is identified indirectly through the virtual call in `CBaseEntity_SetOwner`, so `func_va`, `func_rva`, `func_size`, and `func_sig` are not included in the YAML output.
- The `vfunc_sig` captures the virtual call instruction pattern including the displacement bytes for the vtable offset.
