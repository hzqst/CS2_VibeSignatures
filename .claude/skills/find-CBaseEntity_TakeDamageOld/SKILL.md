---
name: find-CBaseEntity_TakeDamageOld
description: Find and identify the CBaseEntity_TakeDamageOld function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the TakeDamageOld function by searching for the TakeDamageOld debug string references and analyzing cross-references.
---

# Find CBaseEntity_TakeDamageOld, CBaseEntity_TakeDamage, CBaseEntity_TakeDamage_Alive, CBaseEntity_TakeDamage_Dying, CBaseEntity_TakeDamage_Dead

Locate `CBaseEntity_TakeDamageOld`, `CBaseEntity_TakeDamage`, `CBaseEntity_TakeDamage_Alive`, `CBaseEntity_TakeDamage_Dying`, `CBaseEntity_TakeDamage_Dead` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the debug string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="TakeDamageOld.*GetDamageForce"
   ```

   Or alternatively:
   ```
   mcp__ida-pro-mcp__find_regex pattern="TakeDamageOld.*GetDamagePosition"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function and verify it matches:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

   The target function should contain:
   - DevWarning calls with these strings:
     - `"CBaseEntity::TakeDamageOld: damagetype %d with info.GetDamageForce() == Vector::vZero\n"`
     - `"CBaseEntity::TakeDamageOld: damagetype %d with info.GetDamagePosition() == Vector::vZero\n"`
   - Checks for zero vectors in damage force and position
   - Complex damage handling logic with multiple condition checks

   Example pattern:
   ```cpp
   if ( (*(float *)(a2 + 8) == 0.0 && *(float *)(a2 + 12) == 0.0 && *(float *)(a2 + 16) == 0.0
       || *(float *)(a2 + 20) == 0.0 && *(float *)(a2 + 24) == 0.0 && *(float *)(a2 + 28) == 0.0)
       && ++dword_XXXXXXXX < 10 )
   {
       if ( *(float *)(a2 + 8) == 0.0 && ... )
           DevWarning("CBaseEntity::TakeDamageOld: damagetype %d with info.GetDamageForce() == Vector::vZero\n", ...);
       if ( *(float *)(a2 + 20) == 0.0 && ... )
           DevWarning("CBaseEntity::TakeDamageOld: damagetype %d with info.GetDamagePosition() == Vector::vZero\n", ...);
   }
   ```

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CBaseEntity_TakeDamageOld"}]}
   ```

5. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CBaseEntity_TakeDamageOld`.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CBaseEntity_TakeDamageOld`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

7. Look for following code pattern in `CBaseEntity_TakeDamageOld` :

Windows binary:

```c
      (*(void (__fastcall **)(_QWORD *, _DWORD *, __int64))(*a1 + 1000LL))(a1, v6, a2);
      if ( !sub_181198FE0((__int64)a1)
      || !*((_BYTE *)a1 + 744)
      || (v30 = *(_QWORD *)v6, (*(_BYTE *)(*(_QWORD *)v6 + 112LL) & 0x11) == 1) )
      {
LABEL_79:
      //...
      }
      (*(void (__fastcall **)(_QWORD *, _DWORD *))(*a1 + 1008LL))(a1, v6);//This is CBasePlayerPawn_OnTakeDamage, vfunc_offset = 1008LL
      if ( (int)qword_181EE4380 <= 0 )
         goto LABEL_89;
```

Linux binary:

```c
      v24 = *(__int64 (__fastcall **)())(*a1 + 992LL);
      if ( v24 != nullsub_413 )
         ((void (__fastcall *)(_QWORD *, __int64 *, __int64))v24)(a1, v6, a2);
      v25 = (int)sub_C8AA80(a1, v6);
      v26 = (float)*((int *)v6 + 3);
      *((_DWORD *)v6 + 4) = v25;
      v27 = (int)qword_25D5910;
      v28 = _mm_min_epi32(_mm_cvtsi32_si128((int)v26), _mm_cvtsi32_si128(v25));
      *((_DWORD *)v6 + 2) = _mm_cvtsi128_si32(v28);
      v6[3] = _mm_insert_epi32(v28, v25, 1).m128i_u64[0];
      if ( (int)v27 > 0 )
      {
         //...
      }
      (*(void (__fastcall **)(_QWORD *, __int64 *))(*a1 + 1000LL))(a1, v6); //This is CBasePlayerPawn_OnTakeDamage, vfunc_offset = 1000LL, vfunc_offset can change on game update
      if ( (int)qword_25D5910 <= 0 )
         goto LABEL_45;
```

8. Load `CBasePlayerPawn` VTable

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CBasePlayerPawn`

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `vtable_va`, `vtable_numvfunc` and `vtable_entries` for subsequent steps.

9. Calculate VTable Indices and resolve vfunc address

From the offsets found in step 3, calculate vtable indices:

- `vfunc_index` = `<vfunc_offset>` / 8

Resolve the `CBasePlayerPawn_OnTakeDamage` function address from : `CBasePlayerPawn vtable_entries[vfunc_index]`

10. Rename Functions

```
mcp__ida-pro-mcp__rename(batch={"func": [
  {"addr": "<CBasePlayerPawn_OnTakeDamage_addr>", "name": "CBasePlayerPawn_OnTakeDamage"}
]})
```

11. Decompile `CBasePlayerPawn_OnTakeDamage` and look for code pattern

```c
__int64 __fastcall CBasePlayerPawn_OnTakeDamage(__int64 *a1, __int64 *a2)
{
//....other code

  v8 = sub_1803B2B90(a1); //This is CBaseEntity_IsAlive (wrapper around "uint8 m_lifeState" checker)
  if ( v8 )
  {
    v9 = v8 == 1;
    v10 = *a1;
    if ( v9 )
      return (*(__int64 (__fastcall **)(__int64 *, __int64 *))(v10 + 2008))(a1, a2);//This is CBasePlayerPawn_OnTakeDamage_Dying, vfunc_offset = 2024, vfunc_offset can change on game update
    else
      return (*(__int64 (__fastcall **)(__int64 *, __int64 *))(v10 + 2024))(a1, a2);//This is CBasePlayerPawn_OnTakeDamage_Dead, vfunc_offset = 2024, vfunc_offset can change on game update
  }
  else
  {
    byte_181E98998 = 0;
    return (*(__int64 (__fastcall **)(__int64 *, __int64 *))(*a1 + 1992))(a1, a2);//This is CBasePlayerPawn_OnTakeDamage_Alive, vfunc_offset = 1992, vfunc_offset can change on game update

  }
}
```

```c
  (*(void (__fastcall **)(__int64, int *))(*(_QWORD *)a1 + 1984LL))(a1, a2);
  v2 = sub_C7BAA0(a1); //This is CBaseEntity_IsAlive (wrapper around "uint8 m_lifeState" checker)
  v3 = *(_QWORD **)a1;
  if ( !v2 )
  {
    v5 = (__int64 (__fastcall *)(__int64, int *))v3[250];//This is CBasePlayerPawn_OnTakeDamage_Alive, vfunc_index = 250, vfunc_offset = vfunc_index * 8, vfunc_index can change on game update
    byte_257C0A4 = 0;
    return (__int64 (__fastcall *)(__int64, int *))v5(a1, a2);
  }
  if ( v2 == 1 )
  {
    result = (__int64 (__fastcall *)(__int64, int *))v3[252];//This is CBasePlayerPawn_OnTakeDamage_Dying, vfunc_index = 252, vfunc_offset = vfunc_index * 8, vfunc_index can change on game update
    if ( (char *)result == (char *)nullsub_147 )
      return result;
  }
  else
  {
    result = (__int64 (__fastcall *)(__int64, int *))v3[254];//This is CBasePlayerPawn_OnTakeDamage_Dead, vfunc_index = 254, vfunc_offset = vfunc_index * 8, vfunc_index can change on game update
    if ( (char *)result == (char *)nullsub_148 )
      return result;
  }
  return (__int64 (__fastcall *)(__int64, int *))result(a1, a2);
```

`LifeState_t` definition:

```c
enum class LifeState_t : uint32_t {
      LIFE_ALIVE = 0x0,
      LIFE_DYING = 0x1,
      LIFE_DEAD = 0x2,
      LIFE_RESPAWNABLE = 0x3,
      LIFE_RESPAWNING = 0x4,
      NUM_LIFESTATES = 0x5
};
```

12. Calculate VTable Indices and resolve vfunc address for `CBasePlayerPawn_OnTakeDamage_Alive`, `CBasePlayerPawn_OnTakeDamage_Dying`, `CBasePlayerPawn_OnTakeDamage_Dead`

From the offsets found in step 11, calculate vtable indices:

- `vfunc_index` = `<vfunc_offset>` / 8

- `vfunc_offset` = `<vfunc_index>` * 8

Resolve the function addresses from : `CBasePlayerPawn vtable_entries[vfunc_index]` for `CBasePlayerPawn_OnTakeDamage_Alive`, `CBasePlayerPawn_OnTakeDamage_Dying`, `CBasePlayerPawn_OnTakeDamage_Dead`

13. Rename Functions

```
mcp__ida-pro-mcp__rename(batch={"func": [
  {"addr": "<CBasePlayerPawn_OnTakeDamage_Alive_addr>", "name": "CBasePlayerPawn_OnTakeDamage_Alive"}
  {"addr": "<CBasePlayerPawn_OnTakeDamage_Dying_addr>", "name": "CBasePlayerPawn_OnTakeDamage_Dying"}
  {"addr": "<CBasePlayerPawn_OnTakeDamage_Dead_addr>", "name": "CBasePlayerPawn_OnTakeDamage_Dead"}
]})
```

14. Generate and validate unique signature for `CBasePlayerPawn_OnTakeDamage`:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CBasePlayerPawn_OnTakeDamage`.

15. Generate vfunc offset signatures for `CBasePlayerPawn_OnTakeDamage_Alive`, `CBasePlayerPawn_OnTakeDamage_Dying`, `CBasePlayerPawn_OnTakeDamage_Dead`

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CBasePlayerPawn_OnTakeDamage_Alive`, `CBasePlayerPawn_OnTakeDamage_Dying`, `CBasePlayerPawn_OnTakeDamage_Dead`, with `inst_addr` and `vfunc_offset` from step 12

16. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for BOTH functions.

**CBasePlayerPawn_OnTakeDamage** (with signature):
- `func_name`: `CBasePlayerPawn_OnTakeDamage`
- `func_addr`: The function address from step 9
- `func_sig`: `<func_sig>` from step 14
- `vtable_name`: `CBasePlayerPawn`
- `vfunc_offset`: `<vfunc_offset>` from step 9
- `vfunc_index`: `<vfunc_index>` from step 9

**CBasePlayerPawn_OnTakeDamage_Alive** (with signature):
- `func_name`: `CBasePlayerPawn_OnTakeDamage_Alive`
- `func_addr`: The function address from step 12
- `func_sig`: `None` (omit — function is too small for a unique signature)
- `vtable_name`: `CBasePlayerPawn`
- `vfunc_offset`: `<vfunc_offset>` from step 12
- `vfunc_index`: `<vfunc_index>` from step 12
- `vfunc_sig`: `<vfunc_sig>` from step 15

**CBasePlayerPawn_OnTakeDamage_Dying** (with signature):
- `func_name`: `CBasePlayerPawn_OnTakeDamage_Dying`
- `func_addr`: The function address from step 12
- `func_sig`: `None` (omit — function is too small for a unique signature)
- `vtable_name`: `CBasePlayerPawn`
- `vfunc_offset`: `<vfunc_offset>` from step 12
- `vfunc_index`: `<vfunc_index>` from step 12
- `vfunc_sig`: `<vfunc_sig>` from step 15

**CBasePlayerPawn_OnTakeDamage_Dead** (with signature):
- `func_name`: `CBasePlayerPawn_OnTakeDamage_Dead`
- `func_addr`: The function address from step 12
- `func_sig`: `None` (omit — function is too small for a unique signature)
- `vtable_name`: `CBasePlayerPawn`
- `vfunc_offset`: `<vfunc_offset>` from step 12
- `vfunc_index`: `<vfunc_index>` from step 12
- `vfunc_sig`: `<vfunc_sig>` from step 15

## Function Characteristics

- **Prototype**: `unsigned __int64 CBaseEntity_TakeDamageOld(void *pEntity, CTakeDamageInfo *info, void *a3)`
- **Parameters**:
  - `pEntity`: Pointer to the entity taking damage
  - `info`: Pointer to CTakeDamageInfo structure containing damage details
  - `a3`: Additional parameter (damage output info)
- **Return**: unsigned __int64

## Key Behaviors

1. Validates damage info (force vector, position vector)
2. Logs debug warnings when damage vectors are zero (limited to 10 times)
3. Processes damage through entity's damage handling system
4. Large function (~0x675 bytes) with extensive damage processing logic

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- This is a core damage handling function
- Contains debug validation for damage info integrity
- The zero vector checks help identify improperly initialized damage info

## Output YAML Format

The output YAML filename depends on the platform:

- `server.dll` → `CBaseEntity_TakeDamageOld.windows.yaml`, `CBasePlayerPawn_OnTakeDamage.windows.yaml`, `CBasePlayerPawn_OnTakeDamage_Alive.windows.yaml`, `CBasePlayerPawn_OnTakeDamage_Dying.windows.yaml`, `CBasePlayerPawn_OnTakeDamage_Dead.windows.yaml`

- `server.so` → `CBaseEntity_TakeDamageOld.linux.yaml`, `CBasePlayerPawn_OnTakeDamage.linux.yaml`, `CBasePlayerPawn_OnTakeDamage_Alive.linux.yaml`, `CBasePlayerPawn_OnTakeDamage_Dying.linux.yaml`, `CBasePlayerPawn_OnTakeDamage_Dead.linux.yaml`