---
name: find-CBasePlayerPawn_CommitSuicide
description: Find and identify the CBasePlayerPawn_CommitSuicide function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CommitSuicide function by analyzing the CBasePlayerPawn vtable and identifying unique function characteristics including specific pointer offsets (0x890, 0xBF8) and sequential function call patterns.
expected_output:
  - name: CBasePlayerPawn_CommitSuicide
    category: vfunc
    alias:
      - CBasePlayerPawn::CommitSuicide
    files:
      - CBasePlayerPawn_CommitSuicide.{platform}.yaml
---

# Find CBasePlayerPawn_CommitSuicide

Locate `CBasePlayerPawn_CommitSuicide` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Get CBasePlayerPawn vtable information:

   **ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CBasePlayerPawn`.

   Extract `vtable_va` and `vtable_entries` from the result.

2. Decompile the virtual function at vtable[398 ~ 402]:

   ```
   mcp__ida-pro-mcp__decompile addr="<vtable_entries[index]>"
   ```

   where index ranges fronm 398 to 402

3. Verify function characteristics to identify `CBasePlayerPawn::CommitSuicide`:

   The function should look like:

   Windows:
   ```c
   char __fastcall sub_180BE9210(float *a1, unsigned __int8 a2, char a3)
   {
      __int64 v4; // rbp
      char result; // al
      _BYTE v7[112]; // [rsp+40h] [rbp-138h] BYREF
      __int64 v8; // [rsp+B0h] [rbp-C8h]
      int v9; // [rsp+180h] [rbp+8h] BYREF
      char v10; // [rsp+198h] [rbp+20h] BYREF

      v4 = a2;
      result = (*(__int64 (__fastcall **)(float *))(*(_QWORD *)a1 + 1336LL))(a1);
      if ( result )
      {
         sub_1808757E0(&v9, *(_DWORD *)(*((_QWORD *)a1 + 2) + 56LL));
         result = sub_1801C22A0(a1 + 824, (float *)&v9);
         if ( !result || a3 )
         {
            sub_1808757E0(&v9, *(_DWORD *)(*((_QWORD *)a1 + 2) + 56LL));
            a1[824] = *(float *)sub_1801965D0(&v10, &v9);
            sub_180DFABA0((unsigned int)v7, (_DWORD)a1, (_DWORD)a1, 0, 1065353216, (_DWORD)v4 << 6, 0);
            v8 |= (32 * (v4 ^ 1) + 32) | 0x116;
            sub_1803C8520(a1, (__int64)v7, 0LL);//CBaseEntity::TakeDamageOld
            return sub_180DFBEE0((__int64)v7);
         }
      }
      return result;
   }
   ```

   Linux:

   ```c
   void __fastcall sub_1628A10(__int64 a1, unsigned __int8 a2, char a3)
   {
      unsigned __int8 (*v4)(void); // rax
      _BYTE v5[112]; // [rsp+0h] [rbp-140h] BYREF
      __int64 v6; // [rsp+70h] [rbp-D0h]

      v4 = *(unsigned __int8 (**)(void))(*(_QWORD *)a1 + 1328LL);
      if ( (char *)v4 == (char *)CBaseEntity_IsPlayerPawn )
      {
         if ( *(_BYTE *)(a1 + 1472) )
            return;
      }
      else if ( !v4() )
      {
         return;
      }
      if ( *(float *)(a1 + 4072) <= sub_118C0E0(*(unsigned int *)(*(_QWORD *)(a1 + 16) + 56LL)) || a3 )
      {
         *(float *)(a1 + 4072) = sub_118C0E0(*(unsigned int *)(*(_QWORD *)(a1 + 16) + 56LL)) + 5.0;
         sub_18B0D40(v5, a1, a1, 0LL, a2 << 6, 0LL, 1.0);
         v6 |= (a2 == 0 ? 64LL : 32LL) | 0x116;
         sub_C8A650(a1, v5, 0LL);
         sub_189BA20(v5);//CBaseEntity::TakeDamageOld
      }
   }
   ```

   where the `CBaseEntity::TakeDamageOld` can be verified by checking string "CBaseEntity::TakeDamageOld: damagetype %d with info.GetDamagePosition() == Vector::vZero\n" in it's decompiled procedure.

   If the code pattern match, proceed to rename.

4. Rename the function:

   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CBasePlayerPawn_CommitSuicide"}]}
   ```

5. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

7. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CBasePlayerPawn_CommitSuicide`
   - `func_addr`: The function address from step 2
   - `func_sig`: The validated signature from step 6

   VTable parameters:
   - `vtable_name`: `CBasePlayerPawn`
   - `vfunc_index`: The vtable index from step 3
   - `vfunc_offset`: `vfunc_offset = vfunc_index * 8`

## Function Characteristics

- **Parameters**: `(this)` where `this` is CBasePlayerPawn pointer
- **Purpose**: Handles player suicide/death state cleanup and processing
- **Key Operations**:
  - Sets up player state at offset 0x890 (2192 bytes)
  - Calls cleanup functions
  - Invokes virtual function for death handling
  - Sets death-related flags (bit 21 = 0x200000)
  - Finalizes the suicide process

## VTable Information

- **VTable Name**: `CBasePlayerPawn::\`vftable'`
- **VTable Mangled Name**: `??_7CBasePlayerPawn@@6B@` (Windows) / `_ZTV16CBasePlayerPawn` (Linux)
- **VTable Index**: 400 (IDA index) / 399 (array index) - This can change when game updates.
- **VTable Offset**: 0xC78 - This can change when game updates.

* Note that for `server.so`, the first 16 bytes of "vftable" are for RTTI. The real vftable = `_ZTV16CBasePlayerPawn` + `0x10`.

## Unique Identifiers

The function can be uniquely identified by:

1. **Offset 0x890** (`4C 8D A7 90 08 00 00`) - LEA r12, [rdi+890h]
   - This is `a1 + 274` in QWORD pointer arithmetic

2. **Vtable offset 0xBF8** (`FF 90 F8 0B 00 00`) - call qword ptr [rax+0BF8h]
   - Virtual function call at index 383
   - This corresponds to `(*a1 + 3064)` in bytes

3. **Sequential function call pattern**:
   - Call to view initialization
   - Virtual call at vtable[383]
   - Two helper function calls for offset calculations

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBasePlayerPawn_CommitSuicide.windows.yaml`
- `server.so` → `CBasePlayerPawn_CommitSuicide.linux.yaml`

```yaml
func_va: 0x1625080         # Virtual address of the function - This can change when game updates.
func_rva: 0x1625080        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xba            # Function size in bytes - This can change when game updates.
func_sig: 55 31 F6 48 89 E5 41 56 41 55 41 54 4C 8D A7 90 08 00 00 53 48 89 FB 4C 89 E7 E8 ?? ?? ?? ?? 48 8B 03 48 89 DF FF 90 F8 0B 00 00 4C 89 E7 49 89 C5 E8 ?? ?? ?? ?? 4C 89 E7 49 89 C6 E8 ?? ?? ?? ??
vtable_name: CBasePlayerPawn
vfunc_offset: 0xc78        # Offset from vtable start - This can change when game updates.
vfunc_index: 400           # IDA vtable index (array index 399) - This can change when game updates.
```
