---
name: find-CBaseEntity_TakeDamageOld
description: Find and identify the CBaseEntity_TakeDamageOld function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the TakeDamageOld function by searching for the TakeDamageOld debug string references and analyzing cross-references.
---

# Find CBaseEntity_TakeDamageOld

Locate `CBaseEntity_TakeDamageOld` in CS2 server.dll or server.so using IDA Pro MCP tools.

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

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CBaseEntity_TakeDamageOld`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

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
- `server.dll` → `CBaseEntity_TakeDamageOld.windows.yaml`
- `server.so` → `CBaseEntity_TakeDamageOld.linux.yaml`

```yaml
func_va: 0x180XXXXXX      # Virtual address of the function - This can change when game updates.
func_rva: 0xXXXXXX        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xXXX          # Function size in bytes - This can change when game updates.
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - This can change when game updates.
```
