---
name: find-CTakeDamageInfo_GetWeaponName
description: Find and identify the CTakeDamageInfo_GetWeaponName function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the GetWeaponName function by searching for the "_projectile" string reference and analyzing cross-references.
---

# Find CTakeDamageInfo_GetWeaponName

Locate `CTakeDamageInfo::GetWeaponName` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the string "_projectile":

   ```
   mcp__ida-pro-mcp__find_regex pattern="_projectile"
   ```

   Look for the exact string `_projectile` (not the ones with prefixes like `flashbang_projectile`).

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function and verify it matches this pattern:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

   The target function should contain code similar to:
   ```cpp
   if ( (unsigned __int8)sub_XXXXXXXX(v6) )
       return v6 + 7;
   v15 = sub_XXXXXXXX(v6, 95i64);  // 95 = '_' character
   v16 = v15;
   if ( !v15 || (unsigned int)V_stricmp_fast(v15, "_projectile") )
       return v6;
   sub_XXXXXXXX(&unk_XXXXXXXX, "%.*s", (unsigned int)(v16 - (_DWORD)v6), v6);
   return (char *)&unk_XXXXXXXX;
   ```

   Key characteristics:
   - Uses `V_stricmp_fast` to compare with `"_projectile"`
   - Uses `"%.*s"` format string for string manipulation
   - Returns a `const char*`

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CTakeDamageInfo_GetWeaponName"}]}
   ```

5. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CTakeDamageInfo_GetWeaponName`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

   Note: This is NOT a virtual function, so no vtable parameters are needed.

## Signature Pattern

The function contains:
- String comparison with `"_projectile"` using `V_stricmp_fast`
- Format string `"%.*s"` for extracting weapon name prefix
- Character search for `'_'` (95 decimal)

## Function Characteristics

- **Prototype**: `const char *CTakeDamageInfo::GetWeaponName(CTakeDamageInfo *pthis)`
- **Parameters**:
  - `pthis`: Pointer to the CTakeDamageInfo instance (this)
- **Return**: `const char*` - the weapon name with `_projectile` suffix stripped if present

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- This is a regular member function, NOT a virtual function
- No vtable information is needed for this function

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CTakeDamageInfo_GetWeaponName.windows.yaml`
- `server.so` → `CTakeDamageInfo_GetWeaponName.linux.yaml`

```yaml
func_va: 0x180XXXXXX      # Virtual address of the function - This can change when game updates.
func_rva: 0xXXXXXX        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xXXX          # Function size in bytes - This can change when game updates.
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - This can change when game updates.
```
