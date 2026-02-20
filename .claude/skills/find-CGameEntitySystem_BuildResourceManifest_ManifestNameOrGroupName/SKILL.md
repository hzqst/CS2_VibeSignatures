---
name: find-CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName
description: |
  Find and identify the CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName virtual function in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the BuildResourceManifest_ManifestNameOrGroupName vfunc
  by searching for the "GameSessionManifest.vrgrp" string and tracing to the function that references it.
  Trigger: CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName
disable-model-invocation: true
---

# Find CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName

Locate `CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName` vfunc in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

1. Search for the `GameSessionManifest.vrgrp` string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="GameSessionManifest\.vrgrp"
   ```

2. Find cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```
   This leads to the `CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName` function.

3. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": {"addr": "<function_addr>", "name": "CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName"}}
   ```

4. Decompile and verify the function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

   Confirm the function contains a call to `V_stricmp_fast` with `"GameSessionManifest.vrgrp"` and iterates game systems via a callback pattern like:
   ```c
   sub_XXXXXXX(v12, (__int64 (__fastcall *)(_QWORD, __int64))sub_YYYYYYY, (__int64)&v17);
   ```

5. Determine the vtable index by using SKILL `/get-vtable-index` with the CGameEntitySystem vtable.

6. Generate function signature:
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature.

7. Write IDA analysis output as YAML:
   **ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName`
   - `func_addr`: The function address from step 2
   - `func_sig`: The validated signature from step 6

   VTable parameters:
   - `vtable_name`: `CGameEntitySystem`
   - `vfunc_offset`: The offset from step 5
   - `vfunc_index`: The vtable index from step 5

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName.windows.yaml`
- `libserver.so` → `CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName.linux.yaml`
