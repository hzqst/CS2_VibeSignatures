---
name: find-CBaseModelEntity_SetModel
description: Find and identify the CBaseModelEntity_SetModel function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll to locate the SetModel function by searching for known model path strings and analyzing cross-references.
---

# Find CBaseModelEntity_SetModel

Locate `CBaseModelEntity_SetModel` function in CS2 binary via signature pattern matching.

## Method

1. Search for known model path string:
   ```
   weapons/models/defuser/defuser.vmdl
   ```

2. Get cross-references to the string address

3. Decompile referenced functions and look for this pattern:
   ```cpp
   CBaseModelEntity_SetModel(a1, "weapons/models/defuser/defuser.vmdl");
   sub_XXXXXXXX(a1, a2);  // next call after SetModel
   v4 = (_DWORD *)sub_XXXXXXXX(&unk_XXXXXXXX, 0xFFFFFFFFi64);
   if ( !v4 )
     v4 = *(_DWORD **)(qword_XXXXXXXX + 8);
   if ( *v4 == 1 )
   {
     v5 = (...)(...)(
            qword_XXXXXXXX,
            "defuser_dropped",  // game event string
            0i64,
            0i64);
   ```

4. The first function call with the model path string as second parameter is `CBaseModelEntity_SetModel`

## IDA MCP Commands

```
# Step 1: Search string
mcp__ida-pro-mcp__find_regex pattern="weapons/models/defuser/defuser\.vmdl"

# Step 2: Get xrefs (use address from step 1)
mcp__ida-pro-mcp__xrefs_to addrs="<string_address>"

# Step 3: Decompile functions
mcp__ida-pro-mcp__decompile addr="<function_address>"

# Step 4: Rename after identification
mcp__ida-pro-mcp__rename batch={"func": {"addr": "<identified_addr>", "name": "CBaseModelEntity_SetModel"}}
```

## Identification Criteria

The target function:
- Takes 2 parameters: `(entity*, model_path_string)`
- First parameter is entity pointer (`a1`)
- Second parameter is model path string (e.g., `"weapons/models/defuser/defuser.vmdl"`)
- Called at the beginning of entity spawn/initialization functions
