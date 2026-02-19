---
name: find-CNavMesh_GetNearestNavArea
description: Find and identify the CNavMesh_GetNearestNavArea function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the CNavMesh_GetNearestNavArea function by searching for the string "CNavMesh::GetNearestNavArea" and finding the function that references it.
disable-model-invocation: true
---

# Find CNavMesh_GetNearestNavArea

Locate `CNavMesh_GetNearestNavArea` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

### 1. Search for Signature String

Use `find_regex` to search for the debug string:

```
mcp__ida-pro-mcp__find_regex(pattern="CNavMesh::GetNearestNavArea")
```

Expected result: Find string address containing "CNavMesh::GetNearestNavArea"

### 2. Find Cross-References

Use `xrefs_to` to find locations that reference this string:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

Expected result: The function that references this string is `CNavMesh_GetNearestNavArea` itself. The string is used as a profiling/debug marker within the function.

### 3. Decompile and Verify

Decompile the referencing function to confirm it is `CNavMesh_GetNearestNavArea`:

```
mcp__ida-pro-mcp__decompile(addr="<function_addr>")
```

Verify the function references the `"CNavMesh::GetNearestNavArea"` string (typically as a profiling scope marker).

### 4. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CNavMesh_GetNearestNavArea"}]}
```

### 5. Generate Signature

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 6. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNavMesh_GetNearestNavArea`
- `func_addr`: The function address from step 2
- `func_sig`: The validated signature from step 5

## Function Characteristics

- **Type**: Non-virtual (regular) function
- **Purpose**: Finds the nearest navigation area to a given position in the navigation mesh. Used for AI pathfinding and navigation queries.

## String References

- `"CNavMesh::GetNearestNavArea"` — Debug/profiling marker string directly inside the function

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CNavMesh_GetNearestNavArea.windows.yaml`
- `libserver.so` / `libserver.so` → `CNavMesh_GetNearestNavArea.linux.yaml`
