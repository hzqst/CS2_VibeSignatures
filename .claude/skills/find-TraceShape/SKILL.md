---
name: find-TraceShape
description: Find and identify the TraceShape function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the TraceShape function by searching for the VProf counter string "Physics/TraceShape (Server)" and analyzing cross-references.
disable-model-invocation: true
---

# Find TraceShape

Locate `TraceShape` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

1. Search for the VProf counter string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="Physics/TraceShape \(Server\)"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "TraceShape"}]}
   ```

5. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `TraceShape`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

## String References

The function registers a VProf performance counter with the string:
- `Physics/TraceShape (Server)`

This string is passed to `VProf_FindOrCreateCounter` inside a one-time initialization block.

## Function Characteristics

- **Parameters**:
  - `arg0`: Physics world pointer (used for trace operations)
  - `arg1`: Trace parameters (shape/collision info)
  - `arg2`: Start position (Vector*)
  - `arg3`: End position (Vector*)
  - `arg4`: Trace filter object
  - `arg5`: Trace result output structure

- **Return type**: `bool` — returns true if the trace hit something (fraction < 1.0 or startsolid)

- **Behavior**: Performs a shape trace through the physics world, supporting both single-shape and multi-shape (swept) traces depending on the filter configuration.

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `TraceShape.windows.yaml`
- `libserver.so` → `TraceShape.linux.yaml`
