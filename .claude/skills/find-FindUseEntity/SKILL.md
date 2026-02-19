---
name: find-FindUseEntity
description: Find and identify the FindUseEntity function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the FindUseEntity function by searching for the known debug string "Radial using: %s" and analyzing cross-references.
disable-model-invocation: true
---

# Find FindUseEntity

Locate `FindUseEntity` in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

1. Search for the debug string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="Radial using: %s"
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
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "FindUseEntity"}]}
   ```

5. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `FindUseEntity`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

## String References

The function contains a debug log call with format string:
- `Radial using: %s\n`
- `Trace using: %s\n`
- `no usable entity found`

## Function Characteristics

- **Prototype**: `__int64 *__fastcall FindUseEntity(_QWORD *pthis, float a2)`
- **Parameters**:
  - `arg0`: Player pawn pointer (this)
  - `arg1`: Dot product threshold (float)
- **Returns**: Pointer to the found entity, or NULL if no usable entity found

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `FindUseEntity.windows.yaml`
- `libserver.so` → `FindUseEntity.linux.yaml`
