---
name: find-TraceFunc-AND-g_GameTraceManager
description: Find and identify the TraceFunc function and g_GameTraceManager global variable in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate TraceFunc by analyzing the FindUseEntity function and identifying the trace call with CTraceFilter vftable setup and the g_GameTraceManager global pointer.
---

# Find TraceFunc AND g_GameTraceManager

Locate `TraceFunc` (regular function) and `g_GameTraceManager` (global variable) in CS2 server.dll or server.so using IDA Pro MCP tools.

## Prerequisites

- `FindUseEntity` must already be identified (YAML must exist)

If missing, run `/find-FindUseEntity` first.

## Method

### 1. Get FindUseEntity function info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=FindUseEntity`.

If the skill returns an error, **STOP** and report to user.

### 2. Decompile FindUseEntity

```
mcp__ida-pro-mcp__decompile addr="<FindUseEntity_addr>"
```

### 3. Locate TraceFunc call inside FindUseEntity

Look for the following code pattern inside `FindUseEntity`:

```c
sub_XXXXXXXX(v182, v152, &v109, 798721LL);// This is TraceFunc, 798721LL is TraceFlags
```

Key identification:
- The call has 4 arguments
- The last argument is a large integer constant (trace flags, e.g. `798721LL` = `0xC3001`)
- This is a direct function call (not a vtable call)

Record the address of `sub_XXXXXXXX` — this is `TraceFunc`.

### 4. Rename TraceFunc

If the function is not already named `TraceFunc`:

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<TraceFunc_addr>", "name": "TraceFunc"}]}
```

### 5. Decompile TraceFunc and locate g_GameTraceManager

```
mcp__ida-pro-mcp__decompile addr="<TraceFunc_addr>"
```

Look for the following code pattern inside `TraceFunc`:

```c
  v12[0] = &CTraceFilter::`vftable';
  v13 = 0LL;
  v14 = -1LL;
  v15 = -1LL;
  v17 = -65536;
  v18 = 3584;
  v21 = 0;
  v19 = 3;
  v12[1] = a4;
  v16 = 0;
  sub_XXXXXXXXX((_DWORD)off_XXXXXXX, v8, a3, (unsigned int)v12, 1, (__int64)v4, 1);
```

Key identification:
- `CTraceFilter::\`vftable'` is assigned to `v12[0]` at the beginning
- `off_XXXXXXX` is `g_GameTraceManager` — a global pointer passed as the first argument to the inner call
- The inner call has 7 arguments

Record the address of `off_XXXXXXX` — this is `g_GameTraceManager`.

### 6. Rename g_GameTraceManager

If the global variable is not already named `g_GameTraceManager`:

```
mcp__ida-pro-mcp__rename batch={"data": {"old": "off_XXXXXXX", "new": "g_GameTraceManager"}}
```

### 7. Generate and validate unique signature for TraceFunc

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `TraceFunc`.

### 8. Write IDA analysis output for TraceFunc as YAML

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results for `TraceFunc`.

Required parameters:
- `func_name`: `TraceFunc`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 7

### 9. Generate and validate unique signature for g_GameTraceManager

**ALWAYS** Use SKILL `/generate-signature-for-globalvar` to generate a robust and unique signature for `g_GameTraceManager`.

### 10. Write IDA analysis output for g_GameTraceManager as YAML

**ALWAYS** Use SKILL `/write-globalvar-as-yaml` to write the analysis results for `g_GameTraceManager`.

Required parameters:
- `gv_name`: `g_GameTraceManager`
- `gv_addr`: The global variable address from step 5
- `gv_sig`: The validated signature from step 9
- `gv_sig_va`: The virtual address that signature matches
- `gv_inst_offset`: Offset from signature start to GV-accessing instruction
- `gv_inst_length`: Length of the GV-accessing instruction
- `gv_inst_disp`: Displacement offset within the instruction

## Function Characteristics

### TraceFunc

- **Type**: Regular function (not virtual)
- **Purpose**: Performs a game trace operation using `CTraceFilter` and `g_GameTraceManager`
- **Called from**: `FindUseEntity` (use-entity detection logic)
- **Parameters**: 4 arguments — trace start, trace end, output, trace flags
- **Behavior**:
  1. Sets up a `CTraceFilter` on the stack (assigns `CTraceFilter::\`vftable'`)
  2. Configures filter parameters (collision masks, layer flags, etc.)
  3. Calls through `g_GameTraceManager` to perform the actual trace
- **Unique Pattern**: `CTraceFilter::\`vftable'` assignment followed by a call with `g_GameTraceManager` as first arg

### g_GameTraceManager

- **Type**: Global pointer
- **Purpose**: Singleton pointer to the game trace manager, used for performing ray/hull traces in the game world
- **Access Pattern**: Typically accessed via `mov rcx, cs:g_GameTraceManager` or loaded as `off_XXXXXXX`
- **Related Class**: Implements a trace manager interface with methods for performing traces

## Output YAML Format

The output YAML filename for TraceFunc depends on the platform:
- `server.dll` → `TraceFunc.windows.yaml`
- `server.so` / `libserver.so` → `TraceFunc.linux.yaml`

The output YAML filename for g_GameTraceManager depends on the platform:
- `server.dll` → `g_GameTraceManager.windows.yaml`
- `server.so` / `libserver.so` → `g_GameTraceManager.linux.yaml`

## Troubleshooting

**If FindUseEntity YAML not found:**
- Run `/find-FindUseEntity` first to locate and generate the YAML

**If TraceFunc call not found in FindUseEntity:**
- Look for any call with a large integer constant as the last argument (trace flags)
- The trace flags value may differ across game versions, but the pattern of 4 arguments with the last being a constant remains

**If g_GameTraceManager not found in TraceFunc:**
- Look for a global pointer (`off_XXXXXXX`) used as the first argument in a call with 7 arguments
- The function should contain `CTraceFilter::\`vftable'` assignment nearby
