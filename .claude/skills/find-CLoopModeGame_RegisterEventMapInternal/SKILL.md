---
name: find-CLoopModeGame_RegisterEventMapInternal
description: Find and identify CLoopModeGame_RegisterEventMapInternal, RegisterEventListener_Abstract, and CLoopModeGame_OnXXXXXXX event handler functions in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 client binary to locate these functions by searching for the "CLoopModeGame::OnClientPollNetworking" string reference.
disable-model-invocation: true
---

# Find CLoopModeGame_RegisterEventMapInternal

Locate `CLoopModeGame_RegisterEventMapInternal`, `RegisterEventListener_Abstract`, and all `CLoopModeGame_OnXXXXXXX` event handler functions in CS2 `client.dll` or `libclient.so` using IDA Pro MCP tools.

## Method

### 1. Search for the anchor string

```
mcp__ida-pro-mcp__find_regex pattern="CLoopModeGame::OnClientPollNetworking"
```

### 2. Get cross-references to the string

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
```

There should be exactly one code xref — this is inside `CLoopModeGame_RegisterEventMapInternal`.

### 3. Decompile the referencing function

```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

### 4. Match the characteristic code pattern

The function takes 4 parameters `(a1, a2, a3, a4)` and has two main branches:
- When `a3 != 0`: Unregister events branch
- When `a3 == 0`: Register events branch (the one we care about)

In the register branch, look for repeated sequences of this pattern:

```c
// Each event registration follows this pattern:
unknown_libname_XXX(&v_local, &unk_XXXXXXXX);   // Get event descriptor
v_temp = v_local;
v_callback = sub_XXXXXXXX;                        // <-- This is a CLoopModeGame_OnXXXXXXX callback
v_handle = sub_XXXXXXXX(a2);                       // Get handle from a2
sub_XXXXXXXX(a1, &v_handle, 1, 1, v_temp, a4, "CLoopModeGame::OnXXXXXXX");  // <-- This is RegisterEventListener_Abstract
```

Key identifiers:
- **`CLoopModeGame_RegisterEventMapInternal`**: The outer function containing all the event registrations
- **`RegisterEventListener_Abstract`**: The function called with 7 arguments including the event name string as the last argument — it is the same function called for every event registration in the function
- **`CLoopModeGame_OnClientPollNetworking`**: The callback function pointer stored before the call with string `"CLoopModeGame::OnClientPollNetworking"`
- **`CLoopModeGame_OnClientAdvanceTick`**: The callback function pointer stored before the call with string `"CLoopModeGame::OnClientAdvanceTick"`
- Other `CLoopModeGame_OnXXXXXXX` callbacks: Each one is the function pointer stored before the corresponding `RegisterEventListener_Abstract` call with the matching `"CLoopModeGame::OnXXXXXXX"` string

### 5. Identify all event handler callbacks

Scan through the entire register branch and collect ALL `CLoopModeGame_OnXXXXXXX` callback function addresses paired with their event name strings. The event name strings follow the pattern `"CLoopModeGame::OnXXXXXXX"`.

For each registration block:
1. The callback function pointer is assigned to a local variable just before the `RegisterEventListener_Abstract` call
2. The event name string (last argument) tells you the callback name — strip the `::` and replace with `_`

### 6. Check if the functions are already renamed

```
mcp__ida-pro-mcp__lookup_funcs queries=["<RegisterEventMapInternal_addr>", "<RegisterEventListener_Abstract_addr>", "<callback1_addr>", "<callback2_addr>", ...]
```

### 7. Rename all functions that are still unnamed (`sub_` prefix)

```
mcp__ida-pro-mcp__rename batch={"func": [
  {"addr": "<addr>", "name": "CLoopModeGame_RegisterEventMapInternal"},
  {"addr": "<addr>", "name": "RegisterEventListener_Abstract"},
  {"addr": "<addr>", "name": "CLoopModeGame_OnClientPollNetworking"},
  {"addr": "<addr>", "name": "CLoopModeGame_OnClientAdvanceTick"},
  ... (all other CLoopModeGame_OnXXXXXXX callbacks)
]}
```

### 8. Generate and validate unique signatures

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for each function:

- `CLoopModeGame_RegisterEventMapInternal`
- `RegisterEventListener_Abstract`
- Each `CLoopModeGame_OnXXXXXXX` callback function

### 9. Write IDA analysis output as YAML beside the binary

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results for each function.

#### For `CLoopModeGame_RegisterEventMapInternal`:
Required parameters:
- `func_name`: `CLoopModeGame_RegisterEventMapInternal`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 8

#### For `RegisterEventListener_Abstract`:
Required parameters:
- `func_name`: `RegisterEventListener_Abstract`
- `func_addr`: The function address from step 4
- `func_sig`: The validated signature from step 8

#### For each `CLoopModeGame_OnXXXXXXX`:
Required parameters:
- `func_name`: The callback name (e.g., `CLoopModeGame_OnClientPollNetworking`)
- `func_addr`: The callback function address from step 5
- `func_sig`: The validated signature from step 8

Note: These are all regular functions, NOT virtual functions, so no vtable parameters are needed.

## Function Characteristics

### CLoopModeGame_RegisterEventMapInternal

- **Prototype**: `void CLoopModeGame_RegisterEventMapInternal(void *pLoopModeGame, void *a2, int bUnregister, int a4)`
- **Parameters**:
  - `pLoopModeGame`: Pointer to the CLoopModeGame instance
  - `a2`: Context parameter passed to event handle creation
  - `bUnregister`: When non-zero, unregisters events; when zero, registers events
  - `a4`: Additional parameter passed through to RegisterEventListener_Abstract
- **Behavior**: Registers (or unregisters) multiple game event listeners for the CLoopModeGame class

### RegisterEventListener_Abstract

- **Prototype**: `void RegisterEventListener_Abstract(void *pListener, void *pHandle, int a3, int a4, void *pEventDescriptor, int a6, const char *pszEventName)`
- **Parameters**:
  - `pListener`: The listener object (CLoopModeGame instance)
  - `pHandle`: Event handle
  - `a3`: Flag (typically 1)
  - `a4`: Flag (typically 1)
  - `pEventDescriptor`: Event descriptor pointer
  - `a6`: Additional parameter
  - `pszEventName`: Debug name string like `"CLoopModeGame::OnClientPollNetworking"`

### CLoopModeGame_OnXXXXXXX (event callbacks)

- **Prototype**: `void CLoopModeGame_OnXXXXXXX(void *pEvent)` (exact signature may vary)
- **Purpose**: Individual event handler callbacks for various game loop events

## DLL Information

- **DLL**: `client.dll` (Windows) / `libclient.so` (Linux)

## Notes

- All functions are regular functions, NOT virtual functions
- `RegisterEventListener_Abstract` is the same function called for every event registration — verify all calls reference the same address
- The number of event callbacks may vary between game versions — collect ALL of them from the register branch
- Each callback is uniquely identified by its paired event name string

## Output YAML Format

The output YAML filenames depend on the platform:
- `client.dll` → `CLoopModeGame_RegisterEventMapInternal.windows.yaml`, `RegisterEventListener_Abstract.windows.yaml`, `CLoopModeGame_OnClientPollNetworking.windows.yaml`, `CLoopModeGame_OnClientAdvanceTick.windows.yaml`, etc.
- `libclient.so` → `CLoopModeGame_RegisterEventMapInternal.linux.yaml`, `RegisterEventListener_Abstract.linux.yaml`, `CLoopModeGame_OnClientPollNetworking.linux.yaml`, `CLoopModeGame_OnClientAdvanceTick.linux.yaml`, etc.
