---
name: find-CSource2Server_Init-AND-CGameEventManager_Init-AND-gameeventmanager-AND-s_GameEventManager
description: Find and identify the CSource2Server_Init, CGameEventManager_Init, gameeventmanager, s_GameEventManagerin CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CSource2Server::Init function by searching for the "gameeventmanager->Init()" debug string reference and analyzing cross-references.
disable-model-invocation: true
---

# Find CSource2Server_Init

Locate `CSource2Server_Init`, `CGameEventManager_Init`, `gameeventmanager`, `s_GameEventManager` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Search for the debug string

```
mcp__ida-pro-mcp__find_regex pattern="gameeventmanager->Init\\(\\)"
```

### 2. Get cross-references to the string

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
```

### 3. Decompile the referencing function

```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

Verify the function contains the pattern:
```c
COM_TimestampedLog("gameeventmanager->Init()");
sub_XXXXXXXXXX((__int64)off_XXXXXXXX); //This is CGameEventManager_Init(gameeventmanager);
```

### 4. Rename the functions and global variables

#### Rename the function:
```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CSource2Server_Init"}]}
```

#### Rename the caller of `gameeventmanager` to `CGameEventManager_Init` (if found):
```
mcp__ida-pro-mcp__rename batch={"data": {"old": "sub_XXXXXXXXXX", "new": "CGameEventManager_Init"}}
```

#### Rename the game event manager pointer (if found):
```
mcp__ida-pro-mcp__rename batch={"data": {"old": "off_XXXXXXXX", "new": "gameeventmanager"}}
```

#### Rename the global class instance to s_GameEventManager (if found):

The pointer `gameeventmanager` points to a global class instance which is actually `s_GameEventManager`:

```
.data:0000000181B89710 off_181B89710   dq offset off_181B8AAD0
```

```
.data:0000000181B8CAB0 gameeventmanager   dq offset s_GameEventManager
```

This can be verified by checking `off_181B8AAD0`, it should points to "const CGameEventManager::`vftable'":

```
.data:0000000181B8AAD0 off_181B8AAD0   dq offset ??_7CGameEventManager@@6B@
.data:0000000181B8AAD0                                         ; DATA XREF: sub_1800D2C10+5E↑o
.data:0000000181B8AAD0                                         ; sub_180B46B50+2E↑o ...
.data:0000000181B8AAD0                                         ; const CGameEventManager::`vftable'
```

```
mcp__ida-pro-mcp__rename batch={"data": {"old": "off_XXXXXXXX", "new": "s_GameEventManager"}}
```

### 5. Find VTable and Calculate Offset

**ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.

VTable class name: `CSource2Server`

### 6. Generate and validate unique signature for CSource2Server_Init, CGameEventManager_Init

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CSource2Server_Init` and `CGameEventManager_Init`.

### 7. Write IDA analysis output as YAML beside the binary

  **ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for `CSource2Server_Init` and `CGameEventManager_Init`.

  #### For `CSource2Server_Init`:

  Required parameters:
  - `func_name`: `CSource2Server_Init`
  - `func_addr`: The function address of `CSource2Server_Init` from step 3
  - `func_sig`: The validated signature from step 6

  VTable parameters (when this is a virtual function):
  - `vtable_name`: `CSource2Server`
  - `vfunc_offset`: The offset from step 5
  - `vfunc_index`: The index from step 5

  **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results for `CGameEventManager_Init`.

  #### For `CGameEventManager_Init`:

  Required parameters:
  - `func_name`: `CGameEventManager_Init`
  - `func_addr`: The function address of `CGameEventManager_Init` from step 3
  - `func_sig`: The validated signature from step 6

### 8. Generate and validate unique signature for gameeventmanager and s_GameEventManager

   **ALWAYS** Use SKILL `/generate-signature-for-globalvar` to generate a robust and unique signature for: `gameeventmanager` and `s_GameEventManager`.

### 9. Write IDA analysis output for `gameeventmanager` as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-globalvar-as-yaml` to write the analysis results for `gameeventmanager` and `s_GameEventManager`.

  #### For `gameeventmanager`:

   Required parameters:
   - `gv_name`: `gameeventmanager`
   - `gv_addr`: The global variable address from step 4
   - `gv_sig`: The validated signature from step 10
   - `gv_sig_va`: The virtual address that signature matches
   - `gv_inst_offset`: Offset from signature start to GV-accessing instruction
   - `gv_inst_length`: Length of the GV-accessing instruction
   - `gv_inst_disp`: Displacement offset within the instruction

  #### For `s_GameEventManager`:

   Required parameters:
   - `gv_name`: `s_GameEventManager`
   - `gv_addr`: The global variable address from step 4
   - `gv_sig`: The validated signature from step 12
   - `gv_sig_va`: The virtual address that signature matches
   - `gv_inst_offset`: Offset from signature start to GV-accessing instruction
   - `gv_inst_length`: Length of the GV-accessing instruction
   - `gv_inst_disp`: Displacement offset within the instruction

## Signature Pattern

The function contains debug log calls with format strings:
```
COM_TimestampedLog("gameeventmanager->Init()");
COM_TimestampedLog("MathLib_Init");
COM_TimestampedLog("CEngineServiceRegistry::RegisterEngineServices()");
COM_TimestampedLog("CLoopModeRegistry::RegisterLoopModes()");
```

## Function / Global variable Characteristics

### CSource2Server_Init

- **Class**: `CSource2Server`
- **Method**: `Init`
- **Return type**: `__int64` (returns 0 or 1)
- **Purpose**: Initializes the Source 2 server, including game event manager, engine services, loop modes, and game systems
- **Behavior**:
  1. Checks initialization flag (`qword_182049188`)
  2. Parses command line for specific flags (hash `0x34D6B4E6`)
  3. Calls `COM_TimestampedLog("MathLib_Init")` and initializes math library
  4. Calls `COM_TimestampedLog("gameeventmanager->Init()")` and `CGameEventManager_Init(gameeventmanager)`
  5. Calls `COM_TimestampedLog("CEngineServiceRegistry::RegisterEngineServices()")` and registers engine services
  6. Calls `COM_TimestampedLog("CLoopModeRegistry::RegisterLoopModes()")` and registers loop modes
  7. Initializes game save/restore block set
  8. Calls `COM_TimestampedLog("InitGameSystems - Start/Finish")` and initializes game systems
  9. Logs startup message: `"[STARTUP] {%.3f} server module init %s\n"`
- **Unique Identifier**: Hash constant `0x34D6B4E6` in `mov edx, 34D6B4E6h` instruction

### CGameEventManager_Init

- **Purpose**: Initializes the game event manager by loading event definitions from three resource files
- **Parameters**: `(__int64 this)` where `this` is a pointer to the game event manager object (`gameeventmanager`)
- **Return type**: `char` (returns 1 on success)
- **Behavior**:
  1. Calls vtable offset +0x10 (`[rax+10h]`) for pre-initialization
  2. Loads `"resource/core.gameevents"` via vtable offset +0x08 (`[rax+8]`) with r8d=0
  3. Loads `"resource/game.gameevents"` via vtable offset +0x08 (`[rax+8]`) with r8d=0
  4. Loads `"resource/mod.gameevents"` via vtable offset +0x08 (`[rax+8]`) with r8d=1
- **Unique Pattern**: Three consecutive `lea rdx, string` + `call [rax+8]` sequences with different gameevents files

### gameeventmanager

- **Type**: Global pointer (`IGameEventManager2*`)
- **Purpose**: Singleton instance of the game event manager, used throughout the server for event dispatching
- **Initialization**: Set during server initialization, before `CGameEventManager_Init` is called
- **Related Class**: `CGameEventManager` (implements `IGameEventManager2` interface)
- **Access Pattern**: Typically accessed via `mov rcx, cs:gameeventmanager` before calling event manager methods
- **Related Symbols**:
  - `s_GameEventManager` - Static storage for the game event manager instance
  - `CGameEventManager` vtable at `??_7CGameEventManager@@6B@`

## Key Calls in Function

- `COM_TimestampedLog()` - Timestamped logging
- `CGameEventManager_Init()` - Initialize game event manager
- `CommandLine()` - Get command line interface
- `Plat_FloatTime()` - Get platform time
- `Msg()` - Output message

## VTable Information

- **VTable Name**: `CSource2Server`
- **VTable Mangled Name**:
  - Windows: May not have standard mangled name (check with `*CSource2Server*`)
  - Linux: `_ZTV14CSource2Server`
- **VTable Offset**: `0x18` (may change with game updates)
- **VTable Index**: `3` (may change with game updates)

## Output YAML Format

The output YAML filename for CSource2Server_Init depends on the platform:
- `server.dll` → `CSource2Server_Init.windows.yaml`
- `server.so` / `libserver.so` → `CSource2Server_Init.linux.yaml`

The output YAML filename for CGameEventManager_Init depends on the platform:
- `server.dll` → `CGameEventManager_Init.windows.yaml`
- `server.so` → `CGameEventManager_Init.linux.yaml`

The output YAML filename for gameeventmanager depends on the platform:
- `server.dll` → `gameeventmanager.windows.yaml`
- `server.so` → `gameeventmanager.linux.yaml`

The output YAML filename for s_GameEventManager depends on the platform:
- `server.dll` → `s_GameEventManager.windows.yaml`
- `server.so` → `s_GameEventManager.linux.yaml`

## Related Globals

- `gameeventmanager` (`0x181b89710` on Windows) - Global game event manager instance pointer (`IGameEventManager2*`)
- `s_GameEventManager` (`0x181b8aad0` on Windows) - Static storage for the game event manager instance
- `qword_182049188` - Initialization check flag (checked at function start)
- `byte_181EB5CB4` - Command line flag (set when specific command line option is present)
- `qword_181EB1CE8` - Engine interface pointer (checked before game systems init)
- `qword_181BC0A10` - Startup time storage (set via `Plat_FloatTime()`)
