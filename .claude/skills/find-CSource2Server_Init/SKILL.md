---
name: find-CSource2Server_Init
description: |
  Find and identify the CSource2Server_Init function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CSource2Server::Init function by searching for the "gameeventmanager->Init()" debug string reference and analyzing cross-references.
  Trigger: CSource2Server_Init, CSource2Server::Init, server initialization
---

# Find CSource2Server_Init

Locate `CSource2Server_Init` in CS2 server.dll or server.so using IDA Pro MCP tools.

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
sub_XXXXXXXXXX((__int64)s_GameEventManager);
```

### 4. Rename the function and global variable

Rename the function:
```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CSource2Server_Init"}]}
```

Rename the game event manager global (if found):
```
mcp__ida-pro-mcp__rename batch={"data": {"old": "off_XXXXXXXX", "new": "s_GameEventManager"}}
```

Rename the caller for `s_GameEventManager` to `CGameEventManager_Init` (if found):
```
mcp__ida-pro-mcp__rename batch={"data": {"old": "sub_XXXXXXXXXX", "new": "CGameEventManager_Init"}}
```

### 5. Find VTable and Calculate Offset

**ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.

VTable class name: `CSource2Server`

### 6. Generate and validate unique signature

**DO NOT** use `find_bytes` as it won't work for function.
**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 7. Write IDA analysis output as YAML beside the binary

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CSource2Server_Init`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 6

VTable parameters (when this is a virtual function):
- `vtable_name`: `CSource2Server`
- `vfunc_offset`: The offset from step 5
- `vfunc_index`: The index from step 5

## Signature Pattern

The function contains debug log calls with format strings:
```
COM_TimestampedLog("gameeventmanager->Init()");
COM_TimestampedLog("MathLib_Init");
COM_TimestampedLog("CEngineServiceRegistry::RegisterEngineServices()");
COM_TimestampedLog("CLoopModeRegistry::RegisterLoopModes()");
```

## Function Characteristics

- **Class**: `CSource2Server`
- **Method**: `Init`
- **Return type**: `__int64` (returns 0 or 1)
- **Purpose**: Initializes the Source 2 server, including game event manager, engine services, loop modes, and game systems

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

The output YAML filename depends on the platform:
- `server.dll` → `CSource2Server_Init.windows.yaml`
- `server.so` / `libserver.so` → `CSource2Server_Init.linux.yaml`

```yaml
func_va: 0x180c87700      # Virtual address of the function - changes with game updates
func_rva: 0xc87700        # Relative virtual address (VA - image base) - changes with game updates
func_size: 0x1e9          # Function size in bytes - changes with game updates
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - changes with game updates
vtable_name: CSource2Server
vfunc_offset: 0x18        # Offset from vtable start - changes with game updates
vfunc_index: 3            # vtable[3] - changes with game updates
```

## Related Globals

- `s_GameEventManager` - Global game event manager instance pointer
- `qword_182048208` - Initialization check flag
- `byte_181EB4D34` - Command line flag
