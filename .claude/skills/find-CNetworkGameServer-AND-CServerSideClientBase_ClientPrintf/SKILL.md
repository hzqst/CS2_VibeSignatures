---
name: find-CNetworkGameServer-AND-CServerSideClientBase_ClientPrintf
description: Find and identify the CNetworkGameServer global pointer and CServerSideClientBase_ClientPrintf virtual function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the CNetworkGameServer instance by searching for the "tried to sprint to a non-client" debug string reference and analyzing the function that validates client slot indices and calls ClientPrintf via vtable.
---

# Find CNetworkGameServer and CServerSideClientBase_ClientPrintf

Locate `CNetworkGameServer` (global pointer) and `CServerSideClientBase_ClientPrintf` (virtual function) in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Search for the debug string

```
mcp__ida-pro-mcp__find_regex pattern="tried to sprint to a non-client"
```

### 2. Get cross-references to the string

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
```

### 3. Decompile the referencing function

```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

Verify the function matches this pattern:
```c
void __fastcall sub_XXXXXXXXXX(__int64 a1, int a2)
{
  __int64 v2; // rcx

  if ( qword_XXXXXXXXXX )  // CNetworkGameServer pointer
  {
    if ( a2 < 0 || a2 >= *(_DWORD *)(qword_XXXXXXXXXX + 592) ) // +0x250 = ClientList
    {
      ConMsg("tried to sprint to a non-client\n");
    }
    else
    {
      v2 = *(_QWORD *)(*(_QWORD *)(qword_XXXXXXXXXX + 600) + 8LL * a2); // +0x258 = client array
      (*(void (**)(__int64, const char *, ...))(*(_QWORD *)v2 + 128LL))(v2, "%s"); // +0x80 = ClientPrintf vfunc
    }
  }
}
```

Key identifications from the decompiled code:
- `qword_XXXXXXXXXX` = global `CNetworkGameServer` instance pointer
- Offset `0x250` (592) = `CNetworkGameServer.ClientList` (client count / max clients)
- Offset `0x258` (600) = Client list array pointer
- vfunc offset `0x80` (128) on `CServerSideClientBase` vtable = `ClientPrintf`

### 4. Rename the global variable

```
mcp__ida-pro-mcp__rename batch={"data": {"old": "qword_XXXXXXXXXX", "new": "CNetworkGameServer"}}
```

### 5. Write struct YAML for CNetworkGameServer

**ALWAYS** Use SKILL `/write-struct-as-yaml` to write CNetworkGameServer's struct member information:

For `CNetworkGameServer.{platform}.yaml`:
- Offset `0x250`: `ClientList`

### 6. Generate vfunc signature for CServerSideClientBase_ClientPrintf

Identify the instruction that performs the virtual call through vtable offset `0x80`. In step 3's decompiled output, find the line:
```c
(*(void (**)(...))(*(_QWORD *)v2 + 128LL))(v2, "%s");
```

The address comment (e.g. `/*0x1800acdd0*/`) on that line is the `inst_addr` for signature generation.

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CServerSideClientBase_ClientPrintf`, with:
- `inst_addr`: address of the instruction containing the `+0x80` vtable call
- `vfunc_offset`: `0x80`

### 7. Write vfunc YAML for CServerSideClientBase_ClientPrintf

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for `CServerSideClientBase_ClientPrintf`.

Required parameters:
- `func_name`: `CServerSideClientBase_ClientPrintf`
- `func_addr`: `None` (we only have the call site, not the function body)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 6

VTable parameters:
- `vtable_name`: `CServerSideClientBase`
- `vfunc_offset`: `0x80`
- `vfunc_index`: `16` (0x80 / 8)

## Signature Pattern

The function references this debug string:
```
"tried to sprint to a non-client\n"
```

## Function / Global Variable Characteristics

### CNetworkGameServer (global pointer)

- **Type**: Global pointer (`CNetworkGameServer*`)
- **Purpose**: Singleton pointer to the network game server instance, used for client management
- **Struct Members**:
  - `+0x250` (`ClientList`): Client count / max clients (`DWORD`)
  - `+0x258`: Pointer to client array (`CServerSideClientBase**`)
- **Access Pattern**: Typically accessed via `mov reg, cs:CNetworkGameServer` before client operations

### CServerSideClientBase_ClientPrintf (virtual function)

- **Class**: `CServerSideClientBase`
- **Method**: `ClientPrintf`
- **VTable Offset**: `0x80` (index 16)
- **Signature**: `void ClientPrintf(const char* fmt, ...)`
- **Purpose**: Sends a formatted text message to a specific connected client
- **Call Pattern**: Called via `call qword ptr [rax+80h]` or `jmp qword ptr [rax+80h]` on the client's vtable

## Output YAML Format

The output YAML filenames depend on the platform:

For CNetworkGameServer struct:
- `server.dll` → `CNetworkGameServer.windows.yaml`
- `server.so` → `CNetworkGameServer.linux.yaml`

For CServerSideClientBase_ClientPrintf vfunc:
- `server.dll` → `CServerSideClientBase_ClientPrintf.windows.yaml`
- `server.so` → `CServerSideClientBase_ClientPrintf.linux.yaml`
