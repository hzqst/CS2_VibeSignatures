---
name: find-IGameSystem_InitAllSystems-AND-IGameSystem_InitAllSystems_pFirst
description: Find and identify IGameSystem_InitAllSystems (function) and IGameSystem_InitAllSystems_pFirst (global variable) in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the game system initialization linked list head pointer by searching for the "IGameSystem::InitAllSystems" string and analyzing cross-references.
---

# Find IGameSystem_InitAllSystems and IGameSystem_InitAllSystems_pFirst

Locate `IGameSystem_InitAllSystems` (function) and `IGameSystem_InitAllSystems_pFirst` (global variable) in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the debug string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="IGameSystem::InitAllSystems"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Verify the code pattern - look for:
   ```c
   ToolsStallMonitorInternal_BeginScope(v17);
   for ( i = IGameSystem_InitAllSystems_pFirst; i; i = *(_QWORD *)(i + 8) )
   {
     v2 = *(const char **)(i + 16);
     if ( *(_WORD *)CUtlSymbolTable::Find(&unk_XXXXXXXX, &v20, v2) != 0xFFFF )
     {
       Plat_FatalError("Game System %s is defined twice!\n", v2);
       __debugbreak();
     }
   ```

   * The matching function is "IGameSystem::InitAllSystems"

5. Rename the function (if not already named):
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "IGameSystem_InitAllSystems"}]}
   ```

6. Identify the global variable address and rename it:
   - The global variable is referenced in the for loop: `for ( i = IGameSystem_InitAllSystems_pFirst; ...`
   - If it shows as `qword_XXXXXXXX`, rename it:
   ```
   mcp__ida-pro-mcp__rename batch={"data": {"old": "<IGameSystem_InitAllSystems_pFirst_global_variable_address>", "new": "IGameSystem_InitAllSystems_pFirst"}}
   ```

7. Generate and validate unique signature for `IGameSystem_InitAllSystems`:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

8. Write IDA analysis output for `IGameSystem_InitAllSystems` as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `IGameSystem_InitAllSystems`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 7

   Note: This is NOT a virtual function, so no vtable parameters are needed.

9. Generate and validate unique signature for `IGameSystem_InitAllSystems_pFirst`:

   **ALWAYS** Use SKILL `/generate-signature-for-globalvar` to generate a robust and unique signature for the global variable: IGameSystem_InitAllSystems_pFirst.

10. Write IDA analysis output for `IGameSystem_InitAllSystems_pFirst` as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-globalvar-as-yaml` to write the analysis results.

   Required parameters:
   - `gv_name`: `IGameSystem_InitAllSystems_pFirst`
   - `gv_addr`: The global variable address from step 6
   - `gv_sig`: The validated signature from step 9
   - `gv_sig_va`: The virtual address that signature matches
   - `gv_inst_offset`: Offset from signature start to GV-accessing instruction
   - `gv_inst_length`: Length of the GV-accessing instruction
   - `gv_inst_disp`: Displacement offset within the instruction

## Code Pattern

The `IGameSystem_InitAllSystems` function iterates through a linked list of game systems:

```c
for ( i = IGameSystem_InitAllSystems_pFirst; i; i = *(_QWORD *)(i + 8) )
{
    // i + 0x00: unknown
    // i + 0x08: next pointer
    // i + 0x10: system name (const char*)
}
```

## Global Variable Characteristics

- **Type**: `qword` (8 bytes, pointer to linked list node)
- **Purpose**: Head pointer of the game system initialization linked list
- **Usage**: Iterated during game system initialization to register and initialize all game systems

## Instruction Pattern

The global variable is typically accessed with a RIP-relative MOV instruction:
```
48 8B 1D XX XX XX XX    mov rbx, cs:IGameSystem_InitAllSystems_pFirst
48 85 DB                test rbx, rbx
0F 84 XX XX XX XX       jz <skip_loop>
```

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `IGameSystem_InitAllSystems.windows.yaml`, `IGameSystem_InitAllSystems_pFirst.windows.yaml`
- `server.so` → `IGameSystem_InitAllSystems.linux.yaml`, `IGameSystem_InitAllSystems_pFirst.linux.yaml`

### Function YAML (IGameSystem_InitAllSystems)

```yaml
func_va: 0x1804F3DC0      # Virtual address of the function - changes with game updates
func_rva: 0x4F3DC0        # Relative virtual address (VA - image base) - changes with game updates
func_size: 0x329          # Function size in bytes - changes with game updates
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - changes with game updates
```

### Global Variable YAML (IGameSystem_InitAllSystems_pFirst)

```yaml
gv_va: 0x181d7d128        # Global variable virtual address - changes with game updates
gv_rva: 0x1d7d128         # Relative virtual address (VA - image base) - changes with game updates
gv_sig: 48 8B 1D ?? ?? ?? ?? 48 85 DB 0F 84 ?? ?? ?? ?? BD FF FF 00 00
gv_sig_va: 0x1804f3df3    # The virtual address that signature matches
gv_inst_offset: 0         # GV instruction starts at signature start
gv_inst_length: 7         # 48 8B 1D XX XX XX XX = 7 bytes
gv_inst_disp: 3           # Displacement offset starts at position 3 (after 48 8B 1D)
```

## Runtime Resolution

At runtime, after pattern scan finds the signature:

```cpp
// C++ example
uint8_t* instr_addr = scan_result + gv_inst_offset;
int32_t rip_offset = *(int32_t*)(instr_addr + gv_inst_disp);
void* gv_address = instr_addr + gv_inst_length + rip_offset;
```
