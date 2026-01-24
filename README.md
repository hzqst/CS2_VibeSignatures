# CS2 VibeSignatures

Several scripts are included to generate signatures via Agent SKILLS with ida-pro-mcp

Out goal is to update signatures/offsets for each game update without human involved.

Feel free to contibute your SKILLS!

## Requirements

1. claude / codex

2. https://github.com/mrexodia/ida-pro-mcp

3. https://github.com/anthropics/skills/blob/main/skills/skill-creator/SKILL.md

## How to locate functions or variables

Let's locate `CBaseModelEntity_SetModel` for example.

1. Download CS2 binaries
```bash
py .\download_bin.py -gamever 14132
```

2. Open `\CS2_VibeSignatures\bin\14132\server\server.dll` (`server.so`) with IDA-Pro, Ctrl+Alt+M to start MCP server.

3. Let claude do everything for you
```bash
claude /find-CBaseModelEntity_SetModel
```

4. `CBaseModelEntity_SetModel.windows.yaml` or `CBaseModelEntity_SetModel.linux.yaml` will be generated right beside `server.dll` / `server.so` if everything goes as expected

* Automation with headless IDA & subagents is coming soon.

## Export dump yaml

## How to create SKILLS

1. Vibe all the way down to get what you want, `CBaseModelEntity_SetModel` for example.

```bash
Prompt: 
 - search string: `weapons/models/defuser/defuser.vmdl` in IDA

● ida-pro-mcp - find_regex (MCP)(pattern: "weapons/models/defuser/defuser\\.vmdl")
```

```bash
Prompt: 
 - show xref for this string

● ida-pro-mcp - xrefs_to (MCP)(addrs: "0x18152e658")
```

```bash
Prompt: 
 - Can you find code snippet with following pattern in xrefs?

  v2 = a2;
  v3 = (__int64)a1;
  CBaseModelEntity_SetModel(a1, (__int64)"weapons/models/defuser/defuser.vmdl");
  sub_18084ABF0(v3, v2);
  v4 = (_DWORD *)sub_180CED000(&unk_1813D3728, 0xFFFFFFFFi64);
  if ( !v4 )
    v4 = *(_DWORD **)(qword_1813D3730 + 8);
  if ( *v4 == 1 )
  {
    v5 = (__int64 *)(*(__int64 (__fastcall **)(__int64, const char *, _QWORD, _QWORD))(*(_QWORD *)qword_18140DB60 + 48i64))(
                      qword_18140DB60,
                      "defuser_dropped",
                      0i64,
                      0i64);


● ida-pro-mcp - decompile (MCP)(addr: "0x1801B7550")
  ⎿ {
      "addr": "0x1801B7550",
      "code": "__int64 __fastcall sub_1801B7550(__int64 a1, __int64 a2)\n{\n  __int64 result; // rax\n\n  sub_180CD
    … +4 lines (ctrl+o to expand)


● ida-pro-mcp - decompile (MCP)(addr: "0x1801B8210")
  ⎿ {
      "addr": "0x1801B8210",
      "code": "__int64 __fastcall sub_1801B8210(__int64 a1, __int64 a2)\n{\n  _DWORD *v4; // rax\n  __int64 *v5; //
    … +76 lines (ctrl+o to expand)
```

```bash
Prompt: 
 - Rename sub_180A8B930 to CBaseModelEntity_SetModel in IDA

● ida-pro-mcp - rename (MCP)(batch: {"func":{"addr":"0x180A8B930","name":"CBaseModelEntity_SetModel"}})
  ⎿  {
       "func": [
         {
     … +9 lines (ctrl+o to expand)
```

```bash
Prompt: (optional, for virtual function, CCSPlayerPawnBase_PostThink in this case)
 - xref CCSPlayerPawnBase_PostThink

```

```bash
Prompt: (optional, for virtual function, CCSPlayerPawnBase_PostThink in this case)
 - search upward from the read-only address that points to CCSPlayerPawnBase_PostThink, and check if any similar things like:

  ```c
  .rdata:0000000181533788 ; const CCSPlayerPawn::`vftable'
  .rdata:0000000181533788 ??_7CCSPlayerPawn@@6B@
  ```

  ```c
  .data.rel.ro:0000000002114CD0 ; `vtable for'CCSPlayerPawn
  .data.rel.ro:0000000002114CD0 _ZTV13CCSPlayerPawn dq 0 
  ```

  or like the virtuall function table of CCSPlayerPawnBase_PostThink's class

```

```bash

Prompt:
 - Write `{FunctionName}.windows.yaml` / `{FunctionName}.linux.yaml` beside the `server.dll` / `server.so` being analyzed, with the following content:

  For virtual function:

  ```yaml
  func_va: 0x180ABCDEF
  func_rva: 0xABCDEF
  func_size: 0xABC
  vfunc_name: CCSPlayerPawn
  vfunc_mangled_name: _ZTV13CCSPlayerPawn
  vfunc_offset: 0xA00
  vfunc_index: 320
  ```

  For non-virtual function:

  ```yaml
  func_va: 0x180ABCDEF
  func_rva: 0xABCDEF
  func_size: 0xABC
  ```

  * func_rva is calculated with `func_va - ImageBase`

```

```bash
Prompt:
 - /skill-creator Create project-level skill "find-CBaseModelEntity_SetModel" in English according to what we just did, so we can write yaml when using SKILL next time. Don't pack skill. Note that the SKILL should be working with both `server.dll` and `server.so`. You can check for @.claude/skills/find-CCSPlayerController_ChangeTeam/SKILL.md as reference.

● Write \CS2_VibeSignatures\.claude\skills\find-CBaseModelEntity_SetModel\SKILL.md
```