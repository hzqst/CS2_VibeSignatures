# CS2 VibeSignatures

Several scripts and prompts are included to generate signatures via Agent SKILLS.

Our goal is to update signatures/offsets without human involved.

Feel free to contribute your SKILLS with PR!

## Requirements

1. `pip install yaml requests asyncio mcp vdf`

2. claude / codex

3. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)

4. [skill-creator](https://github.com/anthropics/skills/blob/main/skills/skill-creator/SKILL.md), can be installed from claude marketplace.

5. [idalib](https://docs.hex-rays.com/user-guide/idalib) (mandatory for `ida_analyze_bin.py`)

## How to find and generate signatures for specified function or variable

Let's locate `CBaseModelEntity_SetModel` for example.

1. Download CS2 binaries

```bash
python download_bin.py -gamever 14132
```

2. Open `CS2_VibeSignatures/bin/14132/server/server.dll` (`server.so`, or whatever) with IDA-Pro (GUI), wait until auto-analysis complete, Ctrl+Alt+M to start MCP server.

3. Let claude / codex do everything for you

claude (no-interactive-mode)

```bash
claude -p "/find-CBaseModelEntity_SetModel" --agent sig-finder
```

claude (interactive-mode)

```bash
claude
```

```bash
prompt:
 - /find-CCSPlayerController_ChangeTeam
```

codex (no-interactive-mode)

```bash
codex exec "Run SKILL: .claude/skills/find-CCSPlayerController_ChangeTeam/SKILL.md"
```

codex (interactive-mode)

```bash
codex
```

```bash
prompt:
 - Run SKILL: .claude/skills/find-CCSPlayerController_ChangeTeam/SKILL.md
```

4. `CBaseModelEntity_SetModel.windows.yaml` or `CBaseModelEntity_SetModel.linux.yaml` will be generated right beside `server.dll` / `server.so` if everything goes as expected

* Automation with headless IDA & subagents is coming soon.

## How to find and generate signatures for all functions or variables declared in `config.yaml`

1. Download CS2 binaries

```bash
python download_bin.py -gamever 14132
```

2. Run `python ida_analyze_bin.py -gamever=14132 [-configyaml=path/to/config.yaml] [-modules=server] [-platform=windows] [-agent=claude/codex] [-debug]`

## How to convert generated yaml to gamedata json / txt

```bash
python update_gamedata.py -gamever 14132
```

### Current supported gamedata dist

[CounterStrikeSharp](https://github.com/roflmuffin/CounterStrikeSharp) `dist/CounterStrikeSharp/config/addons/counterstrikesharp/gamedata/gamedata.json`

[CS2Fixes](https://github.com/Source2ZE/CS2Fixes) `dist/CS2Fixes/gamedata/cs2fixes.games.txt`

[swiftlys2](https://github.com/swiftly-solution/swiftlys2) 

`dist/swiftlys2/plugin_files/gamedata/cs2/core/offsets.jsonc` 

`dist/swiftlys2/plugin_files/gamedata/cs2/core/signatures.jsonc`

[plugify](https://github.com/untrustedmodders/plugify-plugin-s2sdk) `dist/plugify-plugin-s2sdk/assets/gamedata.jsonc`

## How to create SKILL for: find-{function}

1. Vibe all the way down to get what you want, `CBaseModelEntity_SetModel` for example.

```bash
Prompt: 
 - search string `weapons/models/defuser/defuser.vmdl` in IDA
```

```bash
Prompt: 
 - show xref for this string
```

```bash
Prompt: 
 - Find code snippet with following pattern in xrefs

  v2 = a2;
  v3 = (__int64)a1;
  sub_180A8B930(a1, (__int64)"weapons/models/defuser/defuser.vmdl");
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
```

```bash
Prompt: 
 - Rename sub_180A8B930 to CBaseModelEntity_SetModel in IDA
```

3. Generate a robust signature for this function

```bash
Prompt:
   Generate a robust signature for this function
   -- **DO NOT** use `find_bytes` as it won't work for function.
   -- **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.
```

4. Write YAML

```bash
Prompt:
  **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results into yaml.
```

5. Create SKILL

```bash
Prompt:
 - /skill-creator Create project-level skill "find-{FunctionName}" in **ENGLISH** according to what we just did. Don't pack skill. Note that the SKILL should be working with both `server.dll` and `server.so`. **ALWAYS** check for: @.claude/skills/find-CCSPlayerController_ChangeTeam/SKILL.md and  @.claude/skills/find-CCSPlayerPawnBase_PostThink/SKILL.md 
   as references.
```

## How to create SKILL for: find-{vtable}

1. Vibe all the way down to get what you want, `CCSPlayerPawn_vtable` for example.

```bash
Prompt: 
 - **ALWAYS** Use SKILL: `/get-vtable-address` to find vtable for `CCSPlayerPawn`.
```

* For interface vtable like Source2Server, see `.claude/skills/find-CSource2Server_vtable/SKILL.md`

2. Write YAML

```bash
Prompt:
  - **ALWAYS** Use SKILL `/write-vtable-as-yaml` to write the analysis results into yaml.
```

3. Create SKILL

```bash
Prompt:
 - /skill-creator Create project-level skill "find-{vtableName}_vtable" in **ENGLISH** according to what we just did. Don't pack skill. Note that the SKILL should be working with both `server.dll` and `server.so`. **ALWAYS** check for: @.claude/skills/find-CGameRules_vtable/SKILL.md as references.
```

## How to create SKILL for: find-{virtualfunction}

1. Vibe all the way down to get what you want, `CCSPlayerController_Respawn` for example.

```bash
Prompt: 
 - **ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CCSPlayerController`.

  If the skill returns an error, **STOP** and report to user.

  Otherwise, extract these values for subsequent steps:
  - `vtable_va`: The vtable start address (use as `<VTABLE_START>`)
  - `vtable_numvfunc`: The valid vtable entry count (last valid index = count - 1)

```

```bash
Prompt: 

  - List virtual functions from index 270 to the last valid index:

  mcp__ida-pro-mcp__py_eval code="""
  import ida_bytes, ida_name

  vtable_start = <VTABLE_START>  # Use calculated vtable_start from step 1
  ptr_size = 8
  start_index = 270
  end_index = <LAST_VALID_INDEX>  # Use (vtable_numvfunc - 1) from step 1

  for i in range(start_index, end_index + 1):
      func_ptr = ida_bytes.get_qword(vtable_start + i * ptr_size)
      func_name = ida_name.get_name(func_ptr) or "unknown"
      print(f"vftable[{i}]: {hex(func_ptr)} -> {func_name}")
  """
    
  - Then decompile each function with:

  mcp__ida-pro-mcp__decompile addr="<function_addr>"


```

```bash
Prompt: 
 - Identify CCSPlayerController_Respawn with following code pattern:

    result = GetPlayerPawn(a1);  // Called once
    if ( result )
    {
        v6 = GetPlayerPawn(a1);  // Called again (same function)
        return (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v6 + PAWN_VFUNC_OFFSET))(v6);
    }
    return result;
```

```bash
Prompt: 
 - Rename the virtual function we found to CCSPlayerController_Respawn in IDA
```

3. Get vtable index for this function

```bash
Prompt: 
 - **ALWAYS** Use SKILL `/get-vtable-index` to get vtable offset and index for the function.
```

4. Generate a robust signature for this function

```bash
Prompt:
   Generate a robust signature for this function
   -- **DO NOT** use `find_bytes` as it won't work for function.
   -- **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.
```

5. Write YAML

```bash
Prompt:
  **ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results into yaml.
```

6. Create SKILL

```bash
Prompt:
 - /skill-creator Create project-level skill "find-{FunctionName}" in **ENGLISH** according to what we just did. Don't pack skill. Note that the SKILL should be working with both `server.dll` and `server.so`. **ALWAYS** check for: @.claude/skills/find-CCSPlayerPawnBase_PostThink/SKILL.md as references.
```

## Troubleshooting

### Cannot load IDA library file {name}, Please make sure you are using IDA 

This is because the official idapro package is not compatible with IDA 9.0

Mitigation: Overwrite `Python3**/Lib/site-packages/idapro/__init__.py` with `CS2_VibeSignatures/patched-py/Lib/site-packages/idapro/__init__.py`.

### error: could not create 'ida.egg-info': access denied

Mitigation: You should run `pip install .` and `python py-activate-idalib.py` under `C:\Program Files\IDA Professional 9.0\idalib\python` with **administrator** privilege.

### Could not find idalib64.dll in .........

Mitigation: Try `set IDADIR=C:\Program Files\IDA Professional 9.0` or add `IDADIR=C:\Program Files\IDA Professional 9.0` to your system environment.

### py_eval evaulates unexpected expression with multi-line code

See https://github.com/mrexodia/ida-pro-mcp/pull/240

Mitigation: 
 - Overwrite `Python3**/Lib/site-packages/ida_pro_mcp/ida_mcp/api_python.py` with `CS2_VibeSignatures/patched-py/Lib/site-packages/ida_pro_mcp/ida_mcp/api_python.py`.
 - Overwrite `%APPDATA%/Hex-Rays/IDA Pro/plugins/ida_mcp/api_python.py` with `CS2_VibeSignatures/patched-py/Lib/site-packages/ida_pro_mcp/ida_mcp/api_python.py`.