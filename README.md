# CS2 VibeSignatures

Several scripts and prompts are included to generate signatures via Agent SKILLS.

Our goal is to update signatures/offsets without human involved.

Feel free to contibute your SKILLS!

## Requirements

1. claude / codex

2. https://github.com/mrexodia/ida-pro-mcp

3. https://github.com/anthropics/skills/blob/main/skills/skill-creator/SKILL.md

## For codex

Windows (Admin elevated):

```bash
mklink /J ".codex/skills" ".claude/skills"
```

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

## How to convert yaml to json / gamedata.txt (Valve KeyValues)

* TODO

## How to create SKILLS

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

2. Optionally, search vftable for virtual function, `CCSPlayerPawnBase_PostThink` in this case

```bash
Prompt: 
 - **ALWAYS** Use SKILL `/get-vftable-index` to get vtable offset and index for the function.
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
  **ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

  Required parameters:
  - `func_name`: `CCSPlayerPawnBase_PostThink`
  - `func_addr`: The function address from step 1
  - `func_sig`: The validated signature from step 3

  VTable parameters (if this is a virtual function):
  - `vfunc_name`: `CCSPlayerPawn`
  - `vfunc_mangled_name`: `??_7CCSPlayerPawn@@6B@` (Windows) or `_ZTV13CCSPlayerPawn` (Linux)
  - `vfunc_offset`: The offset from step 2
  - `vfunc_index`: The index from step 2
```

5. Create SKILL

```bash
Prompt:
 - /skill-creator Create project-level skill "find-{FunctionName}" in **ENGLISH** according to what we just did. Don't pack skill. Note that the SKILL should be working with both `server.dll` and `server.so`. **ALWAYS** check for @.claude/skills/find-CCSPlayerController_ChangeTeam/SKILL.md as reference.
```