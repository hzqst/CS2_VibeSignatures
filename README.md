# CS2 VibeSignatures

To generate signatures/offsets for CS2 via Agent SKILLS & MCP Calls.

Our goal is to update signatures/offsets without human involved.

Currently, all signatures/offsets from `CounterStrikeSharp/config/addons/counterstrikesharp/gamedata/gamedata.json` can be updated automatically with this project.

* Signatures from old version of game will be used when available - to save as many tokens as possible.

* Avg cost for the first run: ~ 30$ for claude sonnet 4.5, or ~ 15$ for codex-5.3-high

* Avg time consume for the first run: 30mins ~ 60mins, depending on the model you are using.

* Avg time consume for the second run, when signatures from old version are available: 5mins ~ 15mins, depending on how many signatures are gone after game update.

* Feel free to contribute your SKILLS with PR!

## Requirements

1. `pip install pyyaml requests asyncio mcp vdf`

2. claude / codex

3. [skill-creator](https://github.com/anthropics/skills/blob/main/skills/skill-creator/SKILL.md), can be installed from claude marketplace.

4. IDA Pro 9.0+

5. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)

6. [idalib](https://docs.hex-rays.com/user-guide/idalib) (mandatory for `ida_analyze_bin.py`)

## How to find and generate signatures for all functions or variables declared in `config.yaml`

1. Download CS2 binaries

```bash
python download_bin.py -gamever 14135
```

2. Run `python ida_analyze_bin.py -gamever=14135 [-configyaml=path/to/config.yaml] [-modules=server] [-platform=windows] [-agent=claude/codex] [-maxretry=3] [-debug]`

* Signatures from `from bin/{previous_gamever}/{module}/*.{platform}.yaml` will be used to find functions / global vars directly through mcp call before actually running Agent SKILL(s). No token will be consumed in this case.

## How to convert generated yaml to gamedata json / txt

```bash
python update_gamedata.py -gamever 14135 [-debug]
```

### Currently supported gamedata

[CounterStrikeSharp](https://github.com/roflmuffin/CounterStrikeSharp)

`dist/CounterStrikeSharp/config/addons/counterstrikesharp/gamedata/gamedata.json`

[CS2Fixes](https://github.com/Source2ZE/CS2Fixes) 

`dist/CS2Fixes/gamedata/cs2fixes.games.txt`

[swiftlys2](https://github.com/swiftly-solution/swiftlys2) 

`dist/swiftlys2/plugin_files/gamedata/cs2/core/offsets.jsonc` 

`dist/swiftlys2/plugin_files/gamedata/cs2/core/signatures.jsonc`

[plugify](https://github.com/untrustedmodders/plugify-plugin-s2sdk) 

`dist/plugify-plugin-s2sdk/assets/gamedata.jsonc`

[cs2kz-metamod](https://github.com/Source2ZE/CS2Fixes) 

`dist/cs2kz-metamod/gamedata/cs2kz-core.games.txt`

[modsharp](https://github.com/Kxnrl/modsharp-public) 

`dist/modsharp-public/.asset/gamedata/core.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/engine.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/EntityEnhancement.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/log.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/server.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/tier0.games.jsonc`

[CS2Surf/Timer](https://github.com/CS2Surf-CN/Timer) 

`dist/cs2surf/gamedata/cs2surf-core.games.jsonc` 

## How to create SKILL for vtable

`CCSPlayerPawn` for example.

1. Create a copy of `ida_preprocessor_scripts/find-CBaseEntity_vtable.py` as `ida_preprocessor_scripts/find-CCSPlayerPawn_vtable.py`

 - Don't forget to change `CBaseEntity` to `CCSPlayerPawn` in the new preprocessor script.

 * no LLM needed when finding vtable. everything done in the preprocessor script.

2. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` , `expected_input` (optional), `prerequisite` (optional) explicitly declared.

```yaml
      - name: find-CCSPlayerPawn_vtable
        expected_output:
          - CCSPlayerPawn_vtable.{platform}.yaml
```

3. Add the new symbol to `config.yaml`, under `symbols`.

```yaml
      - name: CCSPlayerPawn_vtable
        category: vtable
```

## How to create SKILL for regular function

* Always make sure you have ida-pro-mcp server running.

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
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.
```

4. Write YAML

```bash
Prompt:
  **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results into yaml.
```

5. Create SKILL

```bash
Prompt:
 - /skill-creator Create project-level skill "find-CBaseModelEntity_SetModel" in **ENGLISH** according to what we just did. 
 - Don't pack skill.
 - Note that the SKILL should be working with both `server.dll` and `server.so`.
 - **ALWAYS** check for: @.claude/skills/find-CCSPlayerController_ChangeTeam/SKILL.md as references.
```

6. Create a copy of `ida_preprocessor_scripts/find-CCSPlayerController_ChangeTeam.py` as `ida_preprocessor_scripts/find-CBaseModelEntity_SetModel.py`

 - Don't forget to change `CCSPlayerController_ChangeTeam` to `CBaseModelEntity_SetModel` in the preprocessor script.

 * The preprocessor script will be used when signature from older version of game is available.

7. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` , `expected_input` (optional), `prerequisite` (optional) explicitly declared.

```yaml
      - name: find-CBaseModelEntity_SetModel
        expected_output:
          - CBaseModelEntity_SetModel.{platform}.yaml
```

8. Add the new symbol to `config.yaml`, under `symbols`.

```yaml
      - name: CBaseModelEntity_SetModel
        catagoty: func
        alias:
          - CBaseModelEntity::SetModel
```

## How to create SKILL for virtual function

* Always make sure you have ida-pro-mcp server running.

1. Vibe all the way down to get what you want, `CBasePlayerController_Respawn` for example.

```bash
Prompt:
  - search string "GMR_BeginRound" in IDA and look for a function with reference to it.
```

```bash
Prompt: 
  - decompile the function who reference "GMR_BeginRound" and look for code pattern:

      do
      {
        //.......
        if ( v31 )
        {
          if ( (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)v31 + 3352LL))(v31) )
          {
            (*(void (__fastcall **)(__int64))(*(_QWORD *)v33 + 3368LL))(v33);
            if ( v36 )
            {
              sub_1801C86D0(v36);
              sub_18039EA00(v36, 32LL);
            }
          }
          else if ( v36 && *(_BYTE *)(v30 + 836) == 3 || *(_BYTE *)(v30 + 836) == 2 )
          {
            sub_1809F9670(v36);
            (*(void (__fastcall **)(__int64))(*(_QWORD *)v30 + 2176LL))(v30);//2176LL is vfunc_offset for CBasePlayerController_Respawn
          }
        }
        ++v28;
      }
      while ( v28 != v29 );
```

```bash
Prompt: 
  **ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CBasePlayerController`.

  If the skill returns an error, **STOP** and report to user.

  Resolve CBasePlayerController_Respawn's address in CBasePlayerController's vtable entries:

  `CBasePlayerController_Respawn = CBasePlayerController vtable_entries[vfunc_offset / 8]`
```

2. Generate a robust signature for this function

```bash
Prompt:
   **ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for CBasePlayerController_Respawn, with `inst_addr` and `vfunc_offset` from previous step
```

5. Write YAML

```bash
Prompt:
  **ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results into yaml for CBasePlayerController_Respawn.
```

6. Create SKILL

```bash
Prompt:
 - /skill-creator Create project-level skill "find-CBasePlayerController_Respawn" in **ENGLISH** according to what we just did. 
 - Don't pack skill. 
 - Note that the SKILL should be working with both `server.dll` and `server.so`. 
 - **ALWAYS** check for: @.claude/skills/find-CBaseEntity_IsPlayerPawn/SKILL.md as references.
```

7. Create a copy of `ida_preprocessor_scripts/find-CBaseEntity_IsPlayerPawn.py` as `ida_preprocessor_scripts/find-CCSPlayerController_Respawn.py`

 - Don't forget to change `CBaseEntity_IsPlayerPawn` to `CBasePlayerController_Respawn` in the preprocessor script.

 * The preprocessor script will be used when signature from older version of game is available.

8. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` , `expected_input` (optional), `prerequisite` (optional) explicitly declared.

```yaml
      - name: find-CBasePlayerController_Respawn
        expected_output:
          - CBasePlayerController_Respawn.{platform}.yaml
        expected_input:
          - CBasePlayerController_vtable.{platform}.yaml
        prerequisite:
          - find-CBasePlayerController_vtable
```

9. Add the new symbol to `config.yaml`, under `symbols`.

```yaml
      - name: CBasePlayerController_Respawn
        category: vfunc
        alias:
          - CBasePlayerController::Respawn
```

## How to create SKILL for global variable

* Always make sure you have ida-pro-mcp server running.

1. Vibe all the way down to get what you want, `IGameSystem_InitAllSystems` AND `IGameSystem_InitAllSystems_pFirst` for example.

```bash
Prompt: 
 - search string "IGameSystem::InitAllSystems" in IDA
```

```bash
Prompt: 
 - search xrefs for this string
```

```bash
rename sub_1804F3DC0 to IGameSystem_InitAllSystems
```

```bash
rename "( i = qword_XXXXXX; i; i = *(_QWORD *)(i + 8) )" to "for ( i = IGameSystem_InitAllSystems_pFirst; i; i = *(_QWORD *)(i + 8) )" if it was not renamed yet.
```

2. Generate a robust signature for IGameSystem_InitAllSystems

```bash
Prompt:
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for IGameSystem_InitAllSystems.
```

3. Write YAML

```bash
Prompt:
  **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results for IGameSystem_InitAllSystems into yaml.
```

4. Generate a robust signature for IGameSystem_InitAllSystems_pFirst

```bash
Prompt:
   **ALWAYS** Use SKILL `/generate-signature-for-globalvar` to generate a robust and unique signature for IGameSystem_InitAllSystems_pFirst.
```

5. Write YAML

```bash
Prompt:
  **ALWAYS** Use SKILL `/write-globalvar-as-yaml` to write the analysis results for IGameSystem_InitAllSystems_pFirst into yaml.
```

6. Create SKILL

```bash
Prompt:
 - /skill-creator Create project-level skill "find-IGameSystem_InitAllSystems-AND-IGameSystem_InitAllSystems_pFirst" in **ENGLISH** according to what we just did.
 - Don't pack skill.
 - Note that the SKILL should be working with both `server.dll` and `server.so`.
 - **ALWAYS** check for @.claude/skills/find-CSource2Server_Init-AND-CGameEventManager_Init-AND-gameeventmanager-AND-s_GameEventManager/SKILL.md as references.
```

8. Create a copy of `ida_preprocessor_scripts/find-CSource2Server_Init-AND-CGameEventManager_Init-AND-gameeventmanager-AND-s_GameEventManager.py` as `ida_preprocessor_scripts/find-IGameSystem_InitAllSystems-AND-IGameSystem_InitAllSystems_pFirst.py`

 - Don't forget to update `TARGET_FUNCTION_NAMES` and `TARGET_GLOBALVAR_NAMES` in the new preprocessor script.

 * The preprocessor script will be used when signature from older version of game is available.

9. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` , `expected_input` (optional), `prerequisite` (optional) explicitly declared.

```yaml
      - name: find-IGameSystem_InitAllSystems-AND-IGameSystem_InitAllSystems_pFirst
        expected_output:
          - IGameSystem_InitAllSystems.{platform}.yaml
          - IGameSystem_InitAllSystems_pFirst.{platform}.yaml
```

8. Add the new symbols to `config.yaml`, under `symbols`.

```yaml
      - name: IGameSystem_InitAllSystems
        category: func
        alias:
          - IGameSystem::InitAllSystems

      - name: IGameSystem_InitAllSystems_pFirst
        category: gv
        alias:
          - IGameSystem::InitAllSystems::pFirst
```

## Troubleshooting

### Cannot load IDA library file {name}, Please make sure you are using IDA 

This is because the official idapro package is not compatible with IDA 9.0

Mitigation: Overwrite `Python3**/Lib/site-packages/idapro/__init__.py` with `CS2_VibeSignatures/patched-py/Lib/site-packages/idapro/__init__.py`.

### error: could not create 'ida.egg-info': access denied

Mitigation: You should run `pip install .` and `python py-activate-idalib.py` under `C:\Program Files\IDA Professional 9.0\idalib\python` with **administrator** privilege.

### Could not find idalib64.dll in .........

Mitigation: Try `set IDADIR=C:\Program Files\IDA Professional 9.0` or add `IDADIR=C:\Program Files\IDA Professional 9.0` to your system environment.

## Jenkins References

```bash
@echo Download latest game binaries

python download_bin.py -gamever %CS2_GAMEVER%
```

```bash
@echo Analyze with Claude and IDA-Pro-MCP

python ida_analyze_bin.py -gamever %CS2_GAMEVER% -agent=claude.cmd -platform %CS2_PLATFORM% -debug
```

```bash
@echo Sync symbol yamls to gamedata

python update_gamedata.py -gamever %CS2_GAMEVER% -debug
```