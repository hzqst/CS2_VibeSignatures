# CS2 VibeSignatures

To generate signatures/offsets for CS2 via Agent SKILLS & MCP Calls.

Our goal is to update signatures/offsets without human involved.

Currently, all signatures/offsets from `CounterStrikeSharp/config/addons/counterstrikesharp/gamedata/gamedata.json` can be updated automatically with this project.

* Signatures from old version of game will be used when available - to save as many tokens as possible.

* Avg cost for the first run: ~ 60$ for claude sonnet 4.5, or ~ 30$ for codex-5.3-high

* Avg time consume for the first run: 60 ~ 120 mins, depending on the model you are using.

* Avg time consume for the second run, when signatures from old version are available: 5mins ~ 15mins, depending on how many signatures are gone after game update.

* Feel free to contribute your SKILLS with PR! See `TODO: Add skill support for XXXXXX` in closed **Issues**.

## Requirements

1. `pip install pyyaml requests asyncio mcp vdf`

2. claude / codex

3. [skill-creator](https://github.com/anthropics/skills/blob/main/skills/skill-creator/SKILL.md), can be installed from claude marketplace.

4. IDA Pro 9.0+

5. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)

6. [idalib](https://docs.hex-rays.com/user-guide/idalib) (mandatory for `ida_analyze_bin.py`)

## Overall workflow

1. Download CS2 binaries

```bash
python download_bin.py -gamever 14135
```

2. Find and generate signatures for all symbols declared in `config.yaml`

 ```bash
 python ida_analyze_bin.py -gamever=14135 [-configyaml=path/to/config.yaml] [-modules=server] [-platform=windows] [-agent=claude/codex] [-maxretry=3] [-debug]
 ```

* Old signatures from `from bin/{previous_gamever}/{module}/{symbol}.{platform}.yaml` will be used to find symbols directly through mcp call before actually running Agent SKILL(s). No token will be consumed in this case.

3. Convert yaml(s) to gamedata json / txt

```bash
python update_gamedata.py -gamever 14135 [-debug]
```

### Currently supported gamedata

[CounterStrikeSharp](https://github.com/roflmuffin/CounterStrikeSharp)

`dist/CounterStrikeSharp/config/addons/counterstrikesharp/gamedata/gamedata.json`

 - 2 skipped symbols.

 - `GameEventManager`: not used anymore by CSS.
 - `CEntityResourceManifest_AddResource`: barely changes on game update.

[CS2Fixes](https://github.com/Source2ZE/CS2Fixes) 

`dist/CS2Fixes/gamedata/cs2fixes.games.txt`

 - 1 skipped symbol.

 - `CCSPlayerPawn_GetMaxSpeed` because it is not a thing in `server.dll`

[swiftlys2](https://github.com/swiftly-solution/swiftlys2) 

`dist/swiftlys2/plugin_files/gamedata/cs2/core/offsets.jsonc` 

`dist/swiftlys2/plugin_files/gamedata/cs2/core/signatures.jsonc`

 - 44 skipped symbols.

[plugify](https://github.com/untrustedmodders/plugify-plugin-s2sdk) 

`dist/plugify-plugin-s2sdk/assets/gamedata.jsonc`

 - 14 skipped symbols.
 
[cs2kz-metamod](https://github.com/Source2ZE/CS2Fixes) 

`dist/cs2kz-metamod/gamedata/cs2kz-core.games.txt`

 - 42 skipped symbols.
 
[modsharp](https://github.com/Kxnrl/modsharp-public) 

`dist/modsharp-public/.asset/gamedata/core.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/engine.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/EntityEnhancement.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/log.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/server.games.jsonc` 

`dist/modsharp-public/.asset/gamedata/tier0.games.jsonc`

 - 230 skipped symbols.
 
[CS2Surf/Timer](https://github.com/CS2Surf-CN/Timer) 

`dist/cs2surf/gamedata/cs2surf-core.games.jsonc` 

 - 26 skipped symbols.
 
## How to create SKILL for vtable

`CCSPlayerPawn` for example.

1. Create preprocessor script

 - Create a copy of `ida_preprocessor_scripts/find-CBaseEntity_vtable.py` as `ida_preprocessor_scripts/find-CCSPlayerPawn_vtable.py`

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

`CBaseModelEntity_SetModel` for example

* Always make sure you have ida-pro-mcp server running.

* For human contributor: You should write new initial prompts when working with new functions, **DO NOT** COPY-PASTE the initial prompts from README!!!

1. Verify and Create SKILL

  - We **SHOULD** verify the SKILL steps via ida-pro-mcp first

  - The SKILL should: search string "weapons/models/defuser/defuser.vmdl" in IDA, look for code snippet with following pattern in xrefs to the string:

```c
    v2 = a2;
    v3 = (__int64)a1;
    sub_180XXXXXX(a1, (__int64)"weapons/models/defuser/defuser.vmdl"); //This is CBaseModelEntity_SetModel, rename it to CBaseModelEntity_SetModel
    sub_180YYYYYY(v3, v2);
    v4 = (_DWORD *)sub_180ZZZZZZ(&unk_181AAAAAA, 0xFFFFFFFFi64);
    if ( !v4 )
      v4 = *(_DWORD **)(qword_181BBBBBB + 8);
    if ( *v4 == 1 )
    {
      v5 = (__int64 *)(*(__int64 (__fastcall **)(__int64, const char *, _QWORD, _QWORD))(*(_QWORD *)qword_181CCCCCC + 48i64))(
                        qword_181CCCCCC,
                        "defuser_dropped",
                        0i64,
                        0i64);
```

  - The SKILL should: generate CBaseModelEntity_SetModel.{platform}.yaml, with func_sig.

  - After successfully written the yaml, we **SHOULD** create project-level skill "find-CBaseModelEntity_SetModel" in **ENGLISH** according to previous operations. DO NOT pack skill. Note that the SKILL should be working with both `server.dll` and `server.so`. **ALWAYS** check other existing SKILL with "write-func-as-yaml" invocation for references.

2. Create preprocessor script

  - Create a copy of `ida_preprocessor_scripts/find-CCSPlayerController_ChangeTeam.py` as `ida_preprocessor_scripts/find-CBaseModelEntity_SetModel.py`

  - Don't forget to update the `TARGET_FUNCTION_NAMES` in the preprocessor script.

  - The preprocessor script will be used when signature from older version of game is available.

3. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` , `expected_input` (optional), `prerequisite` (optional) explicitly declared.

```yaml
      - name: find-CBaseModelEntity_SetModel
        expected_output:
          - CBaseModelEntity_SetModel.{platform}.yaml
```

4. Add the new symbol to `config.yaml`, under `symbols`.

```yaml
      - name: CBaseModelEntity_SetModel
        catagoty: func
        alias:
          - CBaseModelEntity::SetModel
```

## How to create SKILL for virtual function

`CBasePlayerController_Respawn` for example

* Always make sure you have ida-pro-mcp server running.

* For human contributor: You should write new initial prompts when working with new functions, **DO NOT** COPY-PASTE the initial prompts from README!!!

1. Verify and Create SKILL

  - We **SHOULD** verify the SKILL steps via ida-pro-mcp first

  - The SKILL should: search string "GMR_BeginRound" in IDA and look for a function with reference to it, decompile the function who reference "GMR_BeginRound" and look for code pattern:

```c
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
            (*(void (__fastcall **)(__int64))(*(_QWORD *)v30 + 2176LL))(v30); // 2176LL is vfunc_offset for CBasePlayerController_Respawn
          }
        }
        ++v28;
      }
      while ( v28 != v29 );
```

  - The SKILL should: generate `CBasePlayerController_Respawn.{platform}.yaml`, with `func_sig` (or `vfunc_sig` if `CBasePlayerController_Respawn` is too short or too generic).

  - After successfully written the yaml, we **SHOULD** create project-level skill "find-CBasePlayerController_Respawn" in **ENGLISH**. DO NOT pack skill. Note that the SKILL should be working with both `server.dll` and `server.so`. **ALWAYS** check other existing SKILL with "write-vfunc-as-yaml" invocation for references.

2. Create preprocessor script

  - Create a copy of `ida_preprocessor_scripts/find-CBaseEntity_IsPlayerPawn-AND-CBaseEntity_IsPlayerController.py` as `ida_preprocessor_scripts/find-CCSPlayerController_Respawn.py`

  - Don't forget to update `TARGET_FUNCTION_NAMES` in the preprocessor script.

  - The preprocessor script will be used when signature from older version of game is available.

3. Add the new SKILL to `config.yaml`, under `skills`.

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

4. Add the new symbol to `config.yaml`, under `symbols`.

```yaml
      - name: CBasePlayerController_Respawn
        category: vfunc
        alias:
          - CBasePlayerController::Respawn
```

## How to create SKILL for global variable

`IGameSystem_InitAllSystems` AND `IGameSystem_InitAllSystems_pFirst` for example

* Always make sure you have ida-pro-mcp server running.

* For human contributor: You should write new initial prompts when working with new global variables, **DO NOT** COPY-PASTE the initial prompts from README!!!

1. Verify and Create SKILL

  - We **SHOULD** verify the SKILL steps via ida-pro-mcp first

  - The SKILL should: search string "IGameSystem::InitAllSystems" in IDA, search xrefs for the string. the function with xref to the string is IGameSystem_InitAllSystems. rename it to IGameSystem_InitAllSystems if not renamed yet.
 
  - The SKILL should: look for code pattern at very beginning of IGameSystem_InitAllSystems: "( i = qword_XXXXXX; i; i = *(_QWORD *)(i + 8) )"
 
  - The SKILL should: rename "( i = qword_XXXXXX; i; i = *(_QWORD *)(i + 8) )" to "for ( i = IGameSystem_InitAllSystems_pFirst; i; i = *(_QWORD *)(i + 8) )" if it was not renamed yet.

  - The SKILL should: generate `IGameSystem_InitAllSystems.{platform}.yaml`, with `func_sig`.

  - The SKILL should: generate `IGameSystem_InitAllSystems_pFirst.{platform}.yaml`, with `gv_sig`.

  - After successfully written the yaml, we **SHOULD** create project-level skill "find-IGameSystem_InitAllSystems-AND-IGameSystem_InitAllSystems_pFirst" in **ENGLISH**. Don't pack skill. Note that the SKILL should be working with both `server.dll` and `server.so`. **ALWAYS** check other existing SKILL with "write-func-as-yaml" and "write-globalvar-as-yaml" invocation for references.
 
2. Create preprocessor script

  - Create a copy of `ida_preprocessor_scripts/find-CSource2Server_Init-AND-CGameEventManager_Init-AND-gameeventmanager-AND-s_GameEventManager.py` as `ida_preprocessor_scripts/find-IGameSystem_InitAllSystems-AND-IGameSystem_InitAllSystems_pFirst.py`

  - Don't forget to update `TARGET_FUNCTION_NAMES` and `TARGET_GLOBALVAR_NAMES` in the new preprocessor script.

  - The preprocessor script will be used when signature from older version of game is available.

3. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` , `expected_input` (optional), `prerequisite` (optional) explicitly declared.

```yaml
      - name: find-IGameSystem_InitAllSystems-AND-IGameSystem_InitAllSystems_pFirst
        expected_output:
          - IGameSystem_InitAllSystems.{platform}.yaml
          - IGameSystem_InitAllSystems_pFirst.{platform}.yaml
```

4. Add the new symbols to `config.yaml`, under `symbols`.

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

## How to create SKILL for struct offset

`CGameResourceService_BuildResourceManifest` AND `CGameResourceService_m_pEntitySystem` for example.

* Always make sure you have ida-pro-mcp server running.

* For human contributor: You should write new initial prompts when working with new struct offsets, **DO NOT** COPY-PASTE the initial prompts from README!!!

1. Verify and Create SKILL

  - We **SHOULD** verify the SKILL steps via ida-pro-mcp first

  - The SKILL should: search string "CGameResourceService::BuildResourceManifest(start)" in IDA, search xrefs for the string. 
      
      Get xrefs to the `CGameResourceService::BuildResourceManifest(start) [%d entities - %s]` variant string address:

      ```
      mcp__ida-pro-mcp__xrefs_to addrs="<string_address>"
      ```

      The xref should point to a function - this is `CGameResourceService_BuildResourceManifest`. rename it to `CGameResourceService_BuildResourceManifest` if not renamed yet.

  - The SKILL should: generate `CGameResourceService_BuildResourceManifest.{platform}.yaml`, with `func_sig`.

  - The SKILL should: generate `CGameResourceService_m_pEntitySystem.{platform}.yaml`, with `offset` and `offset_sig`.

  - After successfully written the yaml, we **SHOULD** create project-level skill "find-CGameResourceService_BuildResourceManifest-AND-CGameResourceService_m_pEntitySystem" in **ENGLISH**. DO NOT pack skill. Note that the SKILL should be working with both `server.dll` and `server.so`. **ALWAYS** check other existing SKILL with "write-structoffset-as-yaml" for references.

2. Create preprocessor script

```
 - Create a copy of `ida_preprocessor_scripts/find-FireBullets-AND-TraceAttack-AND-CTakeDamageInfo.py` as `ida_preprocessor_scripts/find-CGameResourceService_BuildResourceManifest-AND-CGameResourceService_m_pEntitySystem.py`

 - Don't forget to update `TARGET_FUNCTION_NAMES` and `TARGET_STRUCT_MEMBER_NAMES` in the new preprocessor script.

 - The preprocessor script will be used when signature from older version of game is available.
```

3. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` , `expected_input` (optional), `prerequisite` (optional) explicitly declared.

```yaml
      - name: find-CGameResourceService_BuildResourceManifest-AND-CGameResourceService_m_pEntitySystem
        expected_output:
          - CGameResourceService_BuildResourceManifest.{platform}.yaml
          - CGameResourceService_m_pEntitySystem.{platform}.yaml
```

4. Add the new symbols to `config.yaml`, under `symbols`.

```yaml
      - name: CGameResourceService_BuildResourceManifest
        category: func
        alias:
          - CGameResourceService::BuildResourceManifest
          - BuildResourceManifest

      - name: CGameResourceService
        category: struct

      - name: CGameResourceService_m_pEntitySystem
        category: structmember
        struct: CGameResourceService
        member: m_pEntitySystem
        alias:
          - GameEntitySystem

```

## How to create SKILL for patch

A patch SKILL locates a specific instruction inside a known function and generates replacement bytes to change its behavior at runtime (e.g., force/skip a branch, NOP a call). The prerequisite function must already have a find-SKILL.

* Always make sure you have ida-pro-mcp server running.

`CCSPlayer_MovementServices_FullWalkMove_SpeedClamp` for example — patching the velocity clamping `jbe` to an unconditional `jmp` inside `CCSPlayer_MovementServices_FullWalkMove`.

1. Verify and Create SKILL

  - We **SHOULD** verify the SKILL steps via ida-pro-mcp first

  - The SKILL should: decompile CCSPlayer_MovementServices_FullWalkMove and look for code pattern - whatever a float > A square of whatever a float:

```c
  v20 = (float)((float)(v16 * v16) + (float)(v19 * v19)) + (float)(v17 * v17);
  if ( v20 > (float)(v18 * v18) )
  {
    ...velocity clamping logic...
  }
```

  - The SKILL should: Disassemble around the comparison to find the exact conditional jump instruction.

  - The SKILL should: Disassemble around the comparison address to find the comiss + jbe instruction pair.

```
  Expected assembly pattern:
    addss   xmm2, xmm1          ; v20 = sum of squares
    comiss  xmm2, xmm0          ; compare v20 vs v18*v18
    jbe     loc_XXXXXXXX         ; skip clamp block if v20 <= v18*v18
```

```
  Determine the patch bytes based on the instruction encoding.

  * Near `jbe` (`0F 86 rel32` — 6 bytes) → `E9 <new_rel32> 90` (unconditional `jmp` + `nop`)
  * Short `jbe` (`76 rel8` — 2 bytes) → `EB rel8` (unconditional `jmp short`)
```

 - The SKILL should: generate `CCSPlayer_MovementServices_FullWalkMove.{platform}.yaml`, with `patch_sig` and `patch_bytes`.

 - After successfully written the yaml, we **SHOULD** create project-level skill "find-CCSPlayer_MovementServices_FullWalkMove_SpeedClamp" in **ENGLISH**. Don't pack skill. Note that the SKILL should be working with both `server.dll` and `server.so`. **ALWAYS** check existing SKILL with "write-patch-as-yaml" invocation for references.

2. Create preprocessor script.

 - Create `ida_preprocessor_scripts/find-CCSPlayer_MovementServices_FullWalkMove_SpeedClamp.py` and delegate to `preprocess_common_skill` with `patch_names`.

 - Define `TARGET_PATCH_NAMES = ["CCSPlayer_MovementServices_FullWalkMove_SpeedClamp"]`.

 - Pass `patch_names=TARGET_PATCH_NAMES` in `preprocess_common_skill(...)`.

 - The preprocessor will reuse old patch YAML and requires `patch_sig` to be uniquely matched in new binary (`find_bytes` result must be `== 1`), otherwise preprocessing fails and falls back to normal SKILL execution.

 * The preprocessor script will be used when patch YAML from older version of game is available.

3. Add the new SKILL to `config.yaml`, under `skills`.

 * with `expected_output` , `expected_input` (optional), `prerequisite` (optional) explicitly declared.

```yaml
      - name: find-CCSPlayer_MovementServices_FullWalkMove_SpeedClamp
        expected_output:
          - CCSPlayer_MovementServices_FullWalkMove_SpeedClamp.{platform}.yaml
        expected_input:
          - CCSPlayer_MovementServices_FullWalkMove.{platform}.yaml
        prerequisite:
          - find-CCSPlayer_MovementServices_FullWalkMove-AND-CCSPlayer_MovementServices_CheckVelocity-AND-CCSPlayer_MovementServices_WaterMove
```

4. Add the new symbol to `config.yaml`, under `symbols`.

```yaml
      - name: CCSPlayer_MovementServices_FullWalkMove_SpeedClamp
        category: patch
        alias:
          - ServerMovementUnlock
```

## Troubleshooting

### Cannot load IDA library file {name}, Please make sure you are using IDA 

This is because the official idapro package is not compatible with IDA 9.0

Mitigation: Overwrite `Python3**/Lib/site-packages/idapro/__init__.py` with `CS2_VibeSignatures/patched-py/Lib/site-packages/idapro/__init__.py`.

### error: could not create 'ida.egg-info': access denied

Mitigation: You should run `pip install .` and `python py-activate-idalib.py` under `C:\Program Files\IDA Professional 9.0\idalib\python` with **administrator** privilege.

### Could not find idalib64.dll in .........

Mitigation: Try `set IDADIR=C:\Program Files\IDA Professional 9.0` or add `IDADIR=C:\Program Files\IDA Professional 9.0` to your system environment.

## Jenkins workflow references

```bash
@echo Download latest game binaries

python download_bin.py -gamever %CS2_GAMEVER%
```

```bash
@echo Analyze game binaries

python ida_analyze_bin.py -gamever %CS2_GAMEVER% -agent="claude.cmd" -platform %CS2_PLATFORM% -debug
```

```bash
@echo Update gamedata with generated yamls

python update_gamedata.py -gamever %CS2_GAMEVER% -debug
```
