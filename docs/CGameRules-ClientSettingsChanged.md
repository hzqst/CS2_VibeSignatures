search string `fov_desired`, xref

look for the following snippet:
```cpp
if ( (_DWORD)PlayerInfo != -1 )
    v4 = (_DWORD)PlayerInfo - 1;
  v31 = (_BYTE *)v30(g_Source2EngineToServer, v4, "fov_desired");
```
You should have the oldname, newname and player_changename on the function.

the current function is `CGameRules::ClientSettingsChanged`

prototype: `bool CGameRules::ClientSettingsChanged(CGameRules *pGameRules, CBasePlayerController *pPlayerController)`

dll: `server`
