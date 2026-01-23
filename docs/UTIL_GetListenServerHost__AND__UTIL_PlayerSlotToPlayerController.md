search string `UTIL_GetListenServerHost() called from a dedicated server or single-player game.\n`

look for the following snippet:
```cpp
__int64 UTIL_GetListenServerHost()
{
  __int64 v0; // rdx
  __int64 v1; // r8

  if ( !(unsigned __int8)sub_180CFAA80() )
    return UTIL_PlayerSlotToPlayerController(0);
  Warning("UTIL_GetListenServerHost() called from a dedicated server or single-player game.\n", v0, v1);
  return 0i64;
}
```

prototype: `CBasePlayerController *UTIL_GetListenServerHost()`

prototype: `CBasePlayerController *UTIL_PlayerSlotToPlayerController(CPlayerSlot slot)`

dll: `server`
