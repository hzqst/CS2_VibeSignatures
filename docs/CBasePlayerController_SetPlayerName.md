search string: "fov_desired" and "newname", and find xrefs for those two strings

find an identical function with references to both strings.

find following snippet

```cpp
  if ( *v7 && strcmp(v7, v6) )
  {
      v9 = (*...)(qword_181E9EE78, "player_changename", 0LL, 0LL);

      v34(v10, &v26, a2);        // userid
      v34(v10, &v26, v8);        // oldname
      v19(v10, &v26, v6);        // newname

      CBasePlayerController_SetPlayerName(a2, v6);  // 0x180c9c7e3
  }
```

prototype: `void CBasePlayerController::SetPlayerName(CBasePlayerController* pthis, const char *name)`

dll: `server`
