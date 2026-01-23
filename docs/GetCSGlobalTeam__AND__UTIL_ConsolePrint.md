earch string `%sTeam playing \"CT\": %s\n`

look for the following snippet:
```cpp
  if ( a1 )
    v2 = a1;
  v4 = GetCSGlobalTeam(3);
  if ( v4 )
  {
    v5 = (_BYTE *)sub_18014F360(v4);
    if ( v5 && *v5 )
    {
      UTIL_ConsolePrint("%sTeam playing \"CT\": %s\n", v2, v5);
    }
    else if ( v3 )
    {
      UTIL_ConsolePrint("%sTeam \"CT\" is unset.\n", v2);
    }
  }
```

prototype: `CCSTeam *GetCSGlobalTeam(int teamIndex)`

prototype: `void UTIL_ConsolePrint(const char *fmt, ...)`

dll: `server`
