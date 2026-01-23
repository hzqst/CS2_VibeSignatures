search string: `defuser_pickup`, and xref

```cpp
  if ( *v6 == 1 )
  {
    pEvent = (*(__int64 (__fastcall **)(__int64, const char *, _QWORD, _QWORD))(*(_QWORD *)g_pgameevents
                                                                              + 48i64))(
                g_pgameevents,
                "defuser_pickup",
                0i64,
                0i64);
    if ( pEvent )
    {
      sub_180B598D0(pEntity, (__int64)&v8);
      sub_180101C10(pEvent, "entityid", v8);
      sub_180108F60(pEvent, "userid", v3);
      sub_180108F00(pEvent, "priority", 0i64);
      (*(void (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)g_pgameevents + 56i64))(
        g_pgameevents,
        pEvent,
        0i64);
    }
  }
  result = UTIL_Remove(pEntity);
```

prototype: `void UTIL_Remove(CEntityInstance* pEntity)`

dll: `server`