search string: `name \"%s\"` or `newname`, and xref

```cpp
                CBasePlayerController::SetPlayerName(v7, &v52);
                v37 = *(void (__fastcall **)(__int64, _QWORD, const char *, __int64))(*(_QWORD *)qword_18142C700 + 352i64);
                v38 = (*(__int64 (__fastcall **)(_DWORD *))(*(_QWORD *)v2 + 1032i64))(v2);
                sub_180B570E0(v7, &v53);
                if ( (_DWORD)v53 != -1 )
                  v3 = v53 - 1;
                v37(qword_18142C700, v3, "name \"%s\"", v38);
```

prototype: `void CBasePlayerController::SetPlayerName(CBasePlayerController* pthis, const char *name)`

dll: `server`
