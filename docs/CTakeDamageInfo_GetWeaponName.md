search string: `%.*s`, and xref

Looks for following code snippet:

```cpp
  else
  {
    v6 = (char *)&unk_180D9CE78;
  }
  if ( (unsigned __int8)sub_18053C0F0(v6) )
    return v6 + 7;
  v15 = sub_180D24DE0(v6, 95i64);
  v16 = v15;
  if ( !v15 || (unsigned int)V_stricmp_fast(v15, "_projectile") )
    return v6;
  sub_180636EE0(&unk_1814F3E00, "%.*s", (unsigned int)(v16 - (_DWORD)v6), v6);
  return (char *)&unk_1814F3E00;
}
```

prototype: `const char *CTakeDamageInfo::GetWeaponName(CTakeDamageInfo *pthis)`

dll: `server`