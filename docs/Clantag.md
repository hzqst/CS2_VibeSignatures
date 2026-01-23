search string `clantag`

Search this snippet

```
if ( !strcmp(Name, "ClanTagChanged") && (*(unsigned __int8 (__fastcall **)(_BYTE *))(*(_QWORD *)a1 + 912i64))(a1) )
    {
      String = KeyValues::GetString(a3, "tag", byte_180D76F38, 0i64, 0i64);
      sub_180638D90(a2, String);
      v8 = KeyValues::GetString(a3, "name", byte_180D76F38, 0i64, 0i64);
      sub_180638D70(a2, v8);
      sub_180566710(a1, 2i64);
      sub_180566710(a1, 3i64);
    }
```

On my snippet, the function is the one after `String = KeyValues::GetString(a3, "tag", byte_180D76F38, 0i64, 0i64);` so XREF `sub_180638D90`.

args: `CBasePlayerController *pController, char clantag`

dll: `server`

![image](https://github.com/Salvatore-Als/cs2-signature-list/assets/58212852/06249c88-2922-406d-9bdd-fd9e4f22dcce)

