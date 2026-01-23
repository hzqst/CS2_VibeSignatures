search string: `UTIL_ClientPrint`

look for the following snippet:
```cpp
if ( (*(_DWORD *)(a1 + 864) & 0x100) == 0 )
{
	v2 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)a1 + 1032i64))(a1);
	V_strncpy(v31, v2, 128i64);
	v3 = v31;
	do
	{
	  if ( !*v3 )
		break;
	  if ( *v3 == 37 )
		*v3 = 32;
	  ++v3;
	}
	while ( v3 );
	v4 = v31;
	if ( !v31[0] )
	  v4 = "<unconnected>";
	sub_180948060(1, (unsigned int)"#Cstrike_TitlesTXT_Game_connected", (_DWORD)v4, 0, 0i64, 0i64);
}
```

You should XREF the function that used the string "Cstrike_TitlesTXT_Game_connected"

prototype: `void UTIL_ClientPrintAll(int destination, const char *message, const char *param1, const char *param2, const char *param3, const char *param4)`

dll: `server`

![image](https://img001.prntscr.com/file/img001/YOtHPJTDTIyU7vggi8U__A.pngs)

```cpp
#define HUD_PRINTNOTIFY		1
#define HUD_PRINTCONSOLE	2
#define HUD_PRINTTALK		3
#define HUD_PRINTCENTER		4
```