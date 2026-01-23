search string: `Console command too long`

look for the following snippet:
```cpp
else
{
  sub_18075B2C0(v5, 2i64, "Console command too long.\n", 0i64, 0i64, 0i64, 0i64);
}
```

You should XREF the function that used the string.

prototype: `void ClientPrint(CBasePlayerController *player, int destination, const char *msg, ...);`

dll: `server`

![image](https://github.com/Salvatore-Als/cs2-signature-list/assets/58212852/2f50514a-520d-412d-b447-cc61534ecaa1)

