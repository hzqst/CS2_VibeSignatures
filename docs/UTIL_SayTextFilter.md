xref `UTIL_SayTextFilter2`, look for the following snippet:

```cpp
if ( v59 )
{
    UTIL_SayTextFilter2((__int64)&v61, (__int64)v8, 1, v59, v19, v12, v60, 0i64);
}
else
{
    LOBYTE(v42) = 1;
    UTIL_SayTextFilter(&v61, v73, v8, v42);
}
```

prototype: `void UTIL_SayTextFilter2(IRecipientFilter* filter, const char* pText, CBasePlayerController* pPlayer, bool chat)`

dll: `server`
