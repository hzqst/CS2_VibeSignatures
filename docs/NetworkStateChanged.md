search string: `light_capsule`, and xref

```cpp
  if ( *(_QWORD *)(v10 + 32) )
    v3 = *(void **)(v10 + 32);
  v11 = V_stricmp_fast(v3, "light_capsule");
  v12 = *(_DWORD *)(v5 + 128) == 2;
  *(_BYTE *)(v5 + 132) = v11 == 0;
  if ( v12
    && *(_BYTE *)(v5 + 324)
    && *(_DWORD *)(v5 + 300) == 1
    && *(_DWORD *)(v5 + 196) == 1
    && *(_DWORD *)(v5 + 292) != -1
    && *(_BYTE *)(v5 + 417) != 1 )
  {
    NetworkStateChanged((_QWORD **)(v5 + 72), 417i64, 0xFFFFFFFFi64);
    *(_BYTE *)(v5 + 417) = 1;
    v13 = *(_QWORD *)(v5 + 64);
    if ( *(_BYTE *)(v5 + 448) )
      sub_18077A350(v13);
    else
      sub_18079A9E0(v13);
  }
  return 1;
}
```

prototype: `void NetworkStateChanged(void *chainEntity, int offset, int a3)`

dll: `server`