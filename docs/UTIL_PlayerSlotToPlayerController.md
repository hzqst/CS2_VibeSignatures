search string `splitscreenplayer`

xref

look for the following snippet:
```cpp
__int64 __fastcall sub_1806D9320(__int64 pthis, __int64 a2, const char *a3)
{
  _QWORD *v3; // rdi
  const char *v4; // r15
  __int64 v5; // rbx
  int v7; // eax
  __int64 v8; // r9
  int v10; // [rsp+30h] [rbp-28h] BYREF
  const char *v11; // [rsp+38h] [rbp-20h]

  v3 = (_QWORD *)(pthis + 24);
  *(_DWORD *)(pthis + 20) = -1073741760;
  v4 = a3;
  *(_QWORD *)pthis = vftable;
  v5 = a2;
  *(_DWORD *)(pthis + 16) = 0;
  LOBYTE(a3) = 7;
  *(_QWORD *)(pthis + 24) = 0LL;
  LOBYTE(a2) = 1;
  sub_180D54110(pthis + 88, a2, a3);
  *(_QWORD *)(pthis + 8) = v5;
  v7 = *(_DWORD *)(pthis + 20);
  if ( (v7 & 0x3FFFFFFF) != 0 )
  {
    if ( (v7 & 0x40000000) == 0 )
      v3 = (_QWORD *)*v3;
    *(_BYTE *)v3 = 0;
  }
  *(_DWORD *)(pthis + 16) &= 0xC0000000;
  CBufferString::Insert((CBufferString *)(pthis + 16), 0, v4, -1, 0);
  v10 = 729044430;
  LOBYTE(v8) = 19;
  v11 = "splitscreenplayer";
  sub_180D5D6E0(pthis + 88, &v10, 0xFFFFFFFFLL, v8);
  return pthis;
}
```

```
.rdata:0000000180F8DC18 40 F3 6D 80 01 00 00 00                         vftable         dq offset sub_1806DF340 ; DATA XREF: sub_1806D9320+23↑o
.rdata:0000000180F8DC20 B0 9A 6F 80 01 00 00 00                                         dq offset sub_1806F9AB0
.rdata:0000000180F8DC28 D0 97 6F 80 01 00 00 00                                         dq offset sub_1806F97D0
.rdata:0000000180F8DC30 D0 2E 70 80 01 00 00 00                                         dq offset sub_180702ED0
.rdata:0000000180F8DC38 80 2E 70 80 01 00 00 00                                         dq offset sub_180702E80
.rdata:0000000180F8DC40 00 2E 70 80 01 00 00 00                                         dq offset sub_180702E00
.rdata:0000000180F8DC48 A0 86 6F 80 01 00 00 00                                         dq offset sub_1806F86A0
.rdata:0000000180F8DC50 E0 97 6F 80 01 00 00 00                                         dq offset sub_1806F97E0
.rdata:0000000180F8DC58 20 AE 6F 80 01 00 00 00                                         dq offset sub_1806FAE20
.rdata:0000000180F8DC60 10 96 6F 80 01 00 00 00                                         dq offset sub_1806F9610
.rdata:0000000180F8DC68 E0 AD 6F 80 01 00 00 00                                         dq offset sub_1806FADE0
.rdata:0000000180F8DC70 50 A9 6F 80 01 00 00 00                                         dq offset sub_1806FA950
.rdata:0000000180F8DC78 10 89 6F 80 01 00 00 00                                         dq offset sub_1806F8910
.rdata:0000000180F8DC80 A0 89 6F 80 01 00 00 00                                         dq offset sub_1806F89A0
.rdata:0000000180F8DC88 50 89 6F 80 01 00 00 00                                         dq offset sub_1806F8950
.rdata:0000000180F8DC90 30 A6 6F 80 01 00 00 00                                         dq offset sub_1806FA630
.rdata:0000000180F8DC98 B0 9F 6F 80 01 00 00 00                                         dq offset GetPlayerController
.rdata:0000000180F8DCA0 10 A0 6F 80 01 00 00 00                                         dq offset sub_1806FA010
.rdata:0000000180F8DCA8 20 A2 6F 80 01 00 00 00                                         dq offset sub_1806FA220
.rdata:0000000180F8DCB0 20 A4 6F 80 01 00 00 00                                         dq offset sub_1806FA420
.rdata:0000000180F8DCB8 B0 A8 71 80 01 00 00 00                                         dq offset sub_18071A8B0
.rdata:0000000180F8DCC0 C0 AD 71 80 01 00 00 00                                         dq offset sub_18071ADC0
.rdata:0000000180F8DCC8 10 D7 71 80 01 00 00 00                                         dq offset sub_18071D710
.rdata:0000000180F8DCD0 D0 AB 71 80 01 00 00 00                                         dq offset sub_18071ABD0
.rdata:0000000180F8DCD8 E0 D6 71 80 01 00 00 00                                         dq offset sub_18071D6E0
.rdata:0000000180F8DCE0 E0 D4 71 80 01 00 00 00                                         dq offset sub_18071D4E0
.rdata:0000000180F8DCE8 00 AB 71 80 01 00 00 00                                         dq offset sub_18071AB00
.rdata:0000000180F8DCF0 80 AB 71 80 01 00 00 00                                         dq offset sub_18071AB80
.rdata:0000000180F8DCF8 10 D3 71 80 01 00 00 00                                         dq offset sub_18071D310
.rdata:0000000180F8DD00 B0 D0 71 80 01 00 00 00                                         dq offset sub_18071D0B0
.rdata:0000000180F8DD08 B0 D3 71 80 01 00 00 00                                         dq offset sub_18071D3B0
.rdata:0000000180F8DD10 C0 C6 6F 80 01 00 00 00                                         dq offset sub_1806FC6C0
.rdata:0000000180F8DD18 20 9B 71 80 01 00 00 00                                         dq offset sub_180719B20
.rdata:0000000180F8DD20 00 88 6F 80 01 00 00 00                                         dq offset sub_1806F8800
.rdata:0000000180F8DD28 D8 3D 17 81 01 00 00 00                                         dq offset unk_181173DD8
```

```
.text:00000001806F9FB0                                                 ; __int64 __fastcall GetPlayerController(__int64, __int64)
.text:00000001806F9FB0                                                 GetPlayerController proc near           ; DATA XREF: .rdata:0000000180F8DC98↓o
.text:00000001806F9FB0                                                                                         ; .pdata:00000001816D78E0↓o
.text:00000001806F9FB0
.text:00000001806F9FB0                                                 var_18          = dword ptr -18h
.text:00000001806F9FB0                                                 var_10          = qword ptr -10h
.text:00000001806F9FB0                                                 arg_0           = dword ptr  8
.text:00000001806F9FB0
.text:00000001806F9FB0 48 83 EC 38                                                     sub     rsp, 38h
.text:00000001806F9FB4 8B 02                                                           mov     eax, [rdx]
.text:00000001806F9FB6 4C 8D 44 24 20                                                  lea     r8, [rsp+38h+var_18]
.text:00000001806F9FBB 89 44 24 20                                                     mov     [rsp+38h+var_18], eax
.text:00000001806F9FBF 48 8B 42 08                                                     mov     rax, [rdx+8]
.text:00000001806F9FC3 48 8D 54 24 40                                                  lea     rdx, [rsp+38h+arg_0]
.text:00000001806F9FC8 48 89 44 24 28                                                  mov     [rsp+38h+var_10], rax
.text:00000001806F9FCD 48 8B 01                                                        mov     rax, [rcx]
.text:00000001806F9FD0 FF 50 78                                                        call    qword ptr [rax+78h]
.text:00000001806F9FD3 8B 4C 24 40                                                     mov     ecx, [rsp+38h+arg_0]
.text:00000001806F9FD7 E8 64 76 08 00                                                  call    UTIL_PlayerSlotToPlayerController_0
.text:00000001806F9FDC 48 83 C4 38                                                     add     rsp, 38h
.text:00000001806F9FE0 C3                                                              retn
.text:00000001806F9FE0                                                 GetPlayerController endp
```

prototype: `CBasePlayerController *UTIL_PlayerSlotToPlayerController(CPlayerSlot slot)`

dll: `server`
