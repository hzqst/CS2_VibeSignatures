---
name: find-CBasePlayerController_SetPawn
description: Find and identify the CBasePlayerController_SetPawn function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the SetPawn function by analyzing the cleanup sequence in CBasePlayerController virtual function index around 14 (12 ~ 16) and identifying the characteristic call pattern.
---

# Find CBasePlayerController_SetPawn

Locate `CBasePlayerController_SetPawn` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Get CBasePlayerController vtable address

**ALWAYS** Use SKILL `/get-vtable-address` to find vtable for `CBasePlayerController`.

### 2. Decompile virtual function index around 14 (12 ~ 16)

`vfunc_addr = vtable_start + (vtable_index * 8)`

```
mcp__ida-pro-mcp__decompile addr="<vfunc_addr>"
```

### 3. Identify CBasePlayerController_SetPawn call pattern

Look for the following pattern in the decompiled code:

```c
// Pattern to identify:
for ( i = *(_QWORD **)(a1 + 1928); i; i = (_QWORD *)i[7] )
{
  while ( 1 )
  {
    v15 = *(__int64 (__fastcall **)())(*i + 48LL);
    if ( v15 != nullsub_1097 )
      break;
    i = (_QWORD *)i[7];
    if ( !i )
      goto LABEL_22;
  }
  ((void (__fastcall *)(_QWORD *))v15)(i);
}
LABEL_22:
sub_XXXXXXX(a1, 0, 0, 0, 0, 0);  // <- This is CBasePlayerController_SetPawn
v16 = *(void (__fastcall ****)(_QWORD))(a1 + 2472);
if ( v16 )
{
  (**v16)(v16);
  *(_QWORD *)(a1 + 2472) = 0;
}
```

The target function is called:
- Immediately after iterating a linked list at offset 1928
- Each list node invokes virtual function at vtable offset +48, skipping nullsubs
- Called with parent object (a1) as first argument and all remaining arguments set to zero
- Immediately followed by releasing a function pointer at offset 2472

### 4. Rename the function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "CBasePlayerController_SetPawn"}]}
```

### 5. Generate and validate unique signature

**DO NOT** use `find_bytes` as it won't work for function.
**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 6. Write IDA analysis output as YAML beside the binary

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CBasePlayerController_SetPawn`
- `func_addr`: The function address from step 3
- `func_sig`: The validated signature from step 5

## Function Characteristics

- **Purpose**: Associates or disassociates a pawn with the player controller
- **Parameters**: `(controller, pawn_ptr, param2, param3, param4, param5)`
  - When called with all zeros: clears/nullifies the pawn assignment
- **Called from**: Virtual function index 14 (CBasePlayerController cleanup/destructor)
- **Function size**: ~0x53c bytes (1340 bytes) - may vary between versions

## Signature Pattern

The function has a distinctive prologue:

```
push    rbp
lea     rax, [rdi+7C0h]     ; Pawn offset in controller (0x7C0 = 1984 decimal)
mov     rbp, rsp
push    r15
mov     r15d, ecx
push    r14
push    r13
mov     r13d, r9d
push    r12
mov     r12, rsi
push    rbx
mov     rbx, rdi
sub     rsp, 68h
mov     ecx, [rdi+7C0h]     ; Same offset appears twice
```

Key identifying features:
- Offset 0x7C0 (1984) appears twice - this is the pawn field offset in CBasePlayerController (note that 0x7C0 can change on game updates)
- Standard function prologue with register preservation
- Stack allocation of 0x68 bytes (can change on game updates too)

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `CBasePlayerController_SetPawn.windows.yaml`
- `server.so` → `CBasePlayerController_SetPawn.linux.yaml`

```yaml
func_va: 0x1445610         # Virtual address of the function - changes with game updates
func_rva: 0x1445610        # Relative virtual address (VA - image base) - changes with game updates
func_size: 0x53c           # Function size in bytes - changes with game updates
func_sig: 55 48 8D 87 C0 07 00 00 48 89 E5 41 57 41 89 CF 41 56 41 55 45 89 CD 41 54 49 89 F4 53 48 89 FB 48 83 EC 68 8B 8F C0 07 00 00 44 89 45 80 48 89 45 88 83 F9 FF 0F 84 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ??
```
