I have disassembly outputs and procedure code for multiple related functions.

These are the reference functions:

{reference_blocks}

These are the target functions you need to reverse-engineering:

{target_blocks}

What you need to do is to collect all references to "{symbol_name_list}" in the target functions you need to reverse-engineering and output those references as YAML.

Example:

```yaml
found_vcall: # This is for indirect call to virtual function or virtual function pointer fetching.

  - insn_va: '0x180777700'               # Always be the instruction with displacement offset
    insn_disasm: call    [rax+68h]       # Always be the instruction with displacement offset
    vfunc_offset: '0x68'
    func_name: ILoopMode_OnLoopActivate

  - insn_va: '0x180777778'               # Always be the instruction with displacement offset
    insn_disasm: mov     rax, [rax+80h]  # Always be the instruction with displacement offset
    vfunc_offset: '0x80'
    func_name: INetworkMessages_GetNetworkGroupCount # This must be the true function name we asked to collect, not the sub_XXXXXXXX

found_call: # This is for direct call to non-virtual regular function.

  - insn_va: '0x180888800'
    insn_disasm: call    sub_180999900
    func_name: CLoopModeGame_RegisterEventMapInternal

  - insn_va: '0x180888880'
    insn_disasm: call    sub_180555500
    func_name: CLoopModeGame_SetGameSystemState   # This must be the true function name we asked to collect, not the sub_XXXXXXXX

found_funcptr: # This is for non-virtual regular function pointer.

  - insn_va: '0x180666600'                # Must load/reference the function pointer target address
    insn_disasm: lea     rdx, sub_15BC910 # Must load/reference the function pointer target address
    funcptr_name: CLoopModeGame_OnClientPollNetworking   # This must be the true function name we asked to collect, not the sub_XXXXXXXX

found_gv: # This is for reference to global variable.

  - insn_va: '0x180444400'
    insn_disasm: mov     rcx, cs:qword_180666600 # Must load/reference the global variable
    gv_name: g_pNetworkMessages  # This must be the true globalvar name we asked to collect, not the qword_XXXXXXXX or unk_XXXXXXXX

  - insn_va: '0x180333300'
    insn_disasm: lea     rax, unk_180222200      # Must load/reference the global variable
    gv_name: s_GameEventManager  # This must be the true globalvar name we asked to collect, not the qword_XXXXXXXX or unk_XXXXXXXX

found_struct_offset: # This is for reference to struct member offset.

  - insn_va: '0x1801BA12A'                # Always be the instruction with displacement offset, when instruction access CGameResourceService::m_pEntitySystem
    insn_disasm: mov     rcx, [r14+58h]   # Always be the instruction with displacement offset
    offset: '0x58'
    size: 8
    struct_name: CGameResourceService
    member_name: m_pEntitySystem

  - insn_va: '0x180075B6B'                # Always be the instruction with displacement offset, when instruction access SDL_Mouse::SetRelativeMouseMode
    insn_disasm: mov     rax, [rsi+40h]   # Always be the instruction with displacement offset
    offset: '0x40'
    size: 8
    struct_name: SDL_Mouse
    member_name: SetRelativeMouseMode
```

If nothing found, output an empty YAML. DO NOT output anything other than the desired YAML. DO NOT collect unrelated symbols.
