# Pattern E -- Struct member offset via LLM_DECOMPILE

**Use when:** target is a **struct member offset** (not a function), discovered by decompiling a known predecessor function.

## Template

```python
#!/usr/bin/env python3
"""Preprocess script for find-{SKILL_NAME} skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_STRUCT_MEMBER_NAMES = [
    "{STRUCT_MEMBER_NAME}",  # e.g. "CCheckTransmitInfo_m_nPlayerSlot"
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "{STRUCT_MEMBER_NAME}",
        "prompt/call_llm_decompile.md",
        "references/{MODULE}/{PREDECESSOR_FUNC}.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "{STRUCT_MEMBER_NAME}",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever offset_sig to locate target struct offset and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
```

## Reference YAML Annotation

In the predecessor YAML, annotate every struct field access that corresponds to a target member. Use the `(structmember, struct=X, member=Y)` tag on **all** access sites for that field in both `disasm_code` and `procedure`.

`disasm_code` (IDA hex with `h` suffix, `;` comment):

```asm
  .text:0000000180C99633                 mov     ecx, [rdi+240h]  ; 240h = CCheckTransmitInfo::m_nPlayerSlot (structmember, struct=CCheckTransmitInfo, member=m_nPlayerSlot)
```

`procedure` (C `//` comment, decimal then hex):

```c
*(unsigned int *)(*v6 + 576);  // 576 = 0x240 = CCheckTransmitInfo::m_nPlayerSlot (structmember, struct=CCheckTransmitInfo, member=m_nPlayerSlot)
```

Multiple access sites for the same field all need the same annotation — the LLM uses them together to confirm the offset.

## Key differences from Pattern D

- Uses `TARGET_STRUCT_MEMBER_NAMES` instead of `TARGET_FUNCTION_NAMES`
- Passes `struct_member_names=` instead of `func_names=` to `preprocess_common_skill`
- YAML fields are struct-specific: `struct_name, member_name, offset, size, offset_sig, offset_sig_disp`
- No `FUNC_VTABLE_RELATIONS`
- config.yaml symbol category is `structmember` (not `func` or `vfunc`)

## Checklist

- [ ] `TARGET_STRUCT_MEMBER_NAMES` lists all struct member targets
- [ ] `LLM_DECOMPILE` reference path points to the correct predecessor function YAML
- [ ] `preprocess_skill` signature includes `llm_config=None`
- [ ] `preprocess_common_skill` call passes `struct_member_names=`, `llm_decompile_specs=`, and `llm_config=`
- [ ] No `FUNC_VTABLE_RELATIONS` (struct member, not virtual function)
- [ ] config.yaml symbol category is `structmember`
- [ ] config.yaml `expected_input` includes the predecessor YAML
- [ ] Reference YAMLs exist or generated for both platforms
