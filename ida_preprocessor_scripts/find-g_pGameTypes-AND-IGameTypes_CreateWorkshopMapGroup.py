#!/usr/bin/env python3
"""Preprocess script for find-g_pGameTypes-AND-IGameTypes_CreateWorkshopMapGroup skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IGameTypes_CreateWorkshopMapGroup",
]

TARGET_GLOBALVAR_NAMES = [
    "g_pGameTypes",
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("IGameTypes_CreateWorkshopMapGroup", "IGameTypes"),
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "IGameTypes_CreateWorkshopMapGroup",
        "prompt/call_llm_decompile.md",
        "references/server/CDedicatedServerWorkshopManager_SwitchToWorkshopMapGroup.{platform}.yaml",
    ),
    (
        "g_pGameTypes",
        "prompt/call_llm_decompile.md",
        "references/server/CDedicatedServerWorkshopManager_SwitchToWorkshopMapGroup.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "IGameTypes_CreateWorkshopMapGroup",
        [
            "func_name",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
            "vfunc_sig",
        ],
    ),
    (
        "g_pGameTypes",
        [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever vfunc_sig/gv_sig to locate targets and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        gv_names=TARGET_GLOBALVAR_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
