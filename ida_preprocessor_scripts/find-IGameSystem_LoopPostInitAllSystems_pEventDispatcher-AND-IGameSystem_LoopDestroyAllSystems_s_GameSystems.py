#!/usr/bin/env python3
"""Preprocess script for find-IGameSystem_LoopPostInitAllSystems_pEventDispatcher-AND-IGameSystem_LoopDestroyAllSystems_s_GameSystems skill."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = []
TARGET_GLOBALVAR_NAMES = ["IGameSystem_LoopPostInitAllSystems_pEventDispatcher", "IGameSystem_LoopDestroyAllSystems_s_GameSystems"]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    # Both globals are identified by decompiling IGameSystem_LoopDestroyAllSystems:
    #   pEventDispatcher = the qword pointer zeroed at the end of the function
    #   s_GameSystems     = the dword used as backward-loop count before zeroing pEventDispatcher
    (
        "IGameSystem_LoopPostInitAllSystems_pEventDispatcher",
        "prompt/call_llm_decompile.md",
        "references/server/IGameSystem_LoopDestroyAllSystems.{platform}.yaml",
    ),
    (
        "IGameSystem_LoopDestroyAllSystems_s_GameSystems",
        "prompt/call_llm_decompile.md",
        "references/server/IGameSystem_LoopDestroyAllSystems.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "IGameSystem_LoopPostInitAllSystems_pEventDispatcher",
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
    (
        "IGameSystem_LoopDestroyAllSystems_s_GameSystems",
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
    """Reuse previous gamever gv_sig to locate targets; fallback to LLM_DECOMPILE of IGameSystem_LoopDestroyAllSystems."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        gv_names=TARGET_GLOBALVAR_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
