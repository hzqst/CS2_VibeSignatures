#!/usr/bin/env python3
"""Preprocess script for find-IGameSystem_AddByName-AND-IGameSystem_Add skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IGameSystem_AddByName",
    "IGameSystem_Add",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    # Both functions found by decompiling CLoopModeGame_ReceivedServerInfo:
    #   IGameSystem_AddByName = called repeatedly with string literal args ("GameRulesGameSystem", etc.)
    #   IGameSystem_Add       = called with pointer return values from singleton accessors
    (
        "IGameSystem_AddByName",
        "prompt/call_llm_decompile.md",
        "references/client/CLoopModeGame_ReceivedServerInfo.{platform}.yaml",
    ),
    (
        "IGameSystem_Add",
        "prompt/call_llm_decompile.md",
        "references/client/CLoopModeGame_ReceivedServerInfo.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "IGameSystem_AddByName",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
        ],
    ),
    (
        "IGameSystem_Add",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s); fallback to LLM_DECOMPILE of CLoopModeGame_ReceivedServerInfo."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
