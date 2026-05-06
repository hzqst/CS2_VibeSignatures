#!/usr/bin/env python3
"""Preprocess script for find-SDL_Mouse_relative_mode-AND-SDL_Mouse_SetRelativeMouseMode-AND-SDL_PerformWarpMouseInWindow-windows skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "SDL_PerformWarpMouseInWindow",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "SDL_Mouse_relative_mode",
    "SDL_Mouse_SetRelativeMouseMode",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "SDL_Mouse_relative_mode",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_SetRelativeMouseMode.{platform}.yaml",
    ),
    (
        "SDL_Mouse_SetRelativeMouseMode",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_SetRelativeMouseMode.{platform}.yaml",
    ),
    (
        "SDL_PerformWarpMouseInWindow",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_SetRelativeMouseMode.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "SDL_Mouse_relative_mode",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
    (
        "SDL_Mouse_SetRelativeMouseMode",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
    (
        "SDL_PerformWarpMouseInWindow",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever func_sig/offset_sig to locate targets and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
