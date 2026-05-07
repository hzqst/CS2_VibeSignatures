#!/usr/bin/env python3
"""Preprocess script for find-SDL_Mouse_focus-AND-SDL_Mouse_last_x-AND-SDL_Mouse_last_y-windows skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = []

TARGET_STRUCT_MEMBER_NAMES = [
    "SDL_Mouse_focus",
    "SDL_Mouse_last_x",
    "SDL_Mouse_last_y",
    "SDL_Mouse_has_position",
    "SDL_Mouse_relative_mode_warp_motion",
    "SDL_Mouse_WarpMouse",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "SDL_Mouse_focus",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_PerformWarpMouseInWindow.{platform}.yaml",
    ),
    (
        "SDL_Mouse_last_x",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_PerformWarpMouseInWindow.{platform}.yaml",
    ),
    (
        "SDL_Mouse_last_y",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_PerformWarpMouseInWindow.{platform}.yaml",
    ),
    (
        "SDL_Mouse_has_position",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_PerformWarpMouseInWindow.{platform}.yaml",
    ),
    (
        "SDL_Mouse_relative_mode_warp_motion",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_PerformWarpMouseInWindow.{platform}.yaml",
    ),
    (
        "SDL_Mouse_WarpMouse",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_PerformWarpMouseInWindow.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "SDL_Mouse_focus",
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
        "SDL_Mouse_last_x",
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
        "SDL_Mouse_last_y",
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
        "SDL_Mouse_has_position",
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
        "SDL_Mouse_relative_mode_warp_motion",
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
        "SDL_Mouse_WarpMouse",
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
    """Reuse previous gamever offset_sig to locate targets and write YAML."""
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
