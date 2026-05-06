#!/usr/bin/env python3
"""Preprocess script for find-SDL_GetMouse-AND-SDL_mouse_initialized-windows skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "SDL_GetMouse",
]

TARGET_GLOBALVAR_NAMES = [
    "SDL_mouse_initialized",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "SDL_Mouse_was_touch_mouse_events",
    "SDL_Mouse_cursor_visible",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "SDL_GetMouse",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_PreInitMouse.{platform}.yaml",
    ),
    (
        "SDL_mouse_initialized",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_PreInitMouse.{platform}.yaml",
    ),
    (
        "SDL_Mouse_was_touch_mouse_events",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_PreInitMouse.{platform}.yaml",
    ),
    (
        "SDL_Mouse_cursor_visible",
        "prompt/call_llm_decompile.md",
        "references/SDL3/SDL_PreInitMouse.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "SDL_GetMouse",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig_allow_across_function_boundary:true",
        ],
    ),
    (
        "SDL_mouse_initialized",
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
        "SDL_Mouse_was_touch_mouse_events",
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
        "SDL_Mouse_cursor_visible",
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
    """Reuse previous gamever func_sig/gv_sig/offset_sig to locate targets and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        gv_names=TARGET_GLOBALVAR_NAMES,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
