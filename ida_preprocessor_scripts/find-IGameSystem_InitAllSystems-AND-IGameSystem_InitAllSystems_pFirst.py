#!/usr/bin/env python3
"""Preprocess script for find-IGameSystem_InitAllSystems-AND-IGameSystem_InitAllSystems_pFirst skill."""

import os

from ida_analyze_util import (
    preprocess_func_sig_via_mcp,
    preprocess_gv_sig_via_mcp,
    write_func_yaml,
    write_gv_yaml,
)


TARGET_FUNCTION_NAME = "IGameSystem_InitAllSystems"
TARGET_GLOBALVAR_NAME = "IGameSystem_InitAllSystems_pFirst"


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    """Reuse previous gamever func_sig/gv_sig to locate targets and write YAML."""
    _ = skill_name

    func_output_name = f"{TARGET_FUNCTION_NAME}.{platform}.yaml"
    gv_output_name = f"{TARGET_GLOBALVAR_NAME}.{platform}.yaml"

    matched_func_output = None
    matched_gv_output = None
    for path in expected_outputs:
        basename = os.path.basename(path)
        if basename == func_output_name:
            matched_func_output = path
        elif basename == gv_output_name:
            matched_gv_output = path

    if matched_func_output is None or matched_gv_output is None:
        if debug:
            missing = []
            if matched_func_output is None:
                missing.append(func_output_name)
            if matched_gv_output is None:
                missing.append(gv_output_name)
            print(
                "    Preprocess: expected outputs missing for "
                f"{', '.join(missing)}"
            )
        return False

    func_old_path = (old_yaml_map or {}).get(matched_func_output)
    func_data = await preprocess_func_sig_via_mcp(
        session=session,
        new_path=matched_func_output,
        old_path=func_old_path,
        image_base=image_base,
        new_binary_dir=new_binary_dir,
        platform=platform,
        debug=debug,
    )
    if func_data is None:
        if debug:
            print(f"    Preprocess: failed to locate {TARGET_FUNCTION_NAME}")
        return False

    write_func_yaml(matched_func_output, func_data)
    if debug:
        print(f"    Preprocess: generated {TARGET_FUNCTION_NAME}.{platform}.yaml")

    gv_old_path = (old_yaml_map or {}).get(matched_gv_output)
    gv_data = await preprocess_gv_sig_via_mcp(
        session=session,
        new_path=matched_gv_output,
        old_path=gv_old_path,
        image_base=image_base,
        new_binary_dir=new_binary_dir,
        platform=platform,
        debug=debug,
    )
    if gv_data is None:
        if debug:
            print(f"    Preprocess: failed to locate {TARGET_GLOBALVAR_NAME}")
        return False

    write_gv_yaml(matched_gv_output, gv_data)
    if debug:
        print(f"    Preprocess: generated {TARGET_GLOBALVAR_NAME}.{platform}.yaml")

    return True
