#!/usr/bin/env python3
"""Preprocess script for find-CBasePlayerPawn_DropActivePlayerWeapon-AND-CCSPlayer_ItemServices_DropActivePlayerWeapon-AND-CCSPlayer_WeaponServices_DropWeapon skill."""

import os

from ida_analyze_util import (
    preprocess_func_sig_via_mcp,
    preprocess_gv_sig_via_mcp,
    write_func_yaml,
    write_gv_yaml,
)


TARGET_FUNCTION_NAMES = [
    "CBasePlayerPawn_DropActivePlayerWeapon",
    "CCSPlayer_ItemServices_DropActivePlayerWeapon",
    "CCSPlayer_WeaponServices_DropWeapon",
]
TARGET_GLOBALVAR_NAMES = []


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

    expected_by_filename = {
        f"{func_name}.{platform}.yaml": ("func", func_name)
        for func_name in TARGET_FUNCTION_NAMES
    }
    for gv_name in TARGET_GLOBALVAR_NAMES:
        expected_by_filename[f"{gv_name}.{platform}.yaml"] = ("gv", gv_name)

    matched_func_outputs = {}
    matched_gv_outputs = {}
    for path in expected_outputs:
        basename = os.path.basename(path)
        item = expected_by_filename.get(basename)
        if item is None:
            continue

        kind, name = item
        if kind == "func":
            matched_func_outputs[name] = path
        else:
            matched_gv_outputs[name] = path

    missing_func_names = [name for name in TARGET_FUNCTION_NAMES if name not in matched_func_outputs]
    missing_gv_names = [name for name in TARGET_GLOBALVAR_NAMES if name not in matched_gv_outputs]
    if missing_func_names or missing_gv_names:
        if debug:
            missing = missing_func_names + missing_gv_names
            print(
                "    Preprocess: expected outputs missing for "
                f"{', '.join(missing)}"
            )
        return False

    for func_name in TARGET_FUNCTION_NAMES:
        target_output = matched_func_outputs[func_name]
        old_path = (old_yaml_map or {}).get(target_output)

        func_data = await preprocess_func_sig_via_mcp(
            session=session,
            new_path=target_output,
            old_path=old_path,
            image_base=image_base,
            new_binary_dir=new_binary_dir,
            platform=platform,
            debug=debug,
        )
        if func_data is None:
            if debug:
                print(f"    Preprocess: failed to locate {func_name}")
            return False

        write_func_yaml(target_output, func_data)
        if debug:
            print(f"    Preprocess: generated {func_name}.{platform}.yaml")

    for gv_name in TARGET_GLOBALVAR_NAMES:
        target_output = matched_gv_outputs[gv_name]
        gv_old_path = (old_yaml_map or {}).get(target_output)

        gv_data = await preprocess_gv_sig_via_mcp(
            session=session,
            new_path=target_output,
            old_path=gv_old_path,
            image_base=image_base,
            new_binary_dir=new_binary_dir,
            platform=platform,
            debug=debug,
        )

        if gv_data is None:
            if debug:
                print(f"    Preprocess: failed to locate {gv_name}")
            return False

        write_gv_yaml(target_output, gv_data)
        if debug:
            print(f"    Preprocess: generated {gv_name}.{platform}.yaml")

    return True
