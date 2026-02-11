#!/usr/bin/env python3
"""Preprocess script for find-CBaseEntity_SetStateChanged skill."""

import os

from ida_analyze_util import preprocess_func_sig_via_mcp, write_func_yaml


TARGET_FUNCTION_NAMES = [
    "CBaseEntity_SetStateChanged",
]


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
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    _ = skill_name, new_binary_dir

    expected_by_filename = {
        f"{func_name}.{platform}.yaml": func_name
        for func_name in TARGET_FUNCTION_NAMES
    }
    matched_outputs = {}
    for path in expected_outputs:
        basename = os.path.basename(path)
        func_name = expected_by_filename.get(basename)
        if func_name is not None:
            matched_outputs[func_name] = path

    if len(matched_outputs) != len(TARGET_FUNCTION_NAMES):
        if debug:
            missing = [name for name in TARGET_FUNCTION_NAMES if name not in matched_outputs]
            print(
                "    Preprocess: expected outputs missing for "
                f"{', '.join(missing)}"
            )
        return False

    for func_name in TARGET_FUNCTION_NAMES:
        target_output = matched_outputs[func_name]
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

    return True
