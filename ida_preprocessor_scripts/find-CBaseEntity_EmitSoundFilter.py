#!/usr/bin/env python3
"""Preprocess script for find-CBaseEntity_EmitSoundFilter skill."""

import os

from ida_analyze_util import preprocess_func_sig_via_mcp, write_func_yaml


TARGET_FUNCTION_NAME = "CBaseEntity_EmitSoundFilter"


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
    """Reuse previous gamever func_sig to locate CBaseEntity_EmitSoundFilter and write YAML."""
    _ = skill_name

    target_filename = f"{TARGET_FUNCTION_NAME}.{platform}.yaml"
    target_outputs = [
        path for path in expected_outputs
        if os.path.basename(path) == target_filename
    ]

    if len(target_outputs) != 1:
        if debug:
            print(
                f"    Preprocess: expected exactly one output named {target_filename}, "
                f"got {len(target_outputs)}"
            )
        return False

    target_output = target_outputs[0]
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
        return False

    write_func_yaml(target_output, func_data)
    if debug:
        print(f"    Preprocess: generated {target_filename}")

    return True

