#!/usr/bin/env python3
"""Preprocess script for find-CCSPlayerPawnBase_vtable skill."""

import os

from ida_analyze_util import preprocess_vtable_via_mcp, write_vtable_yaml


TARGET_CLASS_NAME = "CCSPlayerPawnBase"


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
    """Generate CCSPlayerPawnBase vtable YAML by class-name lookup via MCP."""
    _ = skill_name, old_yaml_map, new_binary_dir

    target_filename = f"{TARGET_CLASS_NAME}_vtable.{platform}.yaml"
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

    vtable_data = await preprocess_vtable_via_mcp(
        session=session,
        class_name=TARGET_CLASS_NAME,
        image_base=image_base,
        platform=platform,
        debug=debug,
    )
    if vtable_data is None:
        return False

    write_vtable_yaml(target_outputs[0], vtable_data)
    if debug:
        print(f"    Preprocess: generated {target_filename}")

    return True
