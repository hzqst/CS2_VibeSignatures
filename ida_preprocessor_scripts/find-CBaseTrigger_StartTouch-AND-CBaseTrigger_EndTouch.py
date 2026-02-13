#!/usr/bin/env python3
"""Preprocess script for find-CBaseTrigger_StartTouch-AND-CBaseTrigger_EndTouch skill."""

import os

from ida_analyze_util import (
    preprocess_index_based_vfunc_via_mcp,
    write_func_yaml,
)


BASE_START_TOUCH_NAME = "CBaseEntity_StartTouch"
TARGET_VTABLE_NAME = "CBaseTrigger"
TARGET_FUNCTION_SPECS = [
    ("CBaseTrigger_StartTouch", 0),
    ("CBaseTrigger_EndTouch", 2),
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
    """Resolve CBaseTrigger StartTouch/EndTouch by CBaseEntity StartTouch index and CBaseTrigger vtable."""
    _ = skill_name

    expected_by_filename = {
        f"{func_name}.{platform}.yaml": func_name
        for func_name, _ in TARGET_FUNCTION_SPECS
    }
    matched_outputs = {}
    for path in expected_outputs:
        basename = os.path.basename(path)
        func_name = expected_by_filename.get(basename)
        if func_name is not None:
            matched_outputs[func_name] = path

    if len(matched_outputs) != len(TARGET_FUNCTION_SPECS):
        if debug:
            missing = [
                func_name
                for func_name, _ in TARGET_FUNCTION_SPECS
                if func_name not in matched_outputs
            ]
            print(
                "    Preprocess: expected outputs missing for "
                f"{', '.join(missing)}"
            )
        return False

    for func_name, relative_index in TARGET_FUNCTION_SPECS:
        target_output = matched_outputs[func_name]

        func_data = await preprocess_index_based_vfunc_via_mcp(
            session=session,
            target_func_name=func_name,
            target_output=target_output,
            old_yaml_map=old_yaml_map,
            new_binary_dir=new_binary_dir,
            platform=platform,
            image_base=image_base,
            base_vfunc_name=BASE_START_TOUCH_NAME,
            inherit_vtable_class=TARGET_VTABLE_NAME,
            relative_index_offset=relative_index,
            generate_func_sig=False,
            debug=debug,
        )
        if func_data is None:
            if debug:
                print(f"    Preprocess: failed to locate {func_name}")
            return False

        write_func_yaml(target_output, func_data)
        if debug:
            print(
                "    Preprocess: generated "
                f"{func_name}.{platform}.yaml from vtable index "
                f"{func_data.get('vfunc_index', '?')}"
            )

    return True
