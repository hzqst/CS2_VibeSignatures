#!/usr/bin/env python3
"""Preprocess script for find-CPointTeleport_Teleport-AND-CBaseEntity_Teleport skill."""

import os

from ida_analyze_util import preprocess_func_sig_via_mcp, write_func_yaml


POINT_TELEPORT_FUNCTION = "CPointTeleport_Teleport"
BASE_ENTITY_FUNCTION = "CBaseEntity_Teleport"
BASE_ENTITY_VTABLE = "CBaseEntity"


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
    """Resolve CPointTeleport::Teleport by old func_sig, then derive CBaseEntity::Teleport vfunc index."""
    _ = skill_name

    expected_by_filename = {
        f"{POINT_TELEPORT_FUNCTION}.{platform}.yaml": POINT_TELEPORT_FUNCTION,
        f"{BASE_ENTITY_FUNCTION}.{platform}.yaml": BASE_ENTITY_FUNCTION,
    }
    matched_outputs = {}
    for path in expected_outputs:
        basename = os.path.basename(path)
        func_name = expected_by_filename.get(basename)
        if func_name is not None:
            matched_outputs[func_name] = path

    if len(matched_outputs) != 2:
        if debug:
            missing = [
                name
                for name in (POINT_TELEPORT_FUNCTION, BASE_ENTITY_FUNCTION)
                if name not in matched_outputs
            ]
            print(
                "    Preprocess: expected outputs missing for "
                f"{', '.join(missing)}"
            )
        return False

    point_output = matched_outputs[POINT_TELEPORT_FUNCTION]
    point_old_path = (old_yaml_map or {}).get(point_output)

    point_data = await preprocess_func_sig_via_mcp(
        session=session,
        new_path=point_output,
        old_path=point_old_path,
        image_base=image_base,
        new_binary_dir=new_binary_dir,
        platform=platform,
        debug=debug,
    )
    if point_data is None:
        if debug:
            print("    Preprocess: failed to locate CPointTeleport_Teleport")
        return False

    try:
        point_index = int(point_data.get("vfunc_index"))
    except (TypeError, ValueError):
        if debug:
            print("    Preprocess: CPointTeleport_Teleport vfunc_index missing or invalid")
        return False

    write_func_yaml(point_output, point_data)
    if debug:
        print(f"    Preprocess: generated {POINT_TELEPORT_FUNCTION}.{platform}.yaml")

    base_output = matched_outputs[BASE_ENTITY_FUNCTION]
    base_data = {
        "vtable_name": BASE_ENTITY_VTABLE,
        "vfunc_offset": hex(point_index * 8),
        "vfunc_index": point_index,
    }

    write_func_yaml(base_output, base_data)
    if debug:
        print(
            "    Preprocess: generated "
            f"{BASE_ENTITY_FUNCTION}.{platform}.yaml from vfunc index {point_index}"
        )

    return True