#!/usr/bin/env python3
"""Preprocess script for find-INetworkMessages_RegisterSchemaTypeOverride skill."""

import os
from pathlib import Path

from ida_analyze_util import preprocess_func_sig_via_mcp, write_func_yaml

TARGET_FUNCTION_NAME = "INetworkMessages_RegisterSchemaTypeOverride"
LEGACY_IMPL_FUNCTION_NAME = "CNetworkMessages_RegisterSchemaTypeOverride"
TARGET_FIELDS = [
    "func_name",
    "vfunc_sig",
    "vfunc_offset",
    "vfunc_index",
    "vtable_name",
]


def _resolve_old_yaml_path(target_output, old_yaml_map, platform):
    old_path = (old_yaml_map or {}).get(target_output)
    if old_path and os.path.exists(old_path):
        return old_path

    if not old_path:
        return None

    return str(Path(old_path).with_name(f"{LEGACY_IMPL_FUNCTION_NAME}.{platform}.yaml"))


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    _ = skill_name

    target_output = next(
        (
            path for path in expected_outputs
            if os.path.basename(path)
            == f"{TARGET_FUNCTION_NAME}.{platform}.yaml"
        ),
        None,
    )
    if not target_output:
        if debug:
            print(
                "    Preprocess: expected output missing for "
                f"{TARGET_FUNCTION_NAME}"
            )
        return False

    old_path = _resolve_old_yaml_path(target_output, old_yaml_map, platform)
    func_data = await preprocess_func_sig_via_mcp(
        session=session,
        new_path=target_output,
        old_path=old_path,
        image_base=image_base,
        new_binary_dir=new_binary_dir,
        platform=platform,
        func_name=TARGET_FUNCTION_NAME,
        debug=debug,
    )
    if not isinstance(func_data, dict):
        return False

    func_data["vtable_name"] = "INetworkMessages"
    payload = {field_name: func_data[field_name] for field_name in TARGET_FIELDS}
    write_func_yaml(target_output, payload)
    return True
