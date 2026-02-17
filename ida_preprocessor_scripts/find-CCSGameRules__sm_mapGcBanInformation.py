#!/usr/bin/env python3
"""Preprocess script for find-CCSGameRules__sm_mapGcBanInformation skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBALVAR_NAMES = ["CCSGameRules__sm_mapGcBanInformation"]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever gv_sig to locate target global variable and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=TARGET_GLOBALVAR_NAMES,
        debug=debug,
    )
