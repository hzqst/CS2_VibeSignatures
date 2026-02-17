#!/usr/bin/env python3
"""Preprocess script for find-CGameResourceService_BuildResourceManifest skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGameResourceService_BuildResourceManifest",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "CGameResourceService_m_pEntitySystem",
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever signatures to locate target output(s) and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        debug=debug,
    )
