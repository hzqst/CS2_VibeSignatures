#!/usr/bin/env python3
"""Preprocess script for find-CSource2Server_vtable skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_CLASS_NAME = "CSource2Server"


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Generate CSource2Server vtable YAML by class-name lookup via MCP."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        vtable_class_names=[TARGET_CLASS_NAME],
        platform=platform,
        image_base=image_base,
        debug=debug,
    )
