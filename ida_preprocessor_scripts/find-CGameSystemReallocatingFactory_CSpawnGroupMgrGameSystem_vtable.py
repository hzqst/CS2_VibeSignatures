#!/usr/bin/env python3
"""Preprocess script for find-CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_vtable skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_CLASS_NAMES = [
    "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem",
]

MANGLED_CLASS_NAMES = {
    "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem": [
        "??_7?$CGameSystemReallocatingFactory@VCSpawnGroupMgrGameSystem@@V1@@@6B@",
        "_ZTV30CGameSystemReallocatingFactoryI24CSpawnGroupMgrGameSystemS0_E",
    ],
}


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Generate CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem vtable YAML by class-name lookup via MCP."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        vtable_class_names=TARGET_CLASS_NAMES,
        mangled_class_names=MANGLED_CLASS_NAMES,
        platform=platform,
        image_base=image_base,
        debug=debug,
    )
