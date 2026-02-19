#!/usr/bin/env python3
"""Preprocess script for find-IGameSystem_ServerGamePostSimulate-AND-IGameSystem_ClientGamePostSimulate skill."""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
    ("IGameSystem_ServerGamePostSimulate", "IGameSystem", "CLightQueryGameSystem_ServerGamePostSimulate", False),
    ("IGameSystem_ClientGamePostSimulate", "IGameSystem", "CLightQueryGameSystem_ClientGamePostSimulate", False),
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
    """Resolve IGameSystem_ServerGamePostSimulate and IGameSystem_ClientGamePostSimulate by their respective CLightQueryGameSystem vfunc indices."""
    _ = skill_name

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS,
        debug=debug,
    )
