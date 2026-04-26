#!/usr/bin/env python3
"""Preprocess script for find-IEntityResourceManifestBuilder_BuildResourceManifest_ManifestNameOrGroupName skill."""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
    (
        "IEntityResourceManifestBuilder_BuildResourceManifest_ManifestNameOrGroupName",
        "IEntityResourceManifestBuilder",
        "../server/CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName",
        False,
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "IEntityResourceManifestBuilder_BuildResourceManifest_ManifestNameOrGroupName",
        [
            "func_name",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse old vfunc slot; fallback to inheriting slot index from CGameEntitySystem_BuildResourceManifest_ManifestNameOrGroupName."""
    _ = skill_name

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
