#!/usr/bin/env python3
"""Preprocess script for find-CPlayerCommandQueue_ctor skill."""

import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CPlayerCommandQueue_ctor",
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CPlayerCommandQueue_ctor",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
]


def _read_vtable_va(yaml_path):
    """Read vtable_va from a vtable YAML file, returning it as a hex string or None."""
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            va = data.get("vtable_va")
            if va:
                return str(va)
    except Exception:
        pass
    return None


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    vtable_yaml_path = os.path.join(
        new_binary_dir, f"CPlayerCommandQueue_vtable.{platform}.yaml"
    )
    vtable_va = _read_vtable_va(vtable_yaml_path)
    if not vtable_va:
        if debug:
            print(
                "    Preprocess: CPlayerCommandQueue_vtable vtable_va not found, "
                "cannot resolve xref_gvs"
            )
        return False

    # Build FUNC_XREFS dynamically with the vtable VA as explicit address
    exclude_signatures = ["66 83 ?? FF"] if platform == "linux" else []
    func_xrefs = [
        {
            "func_name": "CPlayerCommandQueue_ctor",
            "xref_strings": [],
            "xref_gvs": [str(vtable_va)],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": exclude_signatures,
        },
    ]

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
