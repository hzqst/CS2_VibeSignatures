#!/usr/bin/env python3
"""Preprocess script for find-CTriggerPush_Touch skill."""

import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import (
    preprocess_func_sig_via_mcp,
    preprocess_gen_func_sig_via_mcp,
    write_func_yaml,
)


TARGET_FUNCTION_NAMES = [
    "CTriggerPush_Touch",
]
TRIGGER_PUSH_VTABLE_NAME = "CTriggerPush"
BASE_TOUCH_FUNCTION_NAME = "CBaseEntity_Touch"


def _read_yaml(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _parse_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ValueError("empty integer string")
        return int(raw, 0)
    return int(value)


def _resolve_trigger_push_touch_via_vtable(new_binary_dir, platform, debug=False):
    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required for vtable fallback")
        return None

    base_touch_path = os.path.join(
        new_binary_dir,
        f"{BASE_TOUCH_FUNCTION_NAME}.{platform}.yaml",
    )
    trigger_push_vtable_path = os.path.join(
        new_binary_dir,
        f"{TRIGGER_PUSH_VTABLE_NAME}_vtable.{platform}.yaml",
    )

    base_touch_data = _read_yaml(base_touch_path)
    if not isinstance(base_touch_data, dict):
        if debug:
            print(
                "    Preprocess: failed to read base touch YAML: "
                f"{os.path.basename(base_touch_path)}"
            )
        return None

    try:
        touch_index = _parse_int(base_touch_data.get("vfunc_index"))
    except Exception:
        if debug:
            print(
                "    Preprocess: invalid vfunc_index in "
                f"{os.path.basename(base_touch_path)}"
            )
        return None

    trigger_push_vtable_data = _read_yaml(trigger_push_vtable_path)
    if not isinstance(trigger_push_vtable_data, dict):
        if debug:
            print(
                "    Preprocess: failed to read vtable YAML: "
                f"{os.path.basename(trigger_push_vtable_path)}"
            )
        return None

    raw_entries = trigger_push_vtable_data.get("vtable_entries", {})
    if not isinstance(raw_entries, dict):
        if debug:
            print("    Preprocess: invalid vtable_entries in CTriggerPush_vtable YAML")
        return None

    normalized_entries = {}
    for idx, addr in raw_entries.items():
        try:
            normalized_entries[int(idx)] = str(addr)
        except (TypeError, ValueError):
            if debug:
                print(f"    Preprocess: invalid vtable entry index: {idx}")
            return None

    func_va = normalized_entries.get(touch_index)
    if not func_va:
        if debug:
            print(
                "    Preprocess: CTriggerPush_vtable missing index "
                f"{touch_index}"
            )
        return None

    return {
        "func_va": func_va,
        "vtable_name": TRIGGER_PUSH_VTABLE_NAME,
        "vfunc_index": touch_index,
    }


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
    """Reuse old func_sig first; fallback to vtable index + generated signature when needed."""
    _ = skill_name

    expected_by_filename = {
        f"{func_name}.{platform}.yaml": func_name
        for func_name in TARGET_FUNCTION_NAMES
    }
    matched_outputs = {}
    for path in expected_outputs:
        basename = os.path.basename(path)
        func_name = expected_by_filename.get(basename)
        if func_name is not None:
            matched_outputs[func_name] = path

    if len(matched_outputs) != len(TARGET_FUNCTION_NAMES):
        if debug:
            missing = [name for name in TARGET_FUNCTION_NAMES if name not in matched_outputs]
            print(
                "    Preprocess: expected outputs missing for "
                f"{', '.join(missing)}"
            )
        return False

    for func_name in TARGET_FUNCTION_NAMES:
        target_output = matched_outputs[func_name]
        old_path = (old_yaml_map or {}).get(target_output)

        func_data = await preprocess_func_sig_via_mcp(
            session=session,
            new_path=target_output,
            old_path=old_path,
            image_base=image_base,
            new_binary_dir=new_binary_dir,
            platform=platform,
            debug=debug,
        )

        if func_data is None:
            fallback_info = _resolve_trigger_push_touch_via_vtable(
                new_binary_dir=new_binary_dir,
                platform=platform,
                debug=debug,
            )
            if fallback_info is None:
                if debug:
                    print(f"    Preprocess: failed to locate {func_name}")
                return False

            func_data = await preprocess_gen_func_sig_via_mcp(
                session=session,
                func_va=fallback_info["func_va"],
                image_base=image_base,
                debug=debug,
            )
            if func_data is None:
                if debug:
                    print(
                        "    Preprocess: fallback signature generation failed for "
                        f"{func_name} at {fallback_info['func_va']}"
                    )
                return False

            touch_index = fallback_info["vfunc_index"]
            func_data["vtable_name"] = fallback_info["vtable_name"]
            func_data["vfunc_offset"] = hex(touch_index * 8)
            func_data["vfunc_index"] = touch_index
            if debug:
                print(
                    "    Preprocess: regenerated func_sig via vtable fallback for "
                    f"{func_name}"
                )

        write_func_yaml(target_output, func_data)
        if debug:
            print(f"    Preprocess: generated {func_name}.{platform}.yaml")

    return True
