#!/usr/bin/env python3
"""Preprocess script for find-CBaseTrigger_StartTouch-AND-CBaseTrigger_EndTouch skill."""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import parse_mcp_result, write_func_yaml


BASE_START_TOUCH_NAME = "CBaseEntity_StartTouch"
TARGET_VTABLE_NAME = "CBaseTrigger"
TARGET_FUNCTION_SPECS = [
    ("CBaseTrigger_StartTouch", 0),
    ("CBaseTrigger_EndTouch", 2),
]


def _read_yaml(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _read_old_func_sig(old_yaml_map, target_output):
    old_path = (old_yaml_map or {}).get(target_output)
    if not old_path or not os.path.exists(old_path):
        return None

    old_data = _read_yaml(old_path)
    if not isinstance(old_data, dict):
        return None

    func_sig = old_data.get("func_sig")
    if not func_sig:
        return None

    return str(func_sig)


async def _query_function_info(session, func_addr_hex):
    py_code = (
        "import idaapi, json\n"
        f"addr = {func_addr_hex}\n"
        "f = idaapi.get_func(addr)\n"
        "if f and f.start_ea == addr:\n"
        "    result = json.dumps({'func_va': hex(f.start_ea), 'func_size': hex(f.end_ea - f.start_ea)})\n"
        "else:\n"
        "    result = json.dumps(None)\n"
    )

    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        result_data = parse_mcp_result(result)
    except Exception:
        return None

    if not isinstance(result_data, dict):
        return None

    result_str = result_data.get("result", "")
    if not result_str:
        return None

    try:
        return json.loads(result_str)
    except (json.JSONDecodeError, TypeError):
        return None


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
    """Resolve CBaseTrigger StartTouch/EndTouch by CBaseEntity StartTouch index and CBaseTrigger vtable."""
    _ = skill_name

    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required for CBaseTrigger touch preprocessing")
        return False

    expected_by_filename = {
        f"{func_name}.{platform}.yaml": func_name
        for func_name, _ in TARGET_FUNCTION_SPECS
    }
    matched_outputs = {}
    for path in expected_outputs:
        basename = os.path.basename(path)
        func_name = expected_by_filename.get(basename)
        if func_name is not None:
            matched_outputs[func_name] = path

    if len(matched_outputs) != len(TARGET_FUNCTION_SPECS):
        if debug:
            missing = [
                func_name
                for func_name, _ in TARGET_FUNCTION_SPECS
                if func_name not in matched_outputs
            ]
            print(
                "    Preprocess: expected outputs missing for "
                f"{', '.join(missing)}"
            )
        return False

    base_start_touch_path = os.path.join(
        new_binary_dir,
        f"{BASE_START_TOUCH_NAME}.{platform}.yaml",
    )
    cbase_trigger_vtable_path = os.path.join(
        new_binary_dir,
        f"{TARGET_VTABLE_NAME}_vtable.{platform}.yaml",
    )

    base_start_touch_data = _read_yaml(base_start_touch_path)
    if not isinstance(base_start_touch_data, dict):
        if debug:
            print(
                "    Preprocess: failed to read base start-touch YAML: "
                f"{os.path.basename(base_start_touch_path)}"
            )
        return False

    base_start_touch_index = base_start_touch_data.get("vfunc_index")
    try:
        base_start_touch_index = int(base_start_touch_index)
    except (TypeError, ValueError):
        if debug:
            print(
                "    Preprocess: invalid vfunc_index in "
                f"{os.path.basename(base_start_touch_path)}"
            )
        return False

    cbase_trigger_vtable_data = _read_yaml(cbase_trigger_vtable_path)
    if not isinstance(cbase_trigger_vtable_data, dict):
        if debug:
            print(
                "    Preprocess: failed to read vtable YAML: "
                f"{os.path.basename(cbase_trigger_vtable_path)}"
            )
        return False

    raw_entries = cbase_trigger_vtable_data.get("vtable_entries", {})
    if not isinstance(raw_entries, dict):
        if debug:
            print("    Preprocess: invalid vtable_entries in CBaseTrigger_vtable YAML")
        return False

    vtable_entries = {}
    for idx, addr in raw_entries.items():
        try:
            vtable_entries[int(idx)] = str(addr)
        except (TypeError, ValueError):
            if debug:
                print(f"    Preprocess: invalid vtable entry index: {idx}")
            return False

    for func_name, relative_index in TARGET_FUNCTION_SPECS:
        target_index = base_start_touch_index + relative_index
        target_addr_hex = vtable_entries.get(target_index)
        if not target_addr_hex:
            if debug:
                print(
                    "    Preprocess: CBaseTrigger vtable missing index "
                    f"{target_index} for {func_name}"
                )
            return False

        func_info = await _query_function_info(session, target_addr_hex)
        if not isinstance(func_info, dict):
            if debug:
                print(f"    Preprocess: failed to query function info for {func_name}")
            return False

        func_va_hex = func_info.get("func_va")
        func_size_hex = func_info.get("func_size")
        if not func_va_hex or not func_size_hex:
            if debug:
                print(f"    Preprocess: incomplete function info for {func_name}")
            return False

        try:
            func_va_int = int(str(func_va_hex), 16)
        except (TypeError, ValueError):
            if debug:
                print(f"    Preprocess: invalid func_va for {func_name}: {func_va_hex}")
            return False

        target_output = matched_outputs[func_name]
        payload = {
            "func_va": str(func_va_hex),
            "func_rva": hex(func_va_int - image_base),
            "func_size": str(func_size_hex),
            "vtable_name": TARGET_VTABLE_NAME,
            "vfunc_offset": hex(target_index * 8),
            "vfunc_index": target_index,
        }

        old_func_sig = _read_old_func_sig(old_yaml_map, target_output)
        if old_func_sig:
            payload["func_sig"] = old_func_sig

        write_func_yaml(target_output, payload)
        if debug:
            print(
                "    Preprocess: generated "
                f"{func_name}.{platform}.yaml from vtable index {target_index}"
            )

    return True