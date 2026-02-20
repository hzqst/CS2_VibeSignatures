#!/usr/bin/env python3
"""Preprocess script for find-IGameSystem_ClientPreRender skill.

Programmatically determines IGameSystem_ClientPreRender and IGameSystem_ClientPreRenderEx by:
1. Reading CLoopModeGame_OnClientPreOutput func_va from its YAML.
2. Finding the first call target (= CLoopModeGame_OnClientPreOutputInternal).
3. Finding two `lea rdx, sub_XXXXXXX` in the internal function.
4. For each, finding the virtual call offset.
5. The one with the smaller vfunc_index = IGameSystem_ClientPreRender.
6. The one with the larger vfunc_index = IGameSystem_ClientPreRenderEx.
7. Resolving the IGameSystem vtable entries at those offsets.
"""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import parse_mcp_result, write_func_yaml


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
    """Resolve IGameSystem_ClientPreRender and ClientPreRenderEx from CLoopModeGame_OnClientPreOutput."""
    _ = skill_name

    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required")
        return False

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
            return int(value.strip(), 0)
        return int(value)

    # 1. Read CLoopModeGame_OnClientPreOutput YAML to get func_va
    src_path = os.path.join(
        new_binary_dir,
        f"CLoopModeGame_OnClientPreOutput.{platform}.yaml",
    )
    src_data = _read_yaml(src_path)
    if not isinstance(src_data, dict) or not src_data.get("func_va"):
        if debug:
            print("    Preprocess: failed to read CLoopModeGame_OnClientPreOutput YAML")
        return False

    src_func_va = str(src_data["func_va"])

    # 2. Read IGameSystem vtable YAML
    vtable_path = os.path.join(
        new_binary_dir,
        f"IGameSystem_vtable.{platform}.yaml",
    )
    vtable_data = _read_yaml(vtable_path)
    if not isinstance(vtable_data, dict):
        if debug:
            print("    Preprocess: failed to read IGameSystem_vtable YAML")
        return False

    raw_entries = vtable_data.get("vtable_entries", {})
    if not isinstance(raw_entries, dict):
        if debug:
            print("    Preprocess: invalid vtable_entries in IGameSystem_vtable YAML")
        return False

    vtable_entries = {}
    for idx, addr in raw_entries.items():
        try:
            vtable_entries[int(idx)] = str(addr)
        except (TypeError, ValueError):
            pass

    # 3. CLoopModeGame_OnClientPreOutput is a thin wrapper that calls
    #    CLoopModeGame_OnClientPreOutputInternal. Find that internal function,
    #    then find two `lea rdx, sub_XXXXXXX` inside it and extract vfunc offsets.
    #    The one with smaller vfunc_index = ClientPreRender,
    #    the one with larger vfunc_index = ClientPreRenderEx.
    py_code = (
        "import idaapi, idautils, idc, json\n"
        f"func_addr = {src_func_va}\n"
        "func = idaapi.get_func(func_addr)\n"
        "result = json.dumps(None)\n"
        "if func:\n"
        "    internal_addr = None\n"
        "    for head in idautils.Heads(func.start_ea, func.end_ea):\n"
        "        mnem = idc.print_insn_mnem(head)\n"
        "        if mnem in ('call', 'jmp'):\n"
        "            target = idc.get_operand_value(head, 0)\n"
        "            if idaapi.get_func(target) and target != func.start_ea:\n"
        "                internal_addr = target\n"
        "                break\n"
        "    if internal_addr:\n"
        "        ifunc = idaapi.get_func(internal_addr)\n"
        "        if ifunc:\n"
        "            lea_targets = []\n"
        "            for head in idautils.Heads(ifunc.start_ea, ifunc.end_ea):\n"
        "                if idc.print_insn_mnem(head) == 'lea' and idc.print_operand(head, 0) == 'rdx':\n"
        "                    t = idc.get_operand_value(head, 1)\n"
        "                    if idaapi.get_func(t):\n"
        "                        lea_targets.append(t)\n"
        "                        if len(lea_targets) == 2:\n"
        "                            break\n"
        "            entries = []\n"
        "            for t in lea_targets:\n"
        "                gef = idaapi.get_func(t)\n"
        "                if gef:\n"
        "                    for head in idautils.Heads(gef.start_ea, gef.end_ea):\n"
        "                        m = idc.print_insn_mnem(head)\n"
        "                        if m in ('call', 'jmp'):\n"
        "                            insn = idaapi.insn_t()\n"
        "                            if idaapi.decode_insn(insn, head):\n"
        "                                op = insn.ops[0]\n"
        "                                if op.type == idaapi.o_displ:\n"
        "                                    entries.append({\n"
        "                                        'game_event_addr': hex(t),\n"
        "                                        'vfunc_offset': op.addr,\n"
        "                                        'vfunc_index': op.addr // 8\n"
        "                                    })\n"
        "                                    break\n"
        "            if len(entries) == 2:\n"
        "                result = json.dumps({'internal_addr': hex(internal_addr), 'entries': entries})\n"
    )

    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        result_data = parse_mcp_result(result)
    except Exception:
        if debug:
            print("    Preprocess: py_eval error finding vfunc offsets")
        return False

    parsed = None
    if isinstance(result_data, dict):
        result_str = result_data.get("result", "")
        if result_str:
            try:
                parsed = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not isinstance(parsed, dict) or not isinstance(parsed.get("entries"), list) or len(parsed["entries"]) != 2:
        if debug:
            print("    Preprocess: failed to determine vfunc offsets from CLoopModeGame_OnClientPreOutput")
        return False

    internal_addr = parsed.get("internal_addr")
    entries = parsed["entries"]

    # Sort by vfunc_index: smaller = ClientPreRender, larger = ClientPreRenderEx
    entries.sort(key=lambda e: e["vfunc_index"])

    target_map = [
        {
            "target_name": "IGameSystem_ClientPreRender",
            "rename_to": "GameSystem_OnClientPreRender",
        },
        {
            "target_name": "IGameSystem_ClientPreRenderEx",
            "rename_to": "GameSystem_OnClientPreRenderEx",
        },
    ]

    if debug:
        for entry, tinfo in zip(entries, target_map):
            print(f"    Preprocess: [{tinfo['target_name']}] vfunc_offset=0x{entry['vfunc_offset']:X}, vfunc_index={entry['vfunc_index']}")

    # 3b. Rename CLoopModeGame_OnClientPreOutputInternal in IDA
    if internal_addr:
        try:
            await session.call_tool(
                name="rename",
                arguments={"batch": {"func": {"addr": internal_addr, "name": "CLoopModeGame_OnClientPreOutputInternal"}}},
            )
        except Exception:
            if debug:
                print("    Preprocess: failed to rename CLoopModeGame_OnClientPreOutputInternal (non-fatal)")

    for entry, tinfo in zip(entries, target_map):
        vfunc_offset = entry["vfunc_offset"]
        vfunc_index = entry["vfunc_index"]
        game_event_addr = entry.get("game_event_addr")

        # 3c. Rename intermediate GameSystem function in IDA
        if game_event_addr:
            try:
                await session.call_tool(
                    name="rename",
                    arguments={"batch": {"func": {"addr": game_event_addr, "name": tinfo["rename_to"]}}},
                )
            except Exception:
                if debug:
                    print(f"    Preprocess: failed to rename {tinfo['rename_to']} (non-fatal)")

        # 4. Look up function address in IGameSystem vtable
        target_addr_hex = vtable_entries.get(vfunc_index)
        if not target_addr_hex:
            if debug:
                print(f"    Preprocess: IGameSystem vtable missing index {vfunc_index}")
            return False

        # 5. Query function info via py_eval
        fi_code = (
            "import idaapi, json\n"
            f"addr = {target_addr_hex}\n"
            "f = idaapi.get_func(addr)\n"
            "if f and f.start_ea == addr:\n"
            "    result = json.dumps({'func_va': hex(f.start_ea), "
            "'func_size': hex(f.end_ea - f.start_ea)})\n"
            "else:\n"
            "    result = json.dumps(None)\n"
        )

        try:
            fi_result = await session.call_tool(
                name="py_eval",
                arguments={"code": fi_code},
            )
            fi_data = parse_mcp_result(fi_result)
        except Exception:
            if debug:
                print(f"    Preprocess: py_eval error querying function info for {tinfo['target_name']}")
            return False

        func_info = None
        if isinstance(fi_data, dict):
            fi_str = fi_data.get("result", "")
            if fi_str:
                try:
                    func_info = json.loads(fi_str)
                except (json.JSONDecodeError, TypeError):
                    pass

        if not isinstance(func_info, dict):
            if debug:
                print(f"    Preprocess: failed to query function info for {tinfo['target_name']}")
            return False

        func_va_hex = func_info.get("func_va")
        func_size_hex = func_info.get("func_size")
        if not func_va_hex or not func_size_hex:
            if debug:
                print(f"    Preprocess: incomplete function info for {tinfo['target_name']}")
            return False

        try:
            func_va_int = int(str(func_va_hex), 16)
        except (TypeError, ValueError):
            if debug:
                print(f"    Preprocess: invalid func_va: {func_va_hex}")
            return False

        # 6. Build and write output YAML
        target_name = tinfo["target_name"]
        payload = {
            "func_name": target_name,
            "func_va": str(func_va_hex),
            "func_rva": hex(func_va_int - image_base),
            "func_size": str(func_size_hex),
            "vtable_name": "IGameSystem",
            "vfunc_offset": hex(vfunc_offset),
            "vfunc_index": vfunc_index,
        }

        output_path = os.path.join(
            new_binary_dir,
            f"{target_name}.{platform}.yaml",
        )
        write_func_yaml(output_path, payload)

        if debug:
            print(f"    Preprocess: written {os.path.basename(output_path)}")

    return True
