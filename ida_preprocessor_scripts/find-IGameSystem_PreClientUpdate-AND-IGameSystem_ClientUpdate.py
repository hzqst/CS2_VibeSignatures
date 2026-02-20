#!/usr/bin/env python3
"""Preprocess script for find-IGameSystem_PreClientUpdate-AND-IGameSystem_ClientUpdate skill.

Programmatically determines IGameSystem_PreClientUpdate and IGameSystem_ClientUpdate by:
1. Reading CLoopModeGame_OnClientSimulate func_va from its YAML.
2. Platform-specific vfunc offset extraction:
   - Windows: Finding the first two `lea rdx, sub_XXXXXXX` targets and extracting vfunc offsets.
   - Linux: Finding two `mov esi, <odd_imm>` + dispatcher call pairs,
     where vfunc_offset = imm - 1 for each.
3. 1st entry = IGameSystem_PreClientUpdate, 2nd = IGameSystem_ClientUpdate.
4. Resolving the IGameSystem vtable entries at those offsets.
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
    """Resolve IGameSystem_PreClientUpdate and IGameSystem_ClientUpdate from CLoopModeGame_OnClientSimulate."""
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

    # 1. Read CLoopModeGame_OnClientSimulate YAML to get func_va
    src_path = os.path.join(
        new_binary_dir,
        f"CLoopModeGame_OnClientSimulate.{platform}.yaml",
    )
    src_data = _read_yaml(src_path)
    if not isinstance(src_data, dict) or not src_data.get("func_va"):
        if debug:
            print("    Preprocess: failed to read CLoopModeGame_OnClientSimulate YAML")
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

    # 3. Use py_eval to find the two vfunc offsets (platform-aware)
    #
    # Windows: two `lea rdx, sub_XXX` → callbacks → `call/jmp [rax+offset]`
    # Linux:   two `mov esi, <odd_imm>` → dispatcher calls
    py_code = (
        "import idaapi, idautils, idc, json\n"
        f"func_addr = {src_func_va}\n"
        "func = idaapi.get_func(func_addr)\n"
        "result = json.dumps(None)\n"
        "if func:\n"
        "    # Try Windows pattern: two lea rdx, sub_XXX\n"
        "    lea_targets = []\n"
        "    for head in idautils.Heads(func.start_ea, func.end_ea):\n"
        "        if idc.print_insn_mnem(head) == 'lea' and idc.print_operand(head, 0) == 'rdx':\n"
        "            target = idc.get_operand_value(head, 1)\n"
        "            if idaapi.get_func(target):\n"
        "                lea_targets.append(target)\n"
        "                if len(lea_targets) == 2:\n"
        "                    break\n"
        "    if len(lea_targets) == 2:\n"
        "        entries = []\n"
        "        for t in lea_targets:\n"
        "            gef = idaapi.get_func(t)\n"
        "            if gef:\n"
        "                for head in idautils.Heads(gef.start_ea, gef.end_ea):\n"
        "                    mnem = idc.print_insn_mnem(head)\n"
        "                    if mnem in ('call', 'jmp'):\n"
        "                        insn = idaapi.insn_t()\n"
        "                        if idaapi.decode_insn(insn, head):\n"
        "                            op = insn.ops[0]\n"
        "                            if op.type == idaapi.o_displ:\n"
        "                                entries.append({\n"
        "                                    'game_event_addr': hex(t),\n"
        "                                    'vfunc_offset': op.addr,\n"
        "                                    'vfunc_index': op.addr // 8\n"
        "                                })\n"
        "                                break\n"
        "        if len(entries) == 2:\n"
        "            result = json.dumps(entries)\n"
        "    else:\n"
        "        # Linux pattern: two mov esi, <odd_imm> + call pairs\n"
        "        entries = []\n"
        "        last_esi_imm = None\n"
        "        for head in idautils.Heads(func.start_ea, func.end_ea):\n"
        "            mnem = idc.print_insn_mnem(head)\n"
        "            if mnem == 'mov':\n"
        "                op0 = idc.print_operand(head, 0)\n"
        "                if op0 in ('esi', 'rsi'):\n"
        "                    insn = idaapi.insn_t()\n"
        "                    if idaapi.decode_insn(insn, head):\n"
        "                        op = insn.ops[1]\n"
        "                        if op.type == idaapi.o_imm and (op.value & 1) != 0 and op.value > 1:\n"
        "                            last_esi_imm = op.value\n"
        "            elif mnem == 'call' and last_esi_imm is not None:\n"
        "                vfunc_off = last_esi_imm - 1\n"
        "                entries.append({\n"
        "                    'vfunc_offset': vfunc_off,\n"
        "                    'vfunc_index': vfunc_off // 8\n"
        "                })\n"
        "                last_esi_imm = None\n"
        "                if len(entries) == 2:\n"
        "                    break\n"
        "        if len(entries) == 2:\n"
        "            result = json.dumps(entries)\n"
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

    entries = None
    if isinstance(result_data, dict):
        result_str = result_data.get("result", "")
        if result_str:
            try:
                entries = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not isinstance(entries, list) or len(entries) != 2:
        if debug:
            print("    Preprocess: failed to determine vfunc offsets from CLoopModeGame_OnClientSimulate")
        return False

    # Map: index 0 = PreClientUpdate, index 1 = ClientUpdate
    target_map = [
        {
            "target_name": "IGameSystem_PreClientUpdate",
            "rename_to": "GameSystem_OnPreClientUpdate",
        },
        {
            "target_name": "IGameSystem_ClientUpdate",
            "rename_to": "GameSystem_OnClientUpdate",
        },
    ]

    for i, (entry, tinfo) in enumerate(zip(entries, target_map)):
        vfunc_offset = entry["vfunc_offset"]
        vfunc_index = entry["vfunc_index"]
        game_event_addr = entry.get("game_event_addr")

        if debug:
            print(f"    Preprocess: [{tinfo['target_name']}] vfunc_offset=0x{vfunc_offset:X}, vfunc_index={vfunc_index}")

        # 3b. Rename intermediate function in IDA
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
