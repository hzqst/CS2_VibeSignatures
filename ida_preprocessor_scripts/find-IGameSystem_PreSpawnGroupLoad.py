#!/usr/bin/env python3
"""Preprocess script for find-IGameSystem_PreSpawnGroupLoad skill.

Programmatically determines IGameSystem_PreSpawnGroupLoad by:
1. Reading CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal func_va from its YAML.
2. Platform-specific vfunc offset extraction:
   - Windows: Finding the 1st `lea rdx, sub_XXXXXXX` (= GameEvent_PreSpawnGroupLoad callback),
     then extracting the vfunc offset from its `call/jmp [rax+offset]`.
   - Linux: Finding the 1st `mov esi, <odd_imm>` before a dispatcher call,
     where vfunc_offset = imm - 1.
3. Resolving the IGameSystem vtable entry at that offset.
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
    """Resolve IGameSystem_PreSpawnGroupLoad from CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal."""
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

    # 1. Read CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal YAML to get func_va
    src_path = os.path.join(
        new_binary_dir,
        f"CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal.{platform}.yaml",
    )
    src_data = _read_yaml(src_path)
    if not isinstance(src_data, dict) or not src_data.get("func_va"):
        if debug:
            print("    Preprocess: failed to read CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal YAML")
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

    # 3. Use py_eval to extract vfunc offset (platform-aware)
    #
    # Windows: The 1st `lea rdx, sub_XXX` loads the PreSpawnGroupLoad callback;
    #          callback does `jmp/call [rax+offset]` where offset is the vfunc byte offset.
    #
    # Linux:   The 1st `mov esi, <odd_imm>` before a dispatcher call,
    #          where vfunc_offset = imm - 1.
    py_code = (
        "import idaapi, idautils, idc, json\n"
        f"func_addr = {src_func_va}\n"
        "func = idaapi.get_func(func_addr)\n"
        "result = json.dumps(None)\n"
        "if func:\n"
        "    # Try Windows pattern: find the 1st lea rdx, sub_XXX\n"
        "    game_event_addr = None\n"
        "    for head in idautils.Heads(func.start_ea, func.end_ea):\n"
        "        if idc.print_insn_mnem(head) == 'lea' and idc.print_operand(head, 0) == 'rdx':\n"
        "            target = idc.get_operand_value(head, 1)\n"
        "            if idaapi.get_func(target):\n"
        "                game_event_addr = target\n"
        "                break\n"
        "    if game_event_addr:\n"
        "        gef = idaapi.get_func(game_event_addr)\n"
        "        if gef:\n"
        "            for head in idautils.Heads(gef.start_ea, gef.end_ea):\n"
        "                mnem = idc.print_insn_mnem(head)\n"
        "                if mnem in ('call', 'jmp'):\n"
        "                    insn = idaapi.insn_t()\n"
        "                    if idaapi.decode_insn(insn, head):\n"
        "                        op = insn.ops[0]\n"
        "                        if op.type == idaapi.o_displ:\n"
        "                            result = json.dumps({\n"
        "                                'game_event_addr': hex(game_event_addr),\n"
        "                                'vfunc_offset': op.addr,\n"
        "                                'vfunc_index': op.addr // 8\n"
        "                            })\n"
        "                            break\n"
        "    else:\n"
        "        # Linux pattern: 1st mov esi, <odd_imm> before dispatcher call\n"
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
        "                result = json.dumps({\n"
        "                    'vfunc_offset': vfunc_off,\n"
        "                    'vfunc_index': vfunc_off // 8\n"
        "                })\n"
        "                break\n"
    )

    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        result_data = parse_mcp_result(result)
    except Exception:
        if debug:
            print("    Preprocess: py_eval error finding vfunc offset")
        return False

    vfunc_info = None
    if isinstance(result_data, dict):
        result_str = result_data.get("result", "")
        if result_str:
            try:
                vfunc_info = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not isinstance(vfunc_info, dict):
        if debug:
            print("    Preprocess: failed to determine vfunc offset from CSpawnGroupMgrGameSystem_SpawnGroupSpawnEntitiesInternal")
        return False

    vfunc_offset = vfunc_info["vfunc_offset"]
    vfunc_index = vfunc_info["vfunc_index"]
    game_event_addr = vfunc_info.get("game_event_addr")

    if debug:
        print(f"    Preprocess: found vfunc_offset=0x{vfunc_offset:X}, vfunc_index={vfunc_index}")

    # 3b. Rename GameEvent_PreSpawnGroupLoad in IDA (Windows only)
    if game_event_addr:
        try:
            await session.call_tool(
                name="rename",
                arguments={"batch": {"func": {"addr": game_event_addr, "name": "GameEvent_PreSpawnGroupLoad"}}},
            )
        except Exception:
            if debug:
                print("    Preprocess: failed to rename GameEvent_PreSpawnGroupLoad (non-fatal)")

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
            print("    Preprocess: py_eval error querying function info")
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
            print("    Preprocess: failed to query function info for IGameSystem_PreSpawnGroupLoad")
        return False

    func_va_hex = func_info.get("func_va")
    func_size_hex = func_info.get("func_size")
    if not func_va_hex or not func_size_hex:
        if debug:
            print("    Preprocess: incomplete function info")
        return False

    try:
        func_va_int = int(str(func_va_hex), 16)
    except (TypeError, ValueError):
        if debug:
            print(f"    Preprocess: invalid func_va: {func_va_hex}")
        return False

    # 6. Build and write output YAML
    target_name = "IGameSystem_PreSpawnGroupLoad"
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
