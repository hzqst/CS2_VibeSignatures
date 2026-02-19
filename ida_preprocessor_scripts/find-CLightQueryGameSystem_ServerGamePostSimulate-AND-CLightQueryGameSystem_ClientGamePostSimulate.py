#!/usr/bin/env python3
"""Preprocess script for find-CLightQueryGameSystem_ServerGamePostSimulate-AND-CLightQueryGameSystem_ClientGamePostSimulate skill.

Locates the two stub virtual functions by:
1. Reading CLightQueryGameSystem_OnPostSimulate YAML for its func_va
2. Reading CLightQueryGameSystem_vtable YAML for vtable entries
3. Using xrefs_to MCP tool to find code xrefs to OnPostSimulate (stub functions)
4. Matching stub addresses against vtable entries to determine vfunc_index
5. Smaller vfunc_index -> ServerGamePostSimulate, larger -> ClientGamePostSimulate
"""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import parse_mcp_result, write_func_yaml, _rename_func_in_ida


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
    """Resolve ServerGamePostSimulate and ClientGamePostSimulate via xrefs + vtable matching."""
    _ = skill_name

    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required")
        return False

    # --- 1. Read OnPostSimulate YAML for func_va ---
    on_post_sim_path = os.path.join(
        new_binary_dir,
        f"CLightQueryGameSystem_OnPostSimulate.{platform}.yaml",
    )
    on_post_sim_data = _read_yaml(on_post_sim_path)
    if not isinstance(on_post_sim_data, dict):
        if debug:
            print("    Preprocess: failed to read CLightQueryGameSystem_OnPostSimulate YAML")
        return False

    try:
        on_post_sim_va = _parse_int(on_post_sim_data["func_va"])
    except (KeyError, ValueError):
        if debug:
            print("    Preprocess: invalid func_va in OnPostSimulate YAML")
        return False

    # --- 2. Read vtable YAML ---
    vtable_path = os.path.join(
        new_binary_dir,
        f"CLightQueryGameSystem_vtable.{platform}.yaml",
    )
    vtable_data = _read_yaml(vtable_path)
    if not isinstance(vtable_data, dict):
        if debug:
            print("    Preprocess: failed to read CLightQueryGameSystem_vtable YAML")
        return False

    raw_entries = vtable_data.get("vtable_entries", {})
    vtable_entries = {}
    for idx, addr in raw_entries.items():
        try:
            vtable_entries[int(idx)] = _parse_int(addr)
        except (ValueError, TypeError):
            continue

    # Build reverse map: func_addr -> vfunc_index
    addr_to_index = {addr: idx for idx, addr in vtable_entries.items()}

    # --- 3. Use MCP xrefs_to to find code xrefs to OnPostSimulate (stub functions) ---
    try:
        xref_result = await session.call_tool(
            name="xrefs_to",
            arguments={"addrs": hex(on_post_sim_va)},
        )
        xref_data = parse_mcp_result(xref_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: xrefs_to failed: {e}")
        return False

    # xrefs_to returns: [{"addr": "0x...", "xrefs": [{"addr": "0x...", "type": "code", "fn": {...}}, ...]}]
    stub_candidates = []
    if isinstance(xref_data, list) and len(xref_data) > 0:
        xrefs = xref_data[0].get("xrefs", [])
        for xref in xrefs:
            if xref.get("type") != "code":
                continue
            fn = xref.get("fn")
            if not fn:
                continue
            fn_size = _parse_int(fn.get("size", "0x0"))
            if fn_size <= 16:
                stub_candidates.append(_parse_int(xref["addr"]))

    if not stub_candidates:
        if debug:
            print("    Preprocess: no stub candidates found via xrefs")
        return False

    if debug:
        print(f"    Preprocess: found {len(stub_candidates)} stub candidate(s)")

    # --- 4. Match stubs against vtable entries ---
    matched = []
    for stub_addr in stub_candidates:
        vfunc_idx = addr_to_index.get(stub_addr)
        if vfunc_idx is not None:
            matched.append((vfunc_idx, stub_addr))

    if len(matched) != 2:
        if debug:
            print(
                f"    Preprocess: expected 2 vtable-matched stubs, got {len(matched)}: "
                f"{[(hex(a), i) for i, a in matched]}"
            )
        return False

    # --- 5. Sort: smaller index -> Server, larger -> Client ---
    matched.sort(key=lambda x: x[0])
    server_index, server_addr = matched[0]
    client_index, client_addr = matched[1]

    if debug:
        print(
            f"    Preprocess: ServerGamePostSimulate -> vtable[{server_index}] @ {hex(server_addr)}"
        )
        print(
            f"    Preprocess: ClientGamePostSimulate -> vtable[{client_index}] @ {hex(client_addr)}"
        )

    # --- 6. Build YAML data and write ---
    targets = [
        ("CLightQueryGameSystem_ServerGamePostSimulate", server_addr, server_index),
        ("CLightQueryGameSystem_ClientGamePostSimulate", client_addr, client_index),
    ]

    for func_name, func_addr, vfunc_index in targets:
        target_filename = f"{func_name}.{platform}.yaml"
        target_outputs = [
            p for p in expected_outputs if os.path.basename(p) == target_filename
        ]
        if len(target_outputs) != 1:
            if debug:
                print(
                    f"    Preprocess: expected exactly one output named {target_filename}, "
                    f"got {len(target_outputs)}"
                )
            return False

        func_rva = func_addr - image_base
        vfunc_offset = vfunc_index * 8

        func_data = {
            "func_name": func_name,
            "func_va": hex(func_addr),
            "func_rva": hex(func_rva),
            "func_size": hex(0),  # placeholder, will be filled by IDA
            "vtable_name": "CLightQueryGameSystem",
            "vfunc_offset": hex(vfunc_offset),
            "vfunc_index": vfunc_index,
        }

        # Try to get actual func_size from IDA
        try:
            size_result = await session.call_tool(
                name="py_eval",
                arguments={
                    "code": (
                        f"import idaapi, json\n"
                        f"func = idaapi.get_func({func_addr})\n"
                        f"print(json.dumps({{'size': hex(func.size()) if func else '0x0'}}))"
                    )
                },
            )
            size_data = parse_mcp_result(size_result)
            if isinstance(size_data, dict):
                stdout = size_data.get("stdout", "")
                if stdout:
                    parsed = json.loads(stdout.strip())
                    func_data["func_size"] = parsed["size"]
        except Exception:
            pass

        await _rename_func_in_ida(session, hex(func_addr), func_name, debug)
        write_func_yaml(target_outputs[0], func_data)
        if debug:
            print(f"    Preprocess: generated {target_filename}")

    return True
