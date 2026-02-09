#!/usr/bin/env python3
"""
IDA Skill Preprocessor for CS2_VibeSignatures

Attempts to pre-process skills by reusing old-version func_sig signatures.
Connects to IDA MCP, searches old signatures in the new binary via find_bytes,
and builds new YAML data for unique matches.

Used by ida_analyze_bin.py as a fast path before invoking full agent-based analysis.
"""

import json
import os

try:
    import yaml
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
except ImportError:
    pass


def parse_mcp_result(result):
    """Parse CallToolResult content to Python object."""
    if result.content:
        text = result.content[0].text
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text
    return None


def write_func_yaml(path, data):
    """Write function/vfunc YAML in the same format as write-func-as-yaml skill."""
    ordered_keys = [
        "func_va", "func_rva", "func_size", "func_sig",
        "vtable_name", "vfunc_offset", "vfunc_index",
    ]
    with open(path, "w", encoding="utf-8") as f:
        for key in ordered_keys:
            if key in data:
                f.write(f"{key}: {data[key]}\n")


async def preprocess_single_skill_via_mcp(
    host, port, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, debug=False
):
    """
    Attempt to pre-process a single skill by reusing old-version func_sig signatures.

    Connects to IDA MCP, searches the old signature in the new binary via find_bytes.
    For unique matches, builds new YAML data (func_va, func_rva, func_size, func_sig).
    For vfuncs, additionally cross-references with the new vtable YAML for vfunc_offset/index.

    Args:
        host: MCP server host
        port: MCP server port
        skill_name: name of the skill to preprocess
        expected_outputs: list of expected output YAML paths
        old_yaml_map: dict mapping new_yaml_path -> old_yaml_path
        new_binary_dir: directory for new version YAML outputs
        platform: "windows" or "linux"
        debug: enable debug output

    Returns:
        True if all outputs were successfully pre-processed, False otherwise
    """
    server_url = f"http://{host}:{port}/mcp"

    try:
        async with streamable_http_client(server_url) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                # Get image_base once
                ib_result = await session.call_tool(
                    name="py_eval",
                    arguments={"code": "hex(idaapi.get_imagebase())"}
                )
                ib_data = parse_mcp_result(ib_result)
                if isinstance(ib_data, dict):
                    image_base = int(ib_data.get("result", "0x0"), 16)
                else:
                    image_base = int(str(ib_data), 16) if ib_data else 0

                skill_success = True
                pending_yamls = {}  # new_path -> new_data

                for new_path in expected_outputs:
                    old_path = old_yaml_map.get(new_path)

                    # Check if old YAML exists
                    if not old_path or not os.path.exists(old_path):
                        if debug:
                            print(f"    Preprocess: no old YAML for {os.path.basename(new_path)}")
                        skill_success = False
                        break

                    # Read old YAML
                    try:
                        with open(old_path, "r", encoding="utf-8") as f:
                            old_data = yaml.safe_load(f)
                    except Exception:
                        skill_success = False
                        break

                    if not old_data or not isinstance(old_data, dict):
                        skill_success = False
                        break

                    func_sig = old_data.get("func_sig")
                    if not func_sig:
                        if debug:
                            print(f"    Preprocess: no func_sig in {os.path.basename(old_path)}")
                        skill_success = False
                        break

                    # Search signature in new binary via MCP find_bytes
                    try:
                        fb_result = await session.call_tool(
                            name="find_bytes",
                            arguments={"patterns": [func_sig], "limit": 2}
                        )
                        fb_data = parse_mcp_result(fb_result)
                    except Exception as e:
                        if debug:
                            print(f"    Preprocess: find_bytes error: {e}")
                        skill_success = False
                        break

                    # Parse find_bytes result: list of {pattern, matches, n, ...}
                    if not isinstance(fb_data, list) or len(fb_data) == 0:
                        skill_success = False
                        break

                    entry = fb_data[0]
                    matches = entry.get("matches", [])
                    match_count = entry.get("n", len(matches))

                    if match_count != 1:
                        if debug:
                            print(f"    Preprocess: {os.path.basename(old_path)} sig matched {match_count} (need 1)")
                        skill_success = False
                        break

                    match_addr = matches[0]  # hex string like "0x180bb1470"

                    # Get function info from match address via py_eval
                    # NOTE: py_eval looks for a variable named 'result' in exec_locals
                    py_code = (
                        f"import idaapi, json\n"
                        f"addr = {match_addr}\n"
                        f"f = idaapi.get_func(addr)\n"
                        f"if f and f.start_ea == addr:\n"
                        f"    result = json.dumps({{'func_va': hex(f.start_ea), 'func_size': hex(f.end_ea - f.start_ea)}})\n"
                        f"else:\n"
                        f"    result = json.dumps(None)\n"
                    )
                    try:
                        fi_result = await session.call_tool(
                            name="py_eval",
                            arguments={"code": py_code}
                        )
                        fi_data = parse_mcp_result(fi_result)
                    except Exception as e:
                        if debug:
                            print(f"    Preprocess: py_eval error: {e}")
                        skill_success = False
                        break

                    # Parse py_eval result
                    func_info = None
                    if isinstance(fi_data, dict):
                        result_str = fi_data.get("result", "")
                        if result_str:
                            try:
                                func_info = json.loads(result_str)
                            except (json.JSONDecodeError, TypeError):
                                pass

                    if not func_info:
                        if debug:
                            print(f"    Preprocess: could not get func info at {match_addr}")
                        skill_success = False
                        break

                    func_va_hex = func_info["func_va"]
                    func_va_int = int(func_va_hex, 16)
                    func_size_hex = func_info["func_size"]

                    # Build new YAML data
                    new_data = {
                        "func_va": func_va_hex,
                        "func_rva": hex(func_va_int - image_base),
                        "func_size": func_size_hex,
                        "func_sig": func_sig,
                    }

                    # For vfunc: cross-reference with vtable YAML
                    if "vtable_name" in old_data:
                        vtable_name = old_data["vtable_name"]
                        vtable_yaml_path = os.path.join(
                            new_binary_dir,
                            f"{vtable_name}_vtable.{platform}.yaml"
                        )

                        if not os.path.exists(vtable_yaml_path):
                            if debug:
                                print(f"    Preprocess: vtable YAML not found: {os.path.basename(vtable_yaml_path)}")
                            skill_success = False
                            break

                        try:
                            with open(vtable_yaml_path, "r", encoding="utf-8") as vf:
                                vtable_data = yaml.safe_load(vf)
                        except Exception:
                            skill_success = False
                            break

                        vtable_entries = vtable_data.get("vtable_entries", {})
                        found_index = None
                        for idx, entry_addr in vtable_entries.items():
                            if int(str(entry_addr), 16) == func_va_int:
                                found_index = int(idx)
                                break

                        if found_index is None:
                            if debug:
                                print(f"    Preprocess: {func_va_hex} not in {vtable_name} vtable entries")
                            skill_success = False
                            break

                        new_data["vtable_name"] = vtable_name
                        new_data["vfunc_offset"] = hex(found_index * 8)
                        new_data["vfunc_index"] = found_index

                    pending_yamls[new_path] = new_data

                # Write all YAMLs only if ALL outputs succeeded
                if skill_success and len(pending_yamls) == len(expected_outputs):
                    for path, data in pending_yamls.items():
                        write_func_yaml(path, data)
                    if debug:
                        print(f"    Preprocess: {skill_name} - all {len(pending_yamls)} outputs written")
                    return True

    except Exception as e:
        if debug:
            print(f"  Preprocess MCP connection error for {skill_name}: {e}")

    return False
