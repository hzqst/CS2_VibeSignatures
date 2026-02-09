#!/usr/bin/env python3
"""
IDA Skill Preprocessor for CS2_VibeSignatures

Attempts to pre-process skills before invoking full agent-based analysis.
Supports two preprocessing modes:
  1. Vtable generation: directly looks up vtable by class name via py_eval
  2. Signature-based function search: reuses old-version func_sig via find_bytes

Connects to IDA MCP and builds new YAML data for successful matches.
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


# Combined vtable lookup + entry reading script for IDA py_eval.
# Merges logic from get-vtable-address/SKILL.md and write-vtable-as-yaml/SKILL.md.
# Uses CLASS_NAME_PLACEHOLDER for substitution (avoids brace-escaping issues).
# Returns JSON via the 'result' variable.
_VTABLE_PY_EVAL_TEMPLATE = r'''
import ida_bytes, ida_name, idaapi, idautils, ida_segment, json

class_name = "CLASS_NAME_PLACEHOLDER"
ptr_size = 8 if idaapi.inf_is_64bit() else 4

vtable_start = None
vtable_symbol = ""
is_linux = False

# Direct symbol: Windows ??_7ClassName@@6B@
win_name = "??_7" + class_name + "@@6B@"
addr = ida_name.get_name_ea(idaapi.BADADDR, win_name)
if addr != idaapi.BADADDR:
    vtable_start = addr
    vtable_symbol = win_name
    is_linux = False

# Direct symbol: Linux _ZTV<len>ClassName
if vtable_start is None:
    linux_name = "_ZTV" + str(len(class_name)) + class_name
    addr = ida_name.get_name_ea(idaapi.BADADDR, linux_name)
    if addr != idaapi.BADADDR:
        vtable_start = addr + 0x10
        vtable_symbol = linux_name + " + 0x10"
        is_linux = True

# RTTI fallback: Windows ??_R4ClassName@@6B@
if vtable_start is None:
    col_name = "??_R4" + class_name + "@@6B@"
    col_addr = ida_name.get_name_ea(idaapi.BADADDR, col_name)
    if col_addr != idaapi.BADADDR:
        is_linux = False
        rdata_seg = ida_segment.get_segm_by_name(".rdata")
        for ref in idautils.DataRefsTo(col_addr):
            if rdata_seg and not (rdata_seg.start_ea <= ref < rdata_seg.end_ea):
                continue
            vtable_start = ref + ptr_size
            sym = ida_name.get_name(vtable_start) or ("??_7" + class_name + "@@6B@")
            vtable_symbol = sym
            break

# RTTI fallback: Linux _ZTI<len>ClassName
if vtable_start is None:
    ti_name = "_ZTI" + str(len(class_name)) + class_name
    ti_addr = ida_name.get_name_ea(idaapi.BADADDR, ti_name)
    if ti_addr != idaapi.BADADDR:
        is_linux = True
        for ref in idautils.DataRefsTo(ti_addr):
            ott = ida_bytes.get_qword(ref - ptr_size) if ptr_size == 8 else ida_bytes.get_dword(ref - ptr_size)
            if ott == 0:
                vtable_start = ref + ptr_size
                ztv_addr = ref - ptr_size
                ztv_name = ida_name.get_name(ztv_addr) or ("_ZTV" + str(len(class_name)) + class_name)
                vtable_symbol = ztv_name + " + 0x10"
                break

if vtable_start is None:
    result = json.dumps(None)
else:
    entries = {}
    count = 0
    for i in range(1000):
        ea = vtable_start + i * ptr_size
        if is_linux and i > 0:
            name = ida_name.get_name(ea)
            if name and (name.startswith("_ZTV") or name.startswith("_ZTI")):
                break
        ptr_value = ida_bytes.get_qword(ea) if ptr_size == 8 else ida_bytes.get_dword(ea)
        if ptr_value == 0:
            if is_linux:
                entries[count] = hex(ptr_value)
                count += 1
                continue
            else:
                break
        if ptr_value == 0xFFFFFFFFFFFFFFFF:
            break
        func = idaapi.get_func(ptr_value)
        if func is not None:
            entries[count] = hex(ptr_value)
            count += 1
            continue
        flags = ida_bytes.get_full_flags(ptr_value)
        if ida_bytes.is_code(flags):
            entries[count] = hex(ptr_value)
            count += 1
            continue
        break

    size_in_bytes = count * ptr_size
    result = json.dumps({
        "vtable_class": class_name,
        "vtable_symbol": vtable_symbol,
        "vtable_va": hex(vtable_start),
        "vtable_size": hex(size_in_bytes),
        "vtable_numvfunc": count,
        "vtable_entries": entries
    })
'''


def parse_mcp_result(result):
    """Parse CallToolResult content to Python object."""
    if result.content:
        text = result.content[0].text
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text
    return None


def _is_vtable_output(filename):
    """Check if filename matches the vtable output pattern: *_vtable.{platform}.yaml"""
    return "_vtable." in filename and filename.endswith(".yaml")


def _extract_class_name(filename):
    """Extract class name from vtable filename like 'CSource2Server_vtable.windows.yaml'."""
    idx = filename.index("_vtable.")
    return filename[:idx]


def _build_vtable_py_eval(class_name):
    """Build the vtable py_eval script for the given class name."""
    return _VTABLE_PY_EVAL_TEMPLATE.replace("CLASS_NAME_PLACEHOLDER", class_name)


def write_vtable_yaml(path, data):
    """Write vtable YAML matching the format produced by write-vtable-as-yaml skill."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"vtable_class: {data['vtable_class']}\n")
        f.write(f"vtable_symbol: {data['vtable_symbol']}\n")
        f.write(f"vtable_va: '{data['vtable_va']}'\n")
        f.write(f"vtable_rva: '{data['vtable_rva']}'\n")
        f.write(f"vtable_size: '{data['vtable_size']}'\n")
        f.write(f"vtable_numvfunc: {data['vtable_numvfunc']}\n")
        f.write("vtable_entries:\n")
        for idx in sorted(data["vtable_entries"].keys()):
            f.write(f"  {idx}: '{data['vtable_entries'][idx]}'\n")


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


async def _preprocess_vtable_via_mcp(session, class_name, image_base, platform, debug=False):
    """
    Preprocess a vtable output by looking up the class vtable via py_eval.

    No old YAML is needed - vtable lookup is purely class-name-based.

    Args:
        session: Active MCP ClientSession
        class_name: Class name (e.g., "CSource2Server")
        image_base: Binary image base address (int)
        platform: "windows" or "linux"
        debug: Enable debug output

    Returns:
        Dict with vtable YAML data, or None on failure
    """
    py_code = _build_vtable_py_eval(class_name)

    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code}
        )
        result_data = parse_mcp_result(result)
    except Exception as e:
        if debug:
            print(f"    Preprocess vtable: py_eval error for {class_name}: {e}")
        return None

    # Parse py_eval result
    vtable_info = None
    if isinstance(result_data, dict):
        result_str = result_data.get("result", "")
        if result_str:
            try:
                vtable_info = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not vtable_info or not isinstance(vtable_info, dict):
        if debug:
            print(f"    Preprocess vtable: no result for {class_name}")
        return None

    # Compute vtable_rva (py_eval doesn't know image_base)
    vtable_va_int = int(vtable_info["vtable_va"], 16)
    vtable_rva = hex(vtable_va_int - image_base)

    # Convert vtable_entries keys from string to int (JSON serialization side-effect)
    raw_entries = vtable_info.get("vtable_entries", {})
    entries = {int(k): v for k, v in raw_entries.items()}

    return {
        "vtable_class": vtable_info["vtable_class"],
        "vtable_symbol": vtable_info["vtable_symbol"],
        "vtable_va": vtable_info["vtable_va"],
        "vtable_rva": vtable_rva,
        "vtable_size": vtable_info["vtable_size"],
        "vtable_numvfunc": vtable_info["vtable_numvfunc"],
        "vtable_entries": entries,
    }


async def _preprocess_func_sig_via_mcp(
    session, new_path, old_path, image_base, new_binary_dir, platform, debug=False
):
    """
    Preprocess a function output by reusing old-version func_sig signature.

    Searches the old signature in the new binary via find_bytes.
    For unique matches, builds new YAML data (func_va, func_rva, func_size, func_sig).
    For vfuncs, additionally cross-references with the new vtable YAML for vfunc_offset/index.

    Args:
        session: Active MCP ClientSession
        new_path: Full path to expected output YAML
        old_path: Full path to old version YAML (may be None)
        image_base: Binary image base address (int)
        new_binary_dir: Directory for new version outputs
        platform: "windows" or "linux"
        debug: Enable debug output

    Returns:
        Dict with function YAML data, or None on failure
    """
    # Check if old YAML exists
    if not old_path or not os.path.exists(old_path):
        if debug:
            print(f"    Preprocess: no old YAML for {os.path.basename(new_path)}")
        return None

    # Read old YAML
    try:
        with open(old_path, "r", encoding="utf-8") as f:
            old_data = yaml.safe_load(f)
    except Exception:
        return None

    if not old_data or not isinstance(old_data, dict):
        return None

    func_sig = old_data.get("func_sig")
    if not func_sig:
        if debug:
            print(f"    Preprocess: no func_sig in {os.path.basename(old_path)}")
        return None

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
        return None

    # Parse find_bytes result: list of {pattern, matches, n, ...}
    if not isinstance(fb_data, list) or len(fb_data) == 0:
        return None

    entry = fb_data[0]
    matches = entry.get("matches", [])
    match_count = entry.get("n", len(matches))

    if match_count != 1:
        if debug:
            print(f"    Preprocess: {os.path.basename(old_path)} sig matched {match_count} (need 1)")
        return None

    match_addr = matches[0]  # hex string like "0x180bb1470"

    # Get function info from match address via py_eval
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
        return None

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
        return None

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
            # Generate vtable YAML on-the-fly via py_eval
            vtable_gen_data = await _preprocess_vtable_via_mcp(
                session, vtable_name, image_base, platform, debug
            )
            if vtable_gen_data is None:
                if debug:
                    print(f"    Preprocess: vtable YAML not found and generation failed: {os.path.basename(vtable_yaml_path)}")
                return None
            write_vtable_yaml(vtable_yaml_path, vtable_gen_data)
            if debug:
                print(f"    Preprocess: generated vtable YAML: {os.path.basename(vtable_yaml_path)}")

        try:
            with open(vtable_yaml_path, "r", encoding="utf-8") as vf:
                vtable_data = yaml.safe_load(vf)
        except Exception:
            return None

        vtable_entries = vtable_data.get("vtable_entries", {})
        found_index = None
        for idx, entry_addr in vtable_entries.items():
            if int(str(entry_addr), 16) == func_va_int:
                found_index = int(idx)
                break

        if found_index is None:
            if debug:
                print(f"    Preprocess: {func_va_hex} not in {vtable_name} vtable entries")
            return None

        new_data["vtable_name"] = vtable_name
        new_data["vfunc_offset"] = hex(found_index * 8)
        new_data["vfunc_index"] = found_index

    return new_data


async def preprocess_single_skill_via_mcp(
    host, port, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, debug=False
):
    """
    Attempt to pre-process a single skill via IDA MCP.

    Dispatches each expected output to the appropriate handler:
      - Vtable outputs (*_vtable.{platform}.yaml): direct class-name-based lookup
      - Function outputs: signature-based search using old-version func_sig

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
                pending_yamls = {}  # new_path -> (data, is_vtable)

                for new_path in expected_outputs:
                    filename = os.path.basename(new_path)

                    if _is_vtable_output(filename):
                        # Vtable preprocessing - no old YAML needed
                        class_name = _extract_class_name(filename)
                        data = await _preprocess_vtable_via_mcp(
                            session, class_name, image_base, platform, debug
                        )
                        if data is None:
                            if debug:
                                print(f"    Preprocess: vtable lookup failed for {class_name}")
                            skill_success = False
                            break
                        pending_yamls[new_path] = (data, True)
                    else:
                        # Function signature preprocessing - needs old YAML
                        old_path = old_yaml_map.get(new_path)
                        data = await _preprocess_func_sig_via_mcp(
                            session, new_path, old_path, image_base,
                            new_binary_dir, platform, debug
                        )
                        if data is None:
                            skill_success = False
                            break
                        pending_yamls[new_path] = (data, False)

                # Write all YAMLs only if ALL outputs succeeded
                if skill_success and len(pending_yamls) == len(expected_outputs):
                    for path, (data, is_vtable) in pending_yamls.items():
                        if is_vtable:
                            write_vtable_yaml(path, data)
                        else:
                            write_func_yaml(path, data)
                    if debug:
                        print(f"    Preprocess: {skill_name} - all {len(pending_yamls)} outputs written")
                    return True

    except Exception as e:
        if debug:
            print(f"  Preprocess MCP connection error for {skill_name}: {e}")

    return False
