#!/usr/bin/env python3
"""Shared utility helpers for IDA analyze scripts."""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None


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
    """Parse CallToolResult content to a Python object."""
    if result.content:
        text = result.content[0].text
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text
    return None


def _build_vtable_py_eval(class_name):
    """Build the vtable py_eval script for the given class name."""
    return _VTABLE_PY_EVAL_TEMPLATE.replace("CLASS_NAME_PLACEHOLDER", class_name)


def write_vtable_yaml(path, data):
    """Write vtable YAML matching the format produced by write-vtable-as-yaml skill."""
    if yaml is None:
        raise RuntimeError("PyYAML is required to write vtable YAML")

    raw_entries = data.get("vtable_entries", {})
    normalized_entries = {int(k): str(v) for k, v in raw_entries.items()}
    payload = {
        "vtable_class": data["vtable_class"],
        "vtable_symbol": data["vtable_symbol"],
        "vtable_va": str(data["vtable_va"]),
        "vtable_rva": str(data["vtable_rva"]),
        "vtable_size": str(data["vtable_size"]),
        "vtable_numvfunc": data["vtable_numvfunc"],
        "vtable_entries": dict(sorted(normalized_entries.items())),
    }

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            payload,
            f,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=False,
        )

def write_func_yaml(path, data):
    """Write function/vfunc YAML with the same key set and key order as write-func-as-yaml; scalar quoting/styling is handled by PyYAML."""
    if yaml is None:
        raise RuntimeError("PyYAML is required to write function YAML")

    ordered_keys = [
        "func_va", "func_rva", "func_size", "func_sig",
        "vtable_name", "vfunc_offset", "vfunc_index",
    ]
    payload = {key: data[key] for key in ordered_keys if key in data}

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            payload,
            f,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=False,
        )

def write_gv_yaml(path, data):
    """Write global-variable YAML with the same key set and key order as write-globalvar-as-yaml; scalar quoting/styling is handled by PyYAML."""
    if yaml is None:
        raise RuntimeError("PyYAML is required to write global-variable YAML")

    ordered_keys = [
        "gv_va", "gv_rva", "gv_sig", "gv_sig_va",
        "gv_inst_offset", "gv_inst_length", "gv_inst_disp",
    ]
    payload = {key: data[key] for key in ordered_keys if key in data}

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            payload,
            f,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=False,
        )

async def preprocess_vtable_via_mcp(session, class_name, image_base, platform, debug=False):
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
    _ = platform  # Reserved for future platform-specific behavior.
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


async def preprocess_func_sig_via_mcp(
    session, new_path, old_path, image_base, new_binary_dir, platform, debug=False
):
    """
    Preprocess a function output by reusing old-version signature metadata.

    Primary path:
    - Reuse old `func_sig`, locate unique match in the new binary, and resolve
      function metadata from the matched function head.

    Fallback path (for old YAML without `func_sig`):
    - Reuse old `vfunc_sig` (must uniquely match in the new binary), then reuse
      old vfunc index/offset and resolve function metadata from the
      corresponding entry in the new vtable YAML.
    - After resolving function VA/size from vtable, try to generate a new
      function-head `func_sig` automatically.

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
    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required for func_sig preprocessing")
        return None

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

    def _parse_int_field(value, field_name):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                raise ValueError(f"empty {field_name}")
            return int(raw, 0)
        return int(value)

    async def _find_unique_match(signature, label):
        try:
            fb_result = await session.call_tool(
                name="find_bytes",
                arguments={"patterns": [signature], "limit": 2}
            )
            fb_data = parse_mcp_result(fb_result)
        except Exception as e:
            if debug:
                print(f"    Preprocess: find_bytes error: {e}")
            return None

        if not isinstance(fb_data, list) or len(fb_data) == 0:
            return None

        entry = fb_data[0]
        if not isinstance(entry, dict):
            return None

        matches = entry.get("matches", [])
        match_count = entry.get("n", len(matches))
        if match_count != 1:
            if debug:
                print(f"    Preprocess: {label} matched {match_count} (need 1)")
            return None

        return matches[0]

    async def _get_func_info(addr_expr):
        py_code = (
            f"import idaapi, json\n"
            f"addr = {addr_expr}\n"
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

        func_info = None
        if isinstance(fi_data, dict):
            stderr_text = fi_data.get("stderr", "")
            if stderr_text and debug:
                print("    Preprocess: py_eval stderr:")
                print(stderr_text.strip())
            result_str = fi_data.get("result", "")
            if result_str:
                try:
                    func_info = json.loads(result_str)
                except (json.JSONDecodeError, TypeError):
                    pass

        if not isinstance(func_info, dict):
            return None
        if "func_va" not in func_info or "func_size" not in func_info:
            return None
        return func_info

    async def _load_vtable_data(vtable_name):
        vtable_yaml_path = os.path.join(
            new_binary_dir,
            f"{vtable_name}_vtable.{platform}.yaml"
        )

        if not os.path.exists(vtable_yaml_path):
            # Generate vtable YAML on-the-fly via py_eval
            vtable_gen_data = await preprocess_vtable_via_mcp(
                session, vtable_name, image_base, platform, debug
            )
            if vtable_gen_data is None:
                if debug:
                    print(
                        "    Preprocess: vtable YAML not found and generation failed: "
                        f"{os.path.basename(vtable_yaml_path)}"
                    )
                return None
            write_vtable_yaml(vtable_yaml_path, vtable_gen_data)
            if debug:
                print(f"    Preprocess: generated vtable YAML: {os.path.basename(vtable_yaml_path)}")

        try:
            with open(vtable_yaml_path, "r", encoding="utf-8") as vf:
                vtable_data = yaml.safe_load(vf)
        except Exception:
            return None

        if not isinstance(vtable_data, dict):
            return None
        return vtable_data

    func_sig = old_data.get("func_sig")
    vfunc_sig = old_data.get("vfunc_sig")
    vtable_name = old_data.get("vtable_name")

    used_vfunc_fallback = False
    vfunc_index = None
    vfunc_offset = None
    vfunc_match_addr = None

    if func_sig:
        match_addr = await _find_unique_match(
            func_sig, f"{os.path.basename(old_path)} func_sig"
        )
        if match_addr is None:
            return None

        func_info = await _get_func_info(match_addr)
        if not func_info:
            if debug:
                print(f"    Preprocess: could not get func info at {match_addr}")
            return None
    else:
        used_vfunc_fallback = True
        if not vfunc_sig:
            if debug:
                print(f"    Preprocess: no func_sig/vfunc_sig in {os.path.basename(old_path)}")
            return None
        if not vtable_name:
            if debug:
                print(
                    "    Preprocess: no vtable_name for vfunc fallback in "
                    f"{os.path.basename(old_path)}"
                )
            return None

        has_index = old_data.get("vfunc_index") is not None
        has_offset = old_data.get("vfunc_offset") is not None
        if not has_index and not has_offset:
            if debug:
                print(
                    "    Preprocess: missing vfunc_index/vfunc_offset in "
                    f"{os.path.basename(old_path)}"
                )
            return None

        try:
            if has_index:
                vfunc_index = _parse_int_field(old_data.get("vfunc_index"), "vfunc_index")
            if has_offset:
                vfunc_offset = _parse_int_field(old_data.get("vfunc_offset"), "vfunc_offset")
        except Exception:
            if debug:
                print(f"    Preprocess: invalid vfunc metadata in {os.path.basename(old_path)}")
            return None

        if vfunc_index is None:
            if vfunc_offset % 8 != 0:
                if debug:
                    print(
                        "    Preprocess: vfunc_offset is not 8-byte aligned in "
                        f"{os.path.basename(old_path)}"
                    )
                return None
            vfunc_index = vfunc_offset // 8
        if vfunc_offset is None:
            vfunc_offset = vfunc_index * 8

        if vfunc_index < 0 or vfunc_offset < 0 or vfunc_offset != vfunc_index * 8:
            if debug:
                print(
                    "    Preprocess: inconsistent vfunc_index/vfunc_offset in "
                    f"{os.path.basename(old_path)}"
                )
            return None

        vfunc_match_addr = await _find_unique_match(
            vfunc_sig, f"{os.path.basename(old_path)} vfunc_sig"
        )
        if vfunc_match_addr is None:
            return None

        vtable_data = await _load_vtable_data(vtable_name)
        if not isinstance(vtable_data, dict):
            return None

        vtable_entries = vtable_data.get("vtable_entries", {})
        func_va_from_vtable = None
        for idx, entry_addr in vtable_entries.items():
            try:
                idx_int = int(idx)
            except Exception:
                continue
            if idx_int != vfunc_index:
                continue
            try:
                func_va_from_vtable = int(str(entry_addr), 16)
            except Exception:
                func_va_from_vtable = None
            break

        if func_va_from_vtable is None:
            if debug:
                print(
                    "    Preprocess: vfunc_index not found in vtable entries: "
                    f"{vtable_name}[{vfunc_index}]"
                )
            return None

        func_info = await _get_func_info(hex(func_va_from_vtable))
        if not func_info:
            if debug:
                print(
                    "    Preprocess: could not get func info from vtable entry: "
                    f"{vtable_name}[{vfunc_index}] -> {hex(func_va_from_vtable)}"
                )
            return None

    func_va_hex = func_info["func_va"]
    func_va_int = int(func_va_hex, 16)
    func_size_hex = func_info["func_size"]

    # Build new YAML data
    new_data = {
        "func_va": func_va_hex,
        "func_rva": hex(func_va_int - image_base),
        "func_size": func_size_hex,
    }
    if func_sig:
        new_data["func_sig"] = func_sig

    # vfunc fallback path: reuse old index/offset and regenerate func_sig from vtable-resolved function.
    if used_vfunc_fallback:
        new_data["vtable_name"] = vtable_name
        new_data["vfunc_offset"] = hex(vfunc_offset)
        new_data["vfunc_index"] = vfunc_index

        generated_sig_data = await preprocess_gen_func_sig_via_mcp(
            session=session,
            func_va=func_va_int,
            image_base=image_base,
            debug=debug,
        )
        if generated_sig_data and generated_sig_data.get("func_sig"):
            new_data["func_sig"] = generated_sig_data["func_sig"]
        elif debug:
            print(
                "    Preprocess: vfunc fallback succeeded but func_sig generation failed: "
                f"{os.path.basename(new_path)}"
            )

        if debug:
            print(
                "    Preprocess: reused vfunc_sig + vtable metadata at "
                f"{vfunc_match_addr} for {os.path.basename(new_path)}"
            )
        return new_data

    # For vfunc with func_sig input: cross-reference with new vtable YAML for vfunc_offset/index.
    if vtable_name:
        vtable_data = await _load_vtable_data(vtable_name)
        if not isinstance(vtable_data, dict):
            return None

        vtable_entries = vtable_data.get("vtable_entries", {})
        found_index = None
        for idx, entry_addr in vtable_entries.items():
            try:
                idx_int = int(idx)
                entry_int = int(str(entry_addr), 16)
            except Exception:
                continue
            if entry_int == func_va_int:
                found_index = idx_int
                break

        if found_index is None:
            if debug:
                print(f"    Preprocess: {func_va_hex} not in {vtable_name} vtable entries")
            return None

        new_data["vtable_name"] = vtable_name
        new_data["vfunc_offset"] = hex(found_index * 8)
        new_data["vfunc_index"] = found_index

    return new_data


async def preprocess_gen_func_sig_via_mcp(
    session,
    func_va,
    image_base,
    min_sig_bytes=6,
    max_sig_bytes=96,
    max_instructions=64,
    extra_wildcard_offsets=None,
    debug=False,
):
    """
    Generate a shortest unique function-head signature for a known function address.

    The generated signature always starts at the function entry (func start address),
    never from the middle of a function. The routine progressively searches for the
    shortest prefix that still uniquely resolves to the target function.

    Wildcards:
    - Auto wildcard: volatile operand bytes (imm/near/far/mem/displ) and branch/call
      relative offsets are wildcarded programmatically.
    - Extra wildcard: caller may provide additional byte offsets (relative to func head)
      via extra_wildcard_offsets.

    Args:
        session: Active MCP ClientSession.
        func_va: Function virtual address (int or hex string) and must be function head.
        image_base: Binary image base address (int).
        min_sig_bytes: Minimum signature prefix length to try.
        max_sig_bytes: Maximum bytes collected from function head.
        max_instructions: Max instructions collected from function head.
        extra_wildcard_offsets: Optional iterable of extra wildcard offsets.
        debug: Enable debug output.

    Returns:
        Dict with function YAML data (func_va, func_rva, func_size, func_sig),
        or None on failure.
    """

    def _parse_int(value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                raise ValueError("empty integer string")
            return int(raw, 0)
        return int(value)

    def _parse_addr(value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return int(value.strip(), 0)
        return int(value)

    try:
        func_va_int = _parse_int(func_va)
    except Exception:
        if debug:
            print(f"    Preprocess: invalid func_va: {func_va}")
        return None

    try:
        min_sig_bytes = max(1, int(min_sig_bytes))
        max_sig_bytes = max(1, int(max_sig_bytes))
        max_instructions = max(1, int(max_instructions))
    except Exception:
        if debug:
            print("    Preprocess: invalid signature generation limits")
        return None

    extra_wildcard_set = set()
    if extra_wildcard_offsets:
        try:
            for offset in extra_wildcard_offsets:
                parsed = _parse_int(offset)
                if parsed >= 0:
                    extra_wildcard_set.add(parsed)
        except Exception:
            if debug:
                print("    Preprocess: invalid extra_wildcard_offsets")
            return None

    py_code = (
        "import idaapi, ida_bytes, idautils, ida_ua, json\n"
        f"target_ea = {func_va_int}\n"
        f"max_sig_bytes = {max_sig_bytes}\n"
        f"max_instructions = {max_instructions}\n"
        "f = idaapi.get_func(target_ea)\n"
        "if not f or f.start_ea != target_ea:\n"
        "    result = json.dumps(None)\n"
        "else:\n"
        "    limit_end = min(f.end_ea, target_ea + max_sig_bytes)\n"
        "    insts = []\n"
        "    cursor = target_ea\n"
        "    total = 0\n"
        "    while cursor < f.end_ea and cursor < limit_end and len(insts) < max_instructions:\n"
        "        insn = idautils.DecodeInstruction(cursor)\n"
        "        if not insn or insn.size <= 0:\n"
        "            break\n"
        "        raw = ida_bytes.get_bytes(cursor, insn.size)\n"
        "        if not raw:\n"
        "            break\n"
        "        wild = set()\n"
        "        for op in insn.ops:\n"
        "            op_type = int(op.type)\n"
        "            if op_type == int(idaapi.o_void):\n"
        "                continue\n"
        "            if op_type in (int(idaapi.o_imm), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_mem), int(idaapi.o_displ)):\n"
        "                offb = int(op.offb)\n"
        "                if offb > 0 and offb < insn.size:\n"
        "                    dsz = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))\n"
        "                    if dsz <= 0:\n"
        "                        dsz = insn.size - offb\n"
        "                    end = min(insn.size, offb + dsz)\n"
        "                    for i in range(offb, end):\n"
        "                        wild.add(i)\n"
        "                offo = int(op.offo)\n"
        "                if offo > 0 and offo < insn.size:\n"
        "                    dsz2 = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))\n"
        "                    if dsz2 <= 0:\n"
        "                        dsz2 = insn.size - offo\n"
        "                    end2 = min(insn.size, offo + dsz2)\n"
        "                    for i in range(offo, end2):\n"
        "                        wild.add(i)\n"
        "        b0 = raw[0]\n"
        "        if b0 in (0xE8, 0xE9, 0xEB):\n"
        "            for i in range(1, insn.size):\n"
        "                wild.add(i)\n"
        "        elif b0 == 0x0F and insn.size >= 2 and (raw[1] & 0xF0) == 0x80:\n"
        "            for i in range(2, insn.size):\n"
        "                wild.add(i)\n"
        "        elif 0x70 <= b0 <= 0x7F:\n"
        "            for i in range(1, insn.size):\n"
        "                wild.add(i)\n"
        "        insts.append({'ea': hex(cursor), 'size': insn.size, 'bytes': raw.hex(), 'wild': sorted(wild)})\n"
        "        cursor += insn.size\n"
        "        total += insn.size\n"
        "        if total >= max_sig_bytes:\n"
        "            break\n"
        "    result = json.dumps({'func_va': hex(f.start_ea), 'func_size': hex(f.end_ea - f.start_ea), 'insts': insts})\n"
    )

    try:
        fi_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        fi_data = parse_mcp_result(fi_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: py_eval error while generating func_sig: {e}")
        return None

    func_info = None
    if isinstance(fi_data, dict):
        stderr_text = fi_data.get("stderr", "")
        if stderr_text and debug:
            print("    Preprocess: py_eval stderr:")
            print(stderr_text.strip())
        result_str = fi_data.get("result", "")
        if result_str:
            try:
                func_info = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not isinstance(func_info, dict):
        if debug:
            print(f"    Preprocess: could not resolve function head at {hex(func_va_int)}")
        return None

    insts = func_info.get("insts", [])
    if not isinstance(insts, list) or len(insts) == 0:
        if debug:
            print(f"    Preprocess: no instruction bytes available at {hex(func_va_int)}")
        return None

    sig_tokens = []
    inst_boundaries = []
    for inst in insts:
        try:
            inst_size = int(inst.get("size", 0))
            inst_hex = str(inst.get("bytes", ""))
            if inst_size <= 0 or len(inst_hex) != inst_size * 2:
                if debug:
                    print("    Preprocess: malformed instruction bytes from py_eval")
                return None

            inst_bytes = [int(inst_hex[i:i + 2], 16) for i in range(0, len(inst_hex), 2)]
            inst_wild = set()
            for item in inst.get("wild", []):
                pos = int(item)
                if 0 <= pos < inst_size:
                    inst_wild.add(pos)
        except Exception:
            if debug:
                print("    Preprocess: failed to decode instruction bytes for func_sig")
            return None

        base_offset = len(sig_tokens)
        for rel_idx, value in enumerate(inst_bytes):
            abs_off = base_offset + rel_idx
            use_wild = (rel_idx in inst_wild) or (abs_off in extra_wildcard_set)
            sig_tokens.append("??" if use_wild else f"{value:02X}")

        # Growth step must align to the next full instruction boundary.
        inst_boundaries.append(len(sig_tokens))

    if len(sig_tokens) == 0 or len(inst_boundaries) == 0:
        if debug:
            print(f"    Preprocess: empty signature token stream at {hex(func_va_int)}")
        return None

    search_start = min_sig_bytes

    best_sig = None
    for prefix_len in inst_boundaries:
        if prefix_len < search_start:
            continue
        prefix_tokens = sig_tokens[:prefix_len]

        # Skip signatures that are all wildcards.
        if all(token == "??" for token in prefix_tokens):
            continue

        candidate_sig = " ".join(prefix_tokens)
        try:
            fb_result = await session.call_tool(
                name="find_bytes",
                arguments={"patterns": [candidate_sig], "limit": 2},
            )
            fb_data = parse_mcp_result(fb_result)
        except Exception as e:
            if debug:
                print(f"    Preprocess: find_bytes error while testing generated sig: {e}")
            return None

        if not isinstance(fb_data, list) or len(fb_data) == 0:
            continue

        entry = fb_data[0]
        matches = entry.get("matches", [])
        match_count = entry.get("n", len(matches))

        if match_count != 1 or not matches:
            continue

        try:
            match_addr = _parse_addr(matches[0])
        except Exception:
            continue

        # Signature must resolve to the target function head, not middle/function body.
        if match_addr != func_va_int:
            continue

        best_sig = candidate_sig
        break

    if not best_sig:
        if debug:
            print(
                "    Preprocess: failed to generate a unique function-head signature "
                f"for {hex(func_va_int)}"
            )
        return None

    try:
        resolved_func_va = str(func_info["func_va"])
        resolved_func_va_int = int(resolved_func_va, 16)
        resolved_func_size = str(func_info["func_size"])
    except Exception:
        if debug:
            print("    Preprocess: invalid func info returned from py_eval")
        return None

    if resolved_func_va_int != func_va_int:
        if debug:
            print(
                "    Preprocess: function head mismatch while generating func_sig "
                f"({hex(resolved_func_va_int)} != {hex(func_va_int)})"
            )
        return None

    if debug:
        print(
            "    Preprocess: generated shortest unique func_sig "
            f"({len(best_sig.split())} bytes) for {hex(func_va_int)}"
        )

    return {
        "func_va": resolved_func_va,
        "func_rva": hex(resolved_func_va_int - image_base),
        "func_size": resolved_func_size,
        "func_sig": best_sig,
    }

async def preprocess_gen_gv_sig_via_mcp(
    session,
    gv_va,
    image_base,
    gv_access_inst_va=None,
    gv_access_func_va=None,
    min_sig_bytes=8,
    max_sig_bytes=96,
    max_instructions=64,
    max_candidates=32,
    extra_wildcard_offsets=None,
    debug=False,
):
    """
    Generate a shortest unique signature for a known global variable address.

    The generated signature MUST resolve to an instruction that accesses the global
    variable (GV-accessing instruction). The signature start address equals that
    instruction address (gv_inst_offset = 0).

    Args:
        session: Active MCP ClientSession.
        gv_va: Global variable virtual address (int or hex string).
        image_base: Binary image base address (int).
        gv_access_inst_va: Optional instruction address known to access gv_va.
        gv_access_func_va: Optional function address to constrain candidate search.
        min_sig_bytes: Minimum signature prefix length to try.
        max_sig_bytes: Maximum bytes collected from signature start.
        max_instructions: Max instructions collected from signature start.
        max_candidates: Maximum GV-access instruction candidates to evaluate.
        extra_wildcard_offsets: Optional iterable of extra wildcard offsets relative
            to signature start.
        debug: Enable debug output.

    Returns:
        Dict with global-variable YAML data, or None on failure.
    """

    def _parse_int(value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                raise ValueError("empty integer string")
            return int(raw, 0)
        return int(value)

    def _parse_addr(value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return int(value.strip(), 0)
        return int(value)

    try:
        gv_va_int = _parse_int(gv_va)
    except Exception:
        if debug:
            print(f"    Preprocess: invalid gv_va: {gv_va}")
        return None

    try:
        min_sig_bytes = max(1, int(min_sig_bytes))
        max_sig_bytes = max(1, int(max_sig_bytes))
        max_instructions = max(1, int(max_instructions))
        max_candidates = max(1, int(max_candidates))
    except Exception:
        if debug:
            print("    Preprocess: invalid gv signature generation limits")
        return None

    inst_va_int = None
    if gv_access_inst_va is not None:
        try:
            inst_va_int = _parse_int(gv_access_inst_va)
        except Exception:
            if debug:
                print(f"    Preprocess: invalid gv_access_inst_va: {gv_access_inst_va}")
            return None

    func_va_int = None
    if gv_access_func_va is not None:
        try:
            func_va_int = _parse_int(gv_access_func_va)
        except Exception:
            if debug:
                print(f"    Preprocess: invalid gv_access_func_va: {gv_access_func_va}")
            return None

    extra_wildcard_set = set()
    if extra_wildcard_offsets:
        try:
            for offset in extra_wildcard_offsets:
                parsed = _parse_int(offset)
                if parsed >= 0:
                    extra_wildcard_set.add(parsed)
        except Exception:
            if debug:
                print("    Preprocess: invalid extra_wildcard_offsets")
            return None

    py_code = (
        "import idaapi, ida_bytes, idautils, ida_ua, json\n"
        f"target_gv = {gv_va_int}\n"
        f"target_inst = {inst_va_int if inst_va_int is not None else 'None'}\n"
        f"target_func = {func_va_int if func_va_int is not None else 'None'}\n"
        f"max_sig_bytes = {max_sig_bytes}\n"
        f"max_instructions = {max_instructions}\n"
        f"max_candidates = {max_candidates}\n"
        "\n"
        "def _resolve_disp_off(insn_ea, insn, raw):\n"
        "    cand_offsets = set()\n"
        "    for op in insn.ops:\n"
        "        op_type = int(op.type)\n"
        "        if op_type == int(idaapi.o_void):\n"
        "            continue\n"
        "        offb = int(getattr(op, 'offb', 0))\n"
        "        offo = int(getattr(op, 'offo', 0))\n"
        "        if offb > 0 and offb + 4 <= insn.size:\n"
        "            cand_offsets.add(offb)\n"
        "        if offo > 0 and offo + 4 <= insn.size:\n"
        "            cand_offsets.add(offo)\n"
        "\n"
        "    for off in sorted(cand_offsets):\n"
        "        disp_i32 = int.from_bytes(raw[off:off + 4], 'little', signed=True)\n"
        "        resolved = (insn_ea + insn.size + disp_i32) & 0xFFFFFFFFFFFFFFFF\n"
        "        if resolved == target_gv:\n"
        "            return off\n"
        "\n"
        "    return None\n"
        "\n"
        "def _collect_sig_stream(inst_ea, disp_off):\n"
        "    f = idaapi.get_func(inst_ea)\n"
        "    if not f:\n"
        "        return None\n"
        "\n"
        "    limit_end = min(f.end_ea, inst_ea + max_sig_bytes)\n"
        "    cursor = inst_ea\n"
        "    total = 0\n"
        "    insts = []\n"
        "    first_len = None\n"
        "\n"
        "    while cursor < f.end_ea and cursor < limit_end and len(insts) < max_instructions:\n"
        "        insn = idautils.DecodeInstruction(cursor)\n"
        "        if not insn or insn.size <= 0:\n"
        "            break\n"
        "\n"
        "        raw = ida_bytes.get_bytes(cursor, insn.size)\n"
        "        if not raw:\n"
        "            break\n"
        "\n"
        "        wild = set()\n"
        "        for op in insn.ops:\n"
        "            op_type = int(op.type)\n"
        "            if op_type == int(idaapi.o_void):\n"
        "                continue\n"
        "\n"
        "            if op_type in (int(idaapi.o_imm), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_mem), int(idaapi.o_displ)):\n"
        "                offb = int(getattr(op, 'offb', 0))\n"
        "                if offb > 0 and offb < insn.size:\n"
        "                    dsz = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))\n"
        "                    if dsz <= 0:\n"
        "                        dsz = insn.size - offb\n"
        "                    end = min(insn.size, offb + dsz)\n"
        "                    for i in range(offb, end):\n"
        "                        wild.add(i)\n"
        "\n"
        "                offo = int(getattr(op, 'offo', 0))\n"
        "                if offo > 0 and offo < insn.size:\n"
        "                    dsz2 = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))\n"
        "                    if dsz2 <= 0:\n"
        "                        dsz2 = insn.size - offo\n"
        "                    end2 = min(insn.size, offo + dsz2)\n"
        "                    for i in range(offo, end2):\n"
        "                        wild.add(i)\n"
        "\n"
        "        b0 = raw[0]\n"
        "        if b0 in (0xE8, 0xE9, 0xEB):\n"
        "            for i in range(1, insn.size):\n"
        "                wild.add(i)\n"
        "        elif b0 == 0x0F and insn.size >= 2 and (raw[1] & 0xF0) == 0x80:\n"
        "            for i in range(2, insn.size):\n"
        "                wild.add(i)\n"
        "        elif 0x70 <= b0 <= 0x7F:\n"
        "            for i in range(1, insn.size):\n"
        "                wild.add(i)\n"
        "\n"
        "        if cursor == inst_ea:\n"
        "            first_len = insn.size\n"
        "            for i in range(disp_off, min(insn.size, disp_off + 4)):\n"
        "                wild.add(i)\n"
        "\n"
        "        insts.append({'ea': hex(cursor), 'size': insn.size, 'bytes': raw.hex(), 'wild': sorted(wild)})\n"
        "\n"
        "        cursor += insn.size\n"
        "        total += insn.size\n"
        "        if total >= max_sig_bytes:\n"
        "            break\n"
        "\n"
        "    if not insts or first_len is None:\n"
        "        return None\n"
        "\n"
        "    return {\n"
        "        'gv_inst_va': hex(inst_ea),\n"
        "        'gv_inst_length': first_len,\n"
        "        'gv_inst_disp': disp_off,\n"
        "        'insts': insts,\n"
        "    }\n"
        "\n"
        "candidates = []\n"
        "seen = set()\n"
        "\n"
        "def _try_add(inst_ea):\n"
        "    if inst_ea in seen:\n"
        "        return\n"
        "    seen.add(inst_ea)\n"
        "\n"
        "    insn = idautils.DecodeInstruction(inst_ea)\n"
        "    if not insn or insn.size <= 0:\n"
        "        return\n"
        "\n"
        "    raw = ida_bytes.get_bytes(inst_ea, insn.size)\n"
        "    if not raw:\n"
        "        return\n"
        "\n"
        "    disp_off = _resolve_disp_off(inst_ea, insn, raw)\n"
        "    if disp_off is None:\n"
        "        return\n"
        "\n"
        "    packed = _collect_sig_stream(inst_ea, disp_off)\n"
        "    if packed is None:\n"
        "        return\n"
        "\n"
        "    candidates.append(packed)\n"
        "\n"
        "if target_inst is not None:\n"
        "    _try_add(target_inst)\n"
        "elif target_func is not None:\n"
        "    f = idaapi.get_func(target_func)\n"
        "    if f:\n"
        "        ea = f.start_ea\n"
        "        while ea < f.end_ea and len(candidates) < max_candidates:\n"
        "            flags = ida_bytes.get_full_flags(ea)\n"
        "            if ida_bytes.is_code(flags):\n"
        "                _try_add(ea)\n"
        "\n"
        "            next_ea = ida_bytes.next_head(ea, f.end_ea)\n"
        "            if next_ea == idaapi.BADADDR or next_ea <= ea:\n"
        "                break\n"
        "            ea = next_ea\n"
        "else:\n"
        "    for ref in idautils.DataRefsTo(target_gv):\n"
        "        if len(candidates) >= max_candidates:\n"
        "            break\n"
        "\n"
        "        flags = ida_bytes.get_full_flags(ref)\n"
        "        if not ida_bytes.is_code(flags):\n"
        "            continue\n"
        "\n"
        "        _try_add(ref)\n"
        "\n"
        "result = json.dumps(candidates)\n"
    )

    try:
        gv_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        gv_data = parse_mcp_result(gv_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: py_eval error while generating gv_sig: {e}")
        return None

    candidate_infos = None
    if isinstance(gv_data, dict):
        stderr_text = gv_data.get("stderr", "")
        if stderr_text and debug:
            print("    Preprocess: py_eval stderr:")
            print(stderr_text.strip())

        result_str = gv_data.get("result", "")
        if result_str:
            try:
                candidate_infos = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not isinstance(candidate_infos, list) or len(candidate_infos) == 0:
        if debug:
            print(f"    Preprocess: no gv-access instruction candidates for {hex(gv_va_int)}")
        return None

    best = None

    for cand in candidate_infos:
        try:
            gv_inst_va = _parse_addr(cand.get("gv_inst_va"))
            gv_inst_length = int(cand.get("gv_inst_length"))
            gv_inst_disp = int(cand.get("gv_inst_disp"))
            insts = cand.get("insts", [])
        except Exception:
            continue

        if not isinstance(insts, list) or len(insts) == 0 or gv_inst_length <= 0 or gv_inst_disp < 0:
            continue

        sig_tokens = []
        inst_boundaries = []
        malformed = False
        for inst in insts:
            try:
                inst_size = int(inst.get("size", 0))
                inst_hex = str(inst.get("bytes", ""))
                if inst_size <= 0 or len(inst_hex) != inst_size * 2:
                    malformed = True
                    break

                inst_bytes = [int(inst_hex[i:i + 2], 16) for i in range(0, len(inst_hex), 2)]
                inst_wild = set()
                for item in inst.get("wild", []):
                    pos = int(item)
                    if 0 <= pos < inst_size:
                        inst_wild.add(pos)
            except Exception:
                malformed = True
                break

            base_offset = len(sig_tokens)
            for rel_idx, value in enumerate(inst_bytes):
                abs_off = base_offset + rel_idx
                use_wild = (rel_idx in inst_wild) or (abs_off in extra_wildcard_set)
                sig_tokens.append("??" if use_wild else f"{value:02X}")

            # Growth step must align to the next full instruction boundary.
            inst_boundaries.append(len(sig_tokens))

        if malformed or len(sig_tokens) == 0 or len(inst_boundaries) == 0:
            continue

        search_start = min_sig_bytes

        for prefix_len in inst_boundaries:
            if prefix_len < search_start:
                continue
            prefix_tokens = sig_tokens[:prefix_len]

            if all(token == "??" for token in prefix_tokens):
                continue

            candidate_sig = " ".join(prefix_tokens)
            try:
                fb_result = await session.call_tool(
                    name="find_bytes",
                    arguments={"patterns": [candidate_sig], "limit": 2},
                )
                fb_data = parse_mcp_result(fb_result)
            except Exception as e:
                if debug:
                    print(f"    Preprocess: find_bytes error while testing generated gv_sig: {e}")
                return None

            if not isinstance(fb_data, list) or len(fb_data) == 0:
                continue

            entry = fb_data[0]
            matches = entry.get("matches", [])
            match_count = entry.get("n", len(matches))

            if match_count != 1 or not matches:
                continue

            try:
                match_addr = _parse_addr(matches[0])
            except Exception:
                continue

            # Signature must resolve to this GV-accessing instruction address.
            if match_addr != gv_inst_va:
                continue

            if best is None or prefix_len < best["sig_len"]:
                best = {
                    "sig": candidate_sig,
                    "sig_len": prefix_len,
                    "gv_sig_va": gv_inst_va,
                    "gv_inst_length": gv_inst_length,
                    "gv_inst_disp": gv_inst_disp,
                }
            break

    if best is None:
        if debug:
            print(
                "    Preprocess: failed to generate a unique gv-access signature "
                f"for {hex(gv_va_int)}"
            )
        return None

    if debug:
        print(
            "    Preprocess: generated shortest unique gv_sig "
            f"({best['sig_len']} bytes) for {hex(gv_va_int)} at {hex(best['gv_sig_va'])}"
        )

    return {
        "gv_va": hex(gv_va_int),
        "gv_rva": hex(gv_va_int - image_base),
        "gv_sig": best["sig"],
        "gv_sig_va": hex(best["gv_sig_va"]),
        "gv_inst_offset": 0,
        "gv_inst_length": best["gv_inst_length"],
        "gv_inst_disp": best["gv_inst_disp"],
    }

async def preprocess_gv_sig_via_mcp(
    session, new_path, old_path, image_base, new_binary_dir, platform, debug=False
):
    """
    Preprocess a global-variable output by reusing old-version gv_sig signature.

    Searches the old signature in the new binary via find_bytes.
    For unique matches, resolves gv_va from RIP-relative instruction metadata
    (gv_inst_offset, gv_inst_length, gv_inst_disp) and builds new YAML data.

    Args:
        session: Active MCP ClientSession
        new_path: Full path to expected output YAML
        old_path: Full path to old version YAML (may be None)
        image_base: Binary image base address (int)
        new_binary_dir: Directory for new version outputs (reserved)
        platform: "windows" or "linux" (reserved)
        debug: Enable debug output

    Returns:
        Dict with global-variable YAML data, or None on failure
    """
    _ = new_binary_dir, platform  # Reserved for future platform-specific behavior.

    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required for gv_sig preprocessing")
        return None

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

    gv_sig = old_data.get("gv_sig")
    if not gv_sig:
        if debug:
            print(f"    Preprocess: no gv_sig in {os.path.basename(old_path)}")
        return None

    def _parse_int_field(value, field_name):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                raise ValueError(f"empty {field_name}")
            return int(raw, 0)
        return int(value)

    try:
        gv_inst_offset = _parse_int_field(old_data.get("gv_inst_offset"), "gv_inst_offset")
        gv_inst_length = _parse_int_field(old_data.get("gv_inst_length"), "gv_inst_length")
        gv_inst_disp = _parse_int_field(old_data.get("gv_inst_disp"), "gv_inst_disp")
    except Exception:
        if debug:
            print(f"    Preprocess: invalid gv instruction metadata in {os.path.basename(old_path)}")
        return None

    if gv_inst_offset < 0 or gv_inst_length <= 0 or gv_inst_disp < 0:
        if debug:
            print(f"    Preprocess: invalid gv instruction values in {os.path.basename(old_path)}")
        return None

    # Search signature in new binary via MCP find_bytes
    try:
        fb_result = await session.call_tool(
            name="find_bytes",
            arguments={"patterns": [gv_sig], "limit": 2}
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
            print(f"    Preprocess: {os.path.basename(old_path)} gv sig matched {match_count} (need 1)")
        return None

    match_addr = matches[0]  # hex string like "0x1804f3df3"

    # Resolve gv_va from instruction metadata via py_eval
    py_code = (
        f"import ida_bytes, json\n"
        f"sig_addr = {match_addr}\n"
        f"inst_addr = sig_addr + {gv_inst_offset}\n"
        f"inst_length = {gv_inst_length}\n"
        f"inst_disp = {gv_inst_disp}\n"
        f"inst_bytes = ida_bytes.get_bytes(inst_addr, inst_length)\n"
        f"if not inst_bytes or len(inst_bytes) < inst_disp + 4:\n"
        f"    result = json.dumps(None)\n"
        f"else:\n"
        f"    disp_bytes = inst_bytes[inst_disp:inst_disp + 4]\n"
        f"    disp_i32 = int.from_bytes(disp_bytes, 'little', signed=True)\n"
        f"    gv_addr = (inst_addr + inst_length + disp_i32) & 0xFFFFFFFFFFFFFFFF\n"
        f"    result = json.dumps({{'gv_va': hex(gv_addr), 'gv_sig_va': hex(sig_addr)}})\n"
    )

    try:
        gv_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code}
        )
        gv_data = parse_mcp_result(gv_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: py_eval error: {e}")
        return None

    # Parse py_eval result
    gv_info = None
    if isinstance(gv_data, dict):
        stderr_text = gv_data.get("stderr", "")
        if stderr_text and debug:
            print("    Preprocess: py_eval stderr:")
            print(stderr_text.strip())
        result_str = gv_data.get("result", "")
        if result_str:
            try:
                gv_info = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not gv_info:
        if debug:
            print(f"    Preprocess: could not resolve global variable at {match_addr}")
        return None

    try:
        gv_va_hex = str(gv_info["gv_va"])
        gv_va_int = int(gv_va_hex, 16)
    except Exception:
        if debug:
            print(f"    Preprocess: invalid gv_va parsed from {match_addr}")
        return None

    gv_sig_va_hex = str(gv_info.get("gv_sig_va", match_addr))

    return {
        "gv_va": gv_va_hex,
        "gv_rva": hex(gv_va_int - image_base),
        "gv_sig": gv_sig,
        "gv_sig_va": gv_sig_va_hex,
        "gv_inst_offset": gv_inst_offset,
        "gv_inst_length": gv_inst_length,
        "gv_inst_disp": gv_inst_disp,
    }
