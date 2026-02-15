#!/usr/bin/env python3
"""
IDA Skill Postprocessor for CS2_VibeSignatures.

Validates generated YAML outputs via IDA MCP after skill execution,
and cleans up invalid outputs to keep bin directory signatures reliable.
"""

import asyncio
import json
import os

from ida_analyze_util import parse_mcp_result

try:
    import yaml
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
except ImportError:
    pass


MCP_CONNECT_MAX_RETRIES = 3
MCP_CONNECT_RETRY_DELAY = 3


async def validate_func_sig_in_yaml_via_mcp(session, yaml_path, debug=False):
    """
    Validate func_sig in a generated YAML by searching it in IDA via MCP.

    Validation rule:
      1) find_bytes(func_sig) must return exactly one match
      2) the match address must be a valid function start (function head)

    If YAML has no func_sig field, this check is treated as pass.

    Args:
        session: Active MCP ClientSession
        yaml_path: Path to generated yaml
        debug: Enable debug output

    Returns:
        True if validation passes (or no func_sig), False otherwise
    """
    if not os.path.exists(yaml_path):
        if debug:
            print(f"    Postprocess: YAML not found: {yaml_path}")
        return False

    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            yaml_data = yaml.safe_load(f)
    except Exception as e:
        if debug:
            print(f"    Postprocess: failed to read {yaml_path}: {e}")
        return False

    if not isinstance(yaml_data, dict):
        if debug:
            print(f"    Postprocess: invalid YAML structure (expect mapping): {yaml_path}")
        return False

    func_sig = yaml_data.get("func_sig")
    if not func_sig:
        return True

    try:
        fb_result = await session.call_tool(
            name="find_bytes",
            arguments={"patterns": [func_sig], "limit": 2}
        )
        fb_data = parse_mcp_result(fb_result)
    except Exception as e:
        if debug:
            print(f"    Postprocess: find_bytes error for {os.path.basename(yaml_path)}: {e}")
        return False

    if not isinstance(fb_data, list) or len(fb_data) == 0:
        if debug:
            print(f"    Postprocess: unexpected find_bytes result for {os.path.basename(yaml_path)}")
        return False

    entry = fb_data[0] if isinstance(fb_data[0], dict) else {}
    matches = entry.get("matches", []) if isinstance(entry, dict) else []
    match_count = entry.get("n", len(matches)) if isinstance(entry, dict) else 0

    if match_count != 1 or not matches:
        if debug:
            print(
                f"    Postprocess: {os.path.basename(yaml_path)} func_sig matched {match_count} (need 1)"
            )
        return False

    match_addr = matches[0]
    addr_expr = hex(match_addr) if isinstance(match_addr, int) else str(match_addr)

    py_code = (
        "import idaapi, json\n"
        f"addr = {addr_expr}\n"
        "f = idaapi.get_func(addr)\n"
        "result = json.dumps({'is_func_head': bool(f and f.start_ea == addr)})\n"
    )

    try:
        fi_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code}
        )
        fi_data = parse_mcp_result(fi_result)
    except Exception as e:
        if debug:
            print(f"    Postprocess: py_eval error for {os.path.basename(yaml_path)}: {e}")
        return False

    is_func_head = False
    if isinstance(fi_data, dict):
        result_str = fi_data.get("result", "")
        if result_str:
            try:
                check_result = json.loads(result_str)
                if isinstance(check_result, dict):
                    is_func_head = bool(check_result.get("is_func_head"))
            except (json.JSONDecodeError, TypeError):
                pass

    if not is_func_head:
        if debug:
            print(
                f"    Postprocess: {os.path.basename(yaml_path)} func_sig match is not a function head"
            )
        return False

    return True


async def postprocess_single_skill_via_mcp(host, port, skill_name, expected_outputs, debug=False):
    """
    Postprocess a single skill output via IDA MCP validations.

    Currently validates func_sig (if present) for each expected output YAML.
    Future validations can be added here as independent checks.

    Args:
        host: MCP server host
        port: MCP server port
        skill_name: skill name for logs
        expected_outputs: list of expected output YAML paths
        debug: enable debug output

    Returns:
        True if all outputs pass postprocess validation, False otherwise
    """
    server_url = f"http://{host}:{port}/mcp"

    for attempt in range(1, MCP_CONNECT_MAX_RETRIES + 1):
        try:
            async with streamable_http_client(server_url) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()

                    all_valid = True
                    for yaml_path in expected_outputs:
                        is_valid = await validate_func_sig_in_yaml_via_mcp(session, yaml_path, debug)
                        if not is_valid:
                            all_valid = False

                    if debug and all_valid:
                        print(f"    Postprocess: {skill_name} - all {len(expected_outputs)} outputs validated")

                    return all_valid
        except Exception as e:
            if debug:
                print(
                    f"    Postprocess MCP connection error for {skill_name} "
                    f"(attempt {attempt}/{MCP_CONNECT_MAX_RETRIES}): {e}"
                )
            if attempt < MCP_CONNECT_MAX_RETRIES:
                if debug:
                    print(
                        f"    Postprocess: retrying MCP connection for {skill_name} "
                        f"in {MCP_CONNECT_RETRY_DELAY}s..."
                    )
                await asyncio.sleep(MCP_CONNECT_RETRY_DELAY)

    return False


def remove_invalid_yaml_outputs(yaml_paths, debug=False):
    """
    Remove YAML outputs when postprocess validation fails.

    This keeps the bin directory free of invalid signatures.

    Args:
        yaml_paths: list of YAML paths to remove
        debug: enable debug output

    Returns:
        Number of files successfully removed
    """
    removed_count = 0
    for path in yaml_paths:
        if not os.path.exists(path):
            continue
        try:
            os.remove(path)
            removed_count += 1
            if debug:
                print(f"    Postprocess cleanup: removed {path}")
        except Exception as e:
            print(f"    Warning: failed to remove invalid yaml '{path}': {e}")
    return removed_count
