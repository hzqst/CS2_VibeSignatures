#!/usr/bin/env python3
"""
IDA Binary Analysis Script for CS2_VibeSignatures

Analyzes CS2 binary files using IDA Pro MCP and Claude/Codex agents.
Sequentially processes modules and symbols defined in config.yaml.

Usage:
    python ida_analyze_bin.py -gamever=14134 [-platform=windows,linux] [-agent=codex]

    -gamever: Game version subdirectory name (required)
    -oldgamever: Old game version for signature reuse (default: gamever - 1)
    -configyaml: Path to config.yaml file (default: config.yaml)
    -bindir: Directory containing downloaded binaries (default: bin)
    -platform: Platforms to analyze, comma-separated (default: windows,linux)
    -agent: Agent to use for analysis: codex or claude (default: codex)
    -ida_args: Additional arguments for idalib-mcp (optional)
    -debug: Enable debug output

Requirements:
    pip install pyyaml
    uv (for running idalib-mcp)
    claude CLI or codex CLI

Output:
    bin/14134/engine/CServerSideClient_IsHearingClient.linux.yaml
    bin/14134/engine/CServerSideClient_IsHearingClient.windows.yaml
    ...and more
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

try:
    import yaml
    import asyncio
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
except ImportError as e:
    print(f"Error: Missing required dependency: {e.name}")
    print("Please install required packages: pip install pyyaml mcp")
    sys.exit(1)
    
DEFAULT_CONFIG_FILE = "config.yaml"
DEFAULT_BIN_DIR = "bin"
DEFAULT_PLATFORM = "windows,linux"
DEFAULT_MODULES = "*"
DEFAULT_AGENT = "claude"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337
MCP_STARTUP_TIMEOUT = 120  # seconds to wait for MCP server
SKILL_TIMEOUT = 600  # 10 minutes per skill

async def quit_ida_via_mcp(host=DEFAULT_HOST, port=DEFAULT_PORT):
    """
    Gracefully quit IDA using MCP py_eval tool with idc.qexit(0).

    Args:
        host: MCP server host
        port: MCP server port
    Returns:
        True if successful, False otherwise
    """
    server_url = f"http://{host}:{port}/mcp"

    try:
        async with streamable_http_client(server_url) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                await session.call_tool(name="py_eval", arguments={"code": "import idc; idc.qexit(0)"})
                return True
    except Exception:
        return False


def quit_ida_gracefully(process, host=DEFAULT_HOST, port=DEFAULT_PORT, debug=False):
    """
    Attempt to quit IDA gracefully via MCP, fall back to terminate if needed.

    Args:
        process: subprocess.Popen object
        host: MCP server host
        port: MCP server port
    """
    if process.poll() is not None:
        return  # Process already exited

    if debug:
        print("  Quitting IDA gracefully via MCP...")

    # Try graceful quit via MCP (fast timeout so we don't hang on a dead server)
    try:
        asyncio.run(asyncio.wait_for(quit_ida_via_mcp(host, port), timeout=5))
    except Exception:
        pass

    # Wait briefly for the process to exit on its own after the quit request.
    try:
        process.wait(timeout=10)
        if debug:
            print("  IDA exited gracefully")
        return
    except subprocess.TimeoutExpired:
        if debug:
            print("  Warning: IDA did not exit after qexit, forcing kill...")

    # Last resort: force kill (avoid terminate to reduce chances of breaking IDB)
    if process.poll() is None:
        try:
            process.kill()
            process.wait(timeout=5)
        except Exception:
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


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze CS2 binary files using IDA Pro MCP and Claude/Codex agents"
    )
    parser.add_argument(
        "-configyaml",
        default=DEFAULT_CONFIG_FILE,
        help=f"Path to config.yaml file (default: {DEFAULT_CONFIG_FILE})"
    )
    parser.add_argument(
        "-bindir",
        default=DEFAULT_BIN_DIR,
        help=f"Directory containing downloaded binaries (default: {DEFAULT_BIN_DIR})"
    )
    parser.add_argument(
        "-gamever",
        required=True,
        help="Game version subdirectory name (required)"
    )
    parser.add_argument(
        "-platform",
        default=DEFAULT_PLATFORM,
        help=f"Platforms to analyze, comma-separated (default: {DEFAULT_PLATFORM})"
    )
    parser.add_argument(
        "-agent",
        default=DEFAULT_AGENT,
        help=f"Agent executable to use for analysis, e.g., claude, claude.cmd, codex, codex.cmd (default: {DEFAULT_AGENT})"
    )
    parser.add_argument(
        "-modules",
        default=DEFAULT_MODULES,
        help=f"Modules to analyze, comma-separated (default: {DEFAULT_MODULES} for all). E.g., server,engine"
    )
    parser.add_argument(
        "-ida_args",
        default="",
        help="Additional arguments for idalib-mcp (optional)"
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="Enable debug output"
    )
    parser.add_argument(
        "-maxretry",
        type=int,
        default=3,
        help="Maximum number of retry attempts for skill execution (default: 3)"
    )
    parser.add_argument(
        "-oldgamever",
        default=None,
        help="Old game version for signature reuse (default: gamever - 1). Set to 'none' to disable."
    )

    args = parser.parse_args()

    # Parse platforms
    args.platforms = [p.strip() for p in args.platform.split(",") if p.strip()]
    valid_platforms = {"windows", "linux"}
    for p in args.platforms:
        if p not in valid_platforms:
            parser.error(f"Invalid platform: {p}. Must be one of: {', '.join(valid_platforms)}")

    # Parse modules filter
    if args.modules == "*":
        args.module_filter = None  # None means all modules
    else:
        args.module_filter = [m.strip() for m in args.modules.split(",") if m.strip()]

    # Resolve oldgamever
    if args.oldgamever is None:
        try:
            args.oldgamever = str(int(args.gamever) - 1)
        except ValueError:
            args.oldgamever = None
    elif args.oldgamever.lower() == "none":
        args.oldgamever = None

    return args


def parse_config(config_path):
    """
    Parse config.yaml and extract module information.

    Args:
        config_path: Path to config.yaml file

    Returns:
        List of module dictionaries containing name, paths, and skills
    """
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    modules = []
    for module in config.get("modules", []):
        name = module.get("name")
        if not name:
            print("  Warning: Skipping module without name")
            continue

        skills = []
        for skill in module.get("skills", []):
            skill_name = skill.get("name")
            if skill_name:
                skills.append({
                    "name": skill_name,
                    "expected_output": skill.get("expected_output", []),
                    "expected_input": skill.get("expected_input", []),
                    "prerequisite": skill.get("prerequisite", []) or [],
                    "max_retries": skill.get("max_retries"),  # None means use default
                })

        modules.append({
            "name": name,
            "path_windows": module.get("path_windows"),
            "path_linux": module.get("path_linux"),
            "skills": skills
        })

    return modules


def topological_sort_skills(skills):
    """
    Perform topological sort on skills based on their prerequisites.

    Args:
        skills: List of skill dicts with 'name' and 'prerequisite' keys

    Returns:
        List of skill names in topologically sorted order (dependencies first)
    """
    # Build name -> skill dict and adjacency list
    skill_map = {skill["name"]: skill for skill in skills}
    skill_names = set(skill_map.keys())

    # Build in-degree count and adjacency list
    in_degree = {name: 0 for name in skill_names}
    dependents = {name: [] for name in skill_names}  # prereq -> list of skills that depend on it

    for skill in skills:
        name = skill["name"]
        for prereq in skill["prerequisite"]:
            if prereq in skill_names:
                in_degree[name] += 1
                dependents[prereq].append(name)

    # Kahn's algorithm for topological sort
    # Start with skills that have no prerequisites (in_degree == 0)
    queue = [name for name in skill_names if in_degree[name] == 0]
    # Sort to ensure deterministic order for skills at the same level
    queue.sort()

    sorted_names = []
    while queue:
        # Pop the first item (maintains stable order)
        current = queue.pop(0)
        sorted_names.append(current)

        # Reduce in-degree for dependents
        for dependent in sorted(dependents[current]):
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                queue.append(dependent)
        queue.sort()

    # Check for cycles
    if len(sorted_names) != len(skill_names):
        remaining = skill_names - set(sorted_names)
        print(f"  Warning: Circular dependency detected among skills: {remaining}")
        # Append remaining skills in original order as fallback
        for skill in skills:
            if skill["name"] not in sorted_names:
                sorted_names.append(skill["name"])

    return sorted_names


def get_binary_path(bin_dir, gamever, module_name, module_path):
    """
    Build binary file path.

    Args:
        bin_dir: Base binary directory
        gamever: Game version subdirectory
        module_name: Module name (e.g., "engine")
        module_path: Module path from config (e.g., "game/bin/win64/engine2.dll")

    Returns:
        Full path to binary file: {bin_dir}/{gamever}/{module_name}/{filename}
    """
    filename = Path(module_path).name
    return os.path.join(bin_dir, gamever, module_name, filename)


def wait_for_port(host, port, timeout=60):
    """
    Wait for a port to become available.

    Args:
        host: Host address
        port: Port number
        timeout: Maximum time to wait in seconds

    Returns:
        True if port is available, False if timeout
    """
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except socket.error:
            pass
        time.sleep(2)
    return False


def start_idalib_mcp(binary_path, host=DEFAULT_HOST, port=DEFAULT_PORT, ida_args="", debug=False):
    """
    Start idalib-mcp as a background process.

    Args:
        binary_path: Path to binary file to analyze
        host: MCP server host
        port: MCP server port
        ida_args: Additional arguments for idalib-mcp
        debug: Enable debug output

    Returns:
        subprocess.Popen object if successful, None if failed
    """
    cmd = ["uv", "run", "idalib-mcp", "--host", host, "--port", str(port)]

    if ida_args:
        cmd.extend(ida_args.split())

    cmd.append(binary_path)

    print(f"  Starting idalib-mcp: {' '.join(cmd)}")

    try:
        if debug:
            process = subprocess.Popen(cmd)
        else:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

        # Wait for MCP server to be ready
        print(f"  Waiting for MCP server on {host}:{port}...")
        if not wait_for_port(host, port, timeout=MCP_STARTUP_TIMEOUT):
            print(f"  Error: MCP server failed to start within {MCP_STARTUP_TIMEOUT} seconds")
            process.kill()
            return None

        print(f"  MCP server is ready")
        return process

    except Exception as e:
        print(f"  Error starting idalib-mcp: {e}")
        return None


def run_skill(skill_name, agent="claude", debug=False, expected_yaml_paths=None, max_retries=3):
    """
    Execute a skill using the specified agent with retry support.

    Args:
        skill_name: Name of the skill (e.g., "find-CServerSideClient_IsHearingClient")
        agent: Agent type ("claude" or "codex")
        debug: Enable debug output
        expected_yaml_paths: List of paths to expected yaml output files. If provided,
                            the skill is considered failed if any file is not generated.
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        True if successful, False otherwise
    """
    session_id = str(uuid.uuid4())

    for attempt in range(max_retries):
        is_retry = attempt > 0

        # Determine agent type based on executable name
        is_claude_agent = "claude" in agent.lower()
        is_codex_agent = "codex" in agent.lower()

        if is_claude_agent:
            cmd = [agent,
                   "-p", f"/{skill_name}",
                   "--agent", "sig-finder",
                   "--allowedTools", "mcp__ida-pro-mcp__*"
                   ]
            # Add session management flags
            if is_retry:
                cmd.extend(["--resume", session_id])
            else:
                cmd.extend(["--session-id", session_id])
        elif is_codex_agent:
            skill_path = f".claude/skills/{skill_name}/SKILL.md"
            cmd = [agent, "exec", f"Run SKILL: {skill_path}"]
        else:
            print(f"    Error: Unknown agent type '{agent}'. Agent name must contain 'claude' or 'codex'.")
            return False

        attempt_str = f"(attempt {attempt + 1}/{max_retries})" if max_retries > 1 else ""
        retry_str = "[RETRY] " if is_retry else ""
        print(f"    {retry_str}Running {attempt_str}: {' '.join(cmd)}")

        try:
            if debug:
                result = subprocess.run(cmd, timeout=SKILL_TIMEOUT)
            else:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=SKILL_TIMEOUT
                )

            if result.returncode != 0:
                print(f"    Skill failed with return code: {result.returncode}")
                if not debug and result.stderr:
                    print(f"    stderr: {result.stderr[:500]}")
                if attempt < max_retries - 1:
                    print(f"    Retrying with session {session_id}...")
                continue

            # Verify all yaml files were generated if expected_yaml_paths is provided
            if expected_yaml_paths is not None:
                missing_files = [p for p in expected_yaml_paths if not os.path.exists(p)]
                if missing_files:
                    print(f"    Error: Expected yaml files not generated: {missing_files}")
                    if attempt < max_retries - 1:
                        print(f"    Retrying with session {session_id}...")
                    continue

            return True

        except subprocess.TimeoutExpired:
            print(f"    Error: Skill execution timeout ({SKILL_TIMEOUT} seconds)")
            if attempt < max_retries - 1:
                print(f"    Retrying with session {session_id}...")
            continue
        except FileNotFoundError:
            print(f"    Error: Agent '{agent}' not found. Please ensure it is installed and in PATH.")
            return False
        except Exception as e:
            print(f"    Error executing skill: {e}")
            if attempt < max_retries - 1:
                print(f"    Retrying with session {session_id}...")
            continue

    print(f"    Failed after {max_retries} attempts")
    return False


def process_binary(binary_path, skills, agent, host, port, ida_args, platform, debug=False, max_retries=3, old_binary_dir=None):
    """
    Process a single binary file.

    Args:
        binary_path: Path to binary file
        skills: List of skill dicts with 'name', 'expected_output', 'expected_input', 'prerequisite', and optional 'max_retries' keys
        agent: Agent type ("claude" or "codex")
        host: MCP server host
        port: MCP server port
        ida_args: Additional arguments for idalib-mcp
        platform: Platform name (e.g., "windows", "linux")
        debug: Enable debug output
        max_retries: Default maximum number of retry attempts for skill execution
        old_binary_dir: Directory containing old version YAML files for signature reuse

    Returns:
        Tuple of (success_count, fail_count, skip_count)
    """
    success_count = 0
    fail_count = 0
    skip_count = 0

    # Get the directory containing the binary for yaml output check
    binary_dir = os.path.dirname(binary_path)

    # Build skill_map for lookup
    skill_map = {skill["name"]: skill for skill in skills}

    # Topological sort skills based on prerequisites
    sorted_skill_names = topological_sort_skills(skills)

    # Filter skills that need processing (skip if all expected outputs already exist)
    skills_to_process = []
    for skill_name in sorted_skill_names:
        skill = skill_map[skill_name]
        # Expand {platform} placeholder in expected_output paths
        expected_outputs = [
            os.path.join(binary_dir, f.replace("{platform}", platform))
            for f in skill["expected_output"]
        ]
        # Check if all output files already exist
        if expected_outputs and all(os.path.exists(p) for p in expected_outputs):
            print(f"  Skipping skill: {skill_name} (all outputs exist)")
            skip_count += 1
        else:
            # Use skill-specific max_retries if provided, otherwise use default
            skill_max_retries = skill.get("max_retries") or max_retries
            skills_to_process.append((skill_name, expected_outputs, skill_max_retries))

    # If all skills are skipped, no need to start IDA
    if not skills_to_process:
        print(f"  All skills already have yaml files, skipping IDA startup")
        return success_count, fail_count, skip_count

    # Start idalib-mcp
    process = start_idalib_mcp(binary_path, host, port, ida_args, debug)
    if process is None:
        return 0, len(skills_to_process), skip_count

    try:
        # Process each skill: try preprocess first, then run_skill if needed
        for skill_name, expected_outputs, skill_max_retries in skills_to_process:
            # Try preprocessing (signature reuse) if old binary dir is available
            if old_binary_dir:
                old_yaml_map = {}
                for new_path in expected_outputs:
                    filename = os.path.basename(new_path)
                    old_path = os.path.join(old_binary_dir, filename)
                    old_yaml_map[new_path] = old_path

                try:
                    preprocess_ok = asyncio.run(
                        preprocess_single_skill_via_mcp(
                            host, port, skill_name, expected_outputs, old_yaml_map,
                            binary_dir, platform, debug
                        )
                    )
                except Exception as e:
                    if debug:
                        print(f"  Pre-processing error for {skill_name}: {e}")
                    preprocess_ok = False

                if preprocess_ok:
                    success_count += 1
                    print(f"  Pre-processed: {skill_name} (signature reuse)")
                    continue

            print(f"  Processing skill: {skill_name}")

            if run_skill(skill_name, agent, debug, expected_yaml_paths=expected_outputs, max_retries=skill_max_retries):
                success_count += 1
                print(f"    Success")
            else:
                fail_count += 1
                print(f"    Failed")

    finally:
        # Gracefully quit IDA via MCP to avoid breaking IDB
        quit_ida_gracefully(process, host, port, debug=debug)

    return success_count, fail_count, skip_count


def main():
    """Main entry point."""
    args = parse_args()

    config_path = args.configyaml
    bin_dir = args.bindir
    gamever = args.gamever
    oldgamever = args.oldgamever
    platforms = args.platforms
    module_filter = args.module_filter
    agent = args.agent
    ida_args = args.ida_args
    debug = args.debug

    # Validate config file exists
    if not os.path.exists(config_path):
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)

    # Print configuration
    print(f"Config file: {config_path}")
    print(f"Binary directory: {bin_dir}")
    print(f"Game version: {gamever}")
    print(f"Old game version: {oldgamever or '(disabled)'}")
    print(f"Platforms: {', '.join(platforms)}")
    print(f"Modules filter: {args.modules}")
    print(f"Agent: {agent}")
    if ida_args:
        print(f"IDA args: {ida_args}")
    if debug:
        print("Debug mode: enabled")

    # Parse config
    print("\nParsing config...")
    modules = parse_config(config_path)
    print(f"Found {len(modules)} modules")

    if not modules:
        print("No modules found in config.")
        sys.exit(0)

    # Process each module
    total_success = 0
    total_fail = 0
    total_skip = 0

    for module in modules:
        module_name = module["name"]
        skills = module["skills"]

        # Filter modules if specified
        if module_filter is not None and module_name not in module_filter:
            print(f"\nModule '{module_name}': Not in filter list, skipping")
            continue

        if not skills:
            print(f"\nModule '{module_name}': No skills defined, skipping")
            continue

        print(f"\n{'='*60}")
        print(f"Module: {module_name}")
        print(f"Skills: {len(skills)}")
        print(f"{'='*60}")

        for platform in platforms:
            path_key = f"path_{platform}"
            module_path = module.get(path_key)

            if not module_path:
                print(f"\n  Platform {platform}: No path defined, skipping")
                total_skip += len(skills)
                continue

            # Build binary path
            binary_path = get_binary_path(bin_dir, gamever, module_name, module_path)

            print(f"\n  Platform: {platform}")
            print(f"  Binary: {binary_path}")

            # Check if binary exists
            if not os.path.exists(binary_path):
                print(f"  Error: Binary file not found: {binary_path}")
                print(f"  Hint: Run download_bin.py first to download binaries")
                total_skip += len(skills)
                continue

            # Compute old binary dir for signature reuse
            old_binary_dir = None
            if oldgamever:
                old_binary_path = get_binary_path(bin_dir, oldgamever, module_name, module_path)
                candidate_dir = os.path.dirname(old_binary_path)
                if os.path.isdir(candidate_dir):
                    old_binary_dir = candidate_dir
                elif debug:
                    print(f"  Old version directory not found: {candidate_dir}")

            # Process binary
            success, fail, skip = process_binary(
                binary_path, skills, agent,
                DEFAULT_HOST, DEFAULT_PORT, ida_args, platform, debug,
                max_retries=args.maxretry,
                old_binary_dir=old_binary_dir
            )
            total_success += success
            total_fail += fail
            total_skip += skip

    # Summary
    print(f"\n{'='*60}")
    print(f"Summary")
    print(f"{'='*60}")
    print(f"  Successful: {total_success}")
    print(f"  Failed: {total_fail}")
    print(f"  Skipped: {total_skip}")

    if total_fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
