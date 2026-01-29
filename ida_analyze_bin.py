#!/usr/bin/env python3
"""
IDA Binary Analysis Script for CS2_VibeSignatures

Analyzes CS2 binary files using IDA Pro MCP and Claude/Codex agents.
Sequentially processes modules and symbols defined in config.yaml.

Usage:
    python ida_analyze_bin.py -gamever=14132 [-platform=windows,linux] [-agent=codex]

    -gamever: Game version subdirectory name (required)
    -configyaml: Path to config.yaml file (default: config.yaml)
    -bindir: Directory containing downloaded binaries (default: bin)
    -platform: Platforms to analyze, comma-separated (default: windows,linux)
    -agent: Agent to use for analysis: codex or claude (default: codex)
    -ida: Additional arguments for idalib-mcp (optional)
    -debug: Enable debug output

Requirements:
    pip install pyyaml
    uv (for running idalib-mcp)
    claude CLI or codex CLI (codex.cmd on Windows)

Output:
    bin/14132/engine/CServerSideClient_IsHearingClient.linux.yaml
    bin/14132/engine/CServerSideClient_IsHearingClient.windows.yaml
    ...and more
"""

import argparse
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
    from mcp.client.streamable_http import streamablehttp_client
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

# Determine codex command based on OS
IS_WINDOWS = sys.platform.startswith("win")
CODEX_CMD = "codex.cmd" if IS_WINDOWS else "codex"


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
        async with streamablehttp_client(server_url) as (read_stream, write_stream, _):
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
        choices=["codex", "claude"],
        default=DEFAULT_AGENT,
        help=f"Agent to use for analysis (default: {DEFAULT_AGENT})"
    )
    parser.add_argument(
        "-modules",
        default=DEFAULT_MODULES,
        help=f"Modules to analyze, comma-separated (default: {DEFAULT_MODULES} for all). E.g., server,engine"
    )
    parser.add_argument(
        "-ida",
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

    return args


def parse_config(config_path):
    """
    Parse config.yaml and extract module information.

    Args:
        config_path: Path to config.yaml file

    Returns:
        List of module dictionaries containing name, paths, and symbols
    """
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    modules = []
    for module in config.get("modules", []):
        name = module.get("name")
        if not name:
            print("  Warning: Skipping module without name")
            continue

        symbols = []
        for sym in module.get("symbols", []):
            sym_name = sym.get("name")
            if sym_name:
                symbols.append({
                    "name": sym_name,
                    "prerequisite": sym.get("prerequsite", []) or []  # Note: config uses "prerequsite" (typo)
                })

        modules.append({
            "name": name,
            "path_windows": module.get("path_windows"),
            "path_linux": module.get("path_linux"),
            "symbols": symbols
        })

    return modules


def topological_sort_symbols(symbols):
    """
    Perform topological sort on symbols based on their prerequisites.

    Args:
        symbols: List of symbol dicts with 'name' and 'prerequisite' keys

    Returns:
        List of symbol names in topologically sorted order (dependencies first)
    """
    # Build name -> symbol dict and adjacency list
    symbol_map = {sym["name"]: sym for sym in symbols}
    symbol_names = set(symbol_map.keys())

    # Build in-degree count and adjacency list
    in_degree = {name: 0 for name in symbol_names}
    dependents = {name: [] for name in symbol_names}  # prereq -> list of symbols that depend on it

    for sym in symbols:
        name = sym["name"]
        for prereq in sym["prerequisite"]:
            if prereq in symbol_names:
                in_degree[name] += 1
                dependents[prereq].append(name)

    # Kahn's algorithm for topological sort
    # Start with symbols that have no prerequisites (in_degree == 0)
    queue = [name for name in symbol_names if in_degree[name] == 0]
    # Sort to ensure deterministic order for symbols at the same level
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
    if len(sorted_names) != len(symbol_names):
        remaining = symbol_names - set(sorted_names)
        print(f"  Warning: Circular dependency detected among symbols: {remaining}")
        # Append remaining symbols in original order as fallback
        for sym in symbols:
            if sym["name"] not in sorted_names:
                sorted_names.append(sym["name"])

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


def run_skill(skill_name, agent="claude", debug=False, expected_yaml_path=None, max_retries=3):
    """
    Execute a skill using the specified agent with retry support.

    Args:
        skill_name: Name of the skill (e.g., "find-CServerSideClient_IsHearingClient")
        agent: Agent type ("claude" or "codex")
        debug: Enable debug output
        expected_yaml_path: Path to the expected yaml output file. If provided,
                           the skill is considered failed if this file is not generated.
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        True if successful, False otherwise
    """
    session_id = str(uuid.uuid4())

    for attempt in range(max_retries):
        is_retry = attempt > 0

        if agent == "claude":
            cmd = ["claude",
                   "-p", f"/{skill_name}",
                   "--agent", "sig-finder",
                   "--allowedTools", "mcp__ida-pro-mcp__*"
                   ]
            # Add session management flags
            if is_retry:
                cmd.extend(["--resume", session_id])
            else:
                cmd.extend(["--session-id", session_id])
        elif agent == "codex":
            skill_path = f".claude/skills/{skill_name}/SKILL.md"
            cmd = [CODEX_CMD, "exec", f"Run SKILL: {skill_path}"]

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

            # Verify yaml file was generated if expected_yaml_path is provided
            if expected_yaml_path is not None:
                if not os.path.exists(expected_yaml_path):
                    print(f"    Error: Expected yaml file not generated at {expected_yaml_path}")
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


def process_binary(binary_path, symbols, agent, host, port, ida_args, platform, debug=False, max_retries=3):
    """
    Process a single binary file.

    Args:
        binary_path: Path to binary file
        symbols: List of symbol dicts with 'name' and 'prerequisite' keys
        agent: Agent type ("claude" or "codex")
        host: MCP server host
        port: MCP server port
        ida_args: Additional arguments for idalib-mcp
        platform: Platform name (e.g., "windows", "linux")
        debug: Enable debug output
        max_retries: Maximum number of retry attempts for skill execution

    Returns:
        Tuple of (success_count, fail_count, skip_count)
    """
    success_count = 0
    fail_count = 0
    skip_count = 0

    # Get the directory containing the binary for yaml output check
    binary_dir = os.path.dirname(binary_path)

    # Topological sort symbols based on prerequisites
    sorted_symbol_names = topological_sort_symbols(symbols)

    # Filter symbols that need processing (skip if yaml already exists)
    symbols_to_process = []
    for symbol_name in sorted_symbol_names:
        yaml_path = os.path.join(binary_dir, f"{symbol_name}.{platform}.yaml")
        if os.path.exists(yaml_path):
            print(f"  Skipping symbol: {symbol_name} (yaml already exists)")
            skip_count += 1
        else:
            symbols_to_process.append(symbol_name)

    # If all symbols are skipped, no need to start IDA
    if not symbols_to_process:
        print(f"  All symbols already have yaml files, skipping IDA startup")
        return success_count, fail_count, skip_count

    # Start idalib-mcp
    process = start_idalib_mcp(binary_path, host, port, ida_args, debug)
    if process is None:
        return 0, len(symbols_to_process), skip_count

    try:
        # Process each symbol
        for symbol in symbols_to_process:
            skill_name = f"find-{symbol}"
            yaml_path = os.path.join(binary_dir, f"{symbol}.{platform}.yaml")
            print(f"  Processing symbol: {symbol}")

            if run_skill(skill_name, agent, debug, expected_yaml_path=yaml_path, max_retries=max_retries):
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
    platforms = args.platforms
    module_filter = args.module_filter
    agent = args.agent
    ida_args = args.ida
    debug = args.debug

    # Validate config file exists
    if not os.path.exists(config_path):
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)

    # Print configuration
    print(f"Config file: {config_path}")
    print(f"Binary directory: {bin_dir}")
    print(f"Game version: {gamever}")
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
        symbols = module["symbols"]

        # Filter modules if specified
        if module_filter is not None and module_name not in module_filter:
            print(f"\nModule '{module_name}': Not in filter list, skipping")
            continue

        if not symbols:
            print(f"\nModule '{module_name}': No symbols defined, skipping")
            continue

        print(f"\n{'='*60}")
        print(f"Module: {module_name}")
        print(f"Symbols: {len(symbols)}")
        print(f"{'='*60}")

        for platform in platforms:
            path_key = f"path_{platform}"
            module_path = module.get(path_key)

            if not module_path:
                print(f"\n  Platform {platform}: No path defined, skipping")
                total_skip += len(symbols)
                continue

            # Build binary path
            binary_path = get_binary_path(bin_dir, gamever, module_name, module_path)

            print(f"\n  Platform: {platform}")
            print(f"  Binary: {binary_path}")

            # Check if binary exists
            if not os.path.exists(binary_path):
                print(f"  Error: Binary file not found: {binary_path}")
                print(f"  Hint: Run download_bin.py first to download binaries")
                total_skip += len(symbols)
                continue

            # Process binary
            success, fail, skip = process_binary(
                binary_path, symbols, agent,
                DEFAULT_HOST, DEFAULT_PORT, ida_args, platform, debug,
                max_retries=args.maxretry
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
