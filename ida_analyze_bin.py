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
"""

import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

try:
    import yaml
except ImportError as e:
    print(f"Error: Missing required dependency: {e.name}")
    print("Please install required packages: pip install pyyaml")
    sys.exit(1)


DEFAULT_CONFIG_FILE = "config.yaml"
DEFAULT_BIN_DIR = "bin"
DEFAULT_PLATFORM = "windows,linux"
DEFAULT_AGENT = "codex"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337
MCP_STARTUP_TIMEOUT = 120  # seconds to wait for MCP server
SKILL_TIMEOUT = 600  # 10 minutes per skill

# Determine codex command based on OS
IS_WINDOWS = sys.platform.startswith("win")
CODEX_CMD = "codex.cmd" if IS_WINDOWS else "codex"


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
        "-ida",
        default="",
        help="Additional arguments for idalib-mcp (optional)"
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="Enable debug output"
    )

    args = parser.parse_args()

    # Parse platforms
    args.platforms = [p.strip() for p in args.platform.split(",") if p.strip()]
    valid_platforms = {"windows", "linux"}
    for p in args.platforms:
        if p not in valid_platforms:
            parser.error(f"Invalid platform: {p}. Must be one of: {', '.join(valid_platforms)}")

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
                symbols.append(sym_name)

        modules.append({
            "name": name,
            "path_windows": module.get("path_windows"),
            "path_linux": module.get("path_linux"),
            "symbols": symbols
        })

    return modules


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


def run_skill(skill_name, agent="claude", debug=False):
    """
    Execute a skill using the specified agent.

    Args:
        agent: Agent type ("claude" or "codex")
        skill_name: Name of the skill (e.g., "find-CServerSideClient_IsHearingClient")
        debug: Enable debug output

    Returns:
        True if successful, False otherwise
    """
    if agent == "claude":
        cmd = ["claude", "-p", f"/{skill_name}", "--agent", "sig-finder"]
    elif agent == "codex": 
        skill_path = f".claude/skills/{skill_name}/SKILL.md"
        cmd = [CODEX_CMD, "exec", f"Run SKILL: {skill_path}"]

    print(f"    Running: {' '.join(cmd)}")

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
            return False

        return True

    except subprocess.TimeoutExpired:
        print(f"    Error: Skill execution timeout ({SKILL_TIMEOUT} seconds)")
        return False
    except FileNotFoundError:
        print(f"    Error: Agent '{agent}' not found. Please ensure it is installed and in PATH.")
        return False
    except Exception as e:
        print(f"    Error executing skill: {e}")
        return False


def process_binary(binary_path, symbols, agent, host, port, ida_args, debug=False):
    """
    Process a single binary file.

    Args:
        binary_path: Path to binary file
        symbols: List of symbol names to analyze
        agent: Agent type ("claude" or "codex")
        host: MCP server host
        port: MCP server port
        ida_args: Additional arguments for idalib-mcp
        debug: Enable debug output

    Returns:
        Tuple of (success_count, fail_count)
    """
    success_count = 0
    fail_count = 0

    # Start idalib-mcp
    process = start_idalib_mcp(binary_path, host, port, ida_args, debug)
    if process is None:
        return 0, len(symbols)

    try:
        # Process each symbol
        for symbol in symbols:
            skill_name = f"find-{symbol}"
            print(f"  Processing symbol: {symbol}")

            if run_skill(skill_name, agent, debug):
                success_count += 1
                print(f"    Success")
            else:
                fail_count += 1
                print(f"    Failed")

    finally:
        # Ensure process is terminated
        if process.poll() is None:
            print("  Terminating idalib-mcp process...")
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()

    return success_count, fail_count


def main():
    """Main entry point."""
    args = parse_args()

    config_path = args.configyaml
    bin_dir = args.bindir
    gamever = args.gamever
    platforms = args.platforms
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
            success, fail = process_binary(
                binary_path, symbols, agent,
                DEFAULT_HOST, DEFAULT_PORT, ida_args, debug
            )
            total_success += success
            total_fail += fail

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
