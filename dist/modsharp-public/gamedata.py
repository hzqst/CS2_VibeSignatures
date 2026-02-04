#!/usr/bin/env python3
"""
ModSharp Gamedata Update Module

Updates gamedata for ModSharp plugin framework.
NOTE: This module is currently disabled (not implemented).
"""

import os
import sys

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# Module metadata
MODULE_NAME = "ModSharp"
MODULE_ENABLED = False  # Not implemented yet

# Relative paths to gamedata files within this dist directory
GAMEDATA_DIR = ".asset/gamedata"


def update(yaml_data, func_lib_map, platforms, dist_dir, alias_to_name_map, debug=False):
    """
    Update ModSharp gamedata files.

    NOTE: This function is not implemented yet.

    Args:
        yaml_data: Loaded YAML data
        func_lib_map: Function name to library mapping
        platforms: List of platforms to update
        dist_dir: Path to this module's dist directory
        alias_to_name_map: Mapping from aliases to function names
        debug: If True, collect updated and skipped symbols info

    Returns:
        Tuple of (updated_count, skipped_count, updated_symbols, skipped_symbols)
    """
    # TODO: Implement ModSharp gamedata update logic
    print(f"  Warning: {MODULE_NAME} update not implemented")
    return 0, 0, [], []
