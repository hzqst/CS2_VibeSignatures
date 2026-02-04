#!/usr/bin/env python3
"""
CS2Surf Gamedata Update Module

Updates gamedata for CS2Surf plugin.
NOTE: This module is currently disabled (not implemented).
"""

import os
import sys

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# Module metadata
MODULE_NAME = "CS2Surf"
MODULE_ENABLED = False  # Not implemented yet

# Relative path to gamedata file within this dist directory
GAMEDATA_PATH = "gamedata/cs2surf-core.games.jsonc"


def update(yaml_data, func_lib_map, platforms, dist_dir, alias_to_name_map, debug=False):
    """
    Update CS2Surf gamedata file.

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
    # TODO: Implement CS2Surf gamedata update logic
    print(f"  Warning: {MODULE_NAME} update not implemented")
    return 0, 0, [], []
