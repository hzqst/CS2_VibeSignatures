#!/usr/bin/env python3
"""Shared utility helpers for IDA analyze scripts."""

import json


def parse_mcp_result(result):
    """Parse CallToolResult content to a Python object."""
    if result.content:
        text = result.content[0].text
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text
    return None