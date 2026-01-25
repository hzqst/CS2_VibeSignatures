---
name: quit-ida
description: Quit/close the current IDA Pro session using ida-pro-mcp. Use this skill when you need to close IDA, exit IDA, quit IDA session, or terminate the current IDA Pro instance.
---

# Quit IDA

Close the current IDA Pro session by executing `idc.qexit(0)` via the `py_eval` MCP tool.

## Usage

Call the `mcp__ida-pro-mcp__py_eval` tool with the following code:

```python
idc.qexit(0)
```

## Example

```json
{
  "code": "idc.qexit(0)"
}
```

This will cleanly exit IDA Pro and close the current session.

## Important notes

- `py_eval` returns `ConnectionResetError`, and later calls to `ida-pro-mcp` become `ConnectionRefusedError`.
- This means IDA quit as expected.