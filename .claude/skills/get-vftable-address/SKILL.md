---
name: get-vftable-address
description: |
  Find a function's vtable address using IDA Pro MCP. Use this skill when want to get exact virtual address of a class.
  Triggers: get vftable address, get virtual function table, find vtable, get vtable
---

# Get VTable Index

Find a class's virtual function table within it's class name.

## Prerequisites

- ClassName

## Method

### 1. Get vtable address by class name:
   ```
   mcp__ida-pro-mcp__list_globals(queries={"filter": "*ClassName*"})
   ```
   Look for:
   - Windows: `??_7ClassName@@6B@`
   - Linux: `_ZTVNClassName` or `_ZTVN...E`

## Platform Notes

- **Windows**: VTable starts directly at the symbol address
- **Linux**: First 16 bytes are RTTI metadata. Real vtable address = `_ZTV... + 0x10`
