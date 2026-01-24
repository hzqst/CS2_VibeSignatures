---
name: find-CCSPlayerPawnBase_PostThink
description: |
  IDA Pro string analysis and function reverse engineering workflow. Connect to IDA Pro via ida-pro-mcp for binary analysis to locate the CCSPlayerPawnBase_PostThink function.
  Use cases:
  (1) Search for specific strings in binary files
  (2) Find cross-references (xrefs) to strings
  (3) Decompile functions that reference strings and view pseudocode
  (4) Locate specific code segments in pseudocode
  (5) Rename functions and variables to improve readability
  (6) Analyze function call relationships and data flow
  Trigger: CCSPlayerPawnBase_PostThink
---

# CCSPlayerPawnBase_PostThink Function Location Workflow

## Overview

This workflow is used to locate the `CCSPlayerPawnBase_PostThink` function in CS2 server binary files. This function is the PostThink handler for player Pawns, responsible for handling enter/exit events for buy zones, bomb zones, and rescue zones.

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the `enter_buyzone` string:

```
mcp__ida-pro-mcp__find_regex(pattern="enter_buyzone")
```

Expected result: Find string address `0x7f6cde`

* If the found address is not 0x7f6cde, that's normal. 0x7f6cde is the address from an older version of server.so; newer versions may have different addresses. The same applies below.

### 2. Find Cross-References

Use `xrefs_to` to find locations that reference this string:

```
mcp__ida-pro-mcp__xrefs_to(addrs="0x7f6cde")
```

Expected result: Find function `sub_9E0280`

### 3. Rename Function

Use `rename` to give the function a meaningful name:

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "0x9E0280", "name": "CCSPlayerPawnBase_PostThink"}})
```

### 4. Decompile to View Pseudocode

Use `decompile` to view the function pseudocode:

```
mcp__ida-pro-mcp__decompile(addr="0x9E0280")
```

## Function Characteristics

The `CCSPlayerPawnBase_PostThink` function contains the following signature strings:

- `enter_buyzone` / `exit_buyzone` - Buy zone events
- `enter_bombzone` / `exit_bombzone` - Bomb zone events
- `enter_rescue_zone` / `exit_rescue_zone` - Rescue zone events
- `weapon_c4` - C4 bomb detection
- `SpottedLooseBomb` - AFK player dropped bomb notification

## Related Functions

- `sub_10CA560` - Check if in buy zone
- `sub_10CA6A0` - Check if can purchase
- `sub_12929F0` - Find specified weapon
- `qword_20E1CC0` - Game event manager
