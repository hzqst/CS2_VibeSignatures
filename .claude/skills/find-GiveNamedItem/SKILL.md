---
name: find-GiveNamedItem
description: Find and identify the GiveNamedItem function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the GiveNamedItem function by searching for known debug string references and analyzing cross-references.
---

# Find GiveNamedItem

Locate `GiveNamedItem` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the debug string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="GiveNamedItem: interpreting"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "GiveNamedItem"}]}
   ```

5. Generate and validate unique signature:

   **DO NOT** use `find_bytes` as it won't work for function.
   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `GiveNamedItem`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

   Note: GiveNamedItem is NOT a virtual function, so no vtable parameters are needed.

## Signature Pattern

The function contains a debug log call with format string:
```
GiveNamedItem: interpreting '%s' as '%s'\n
```

This string is used when the function translates legacy weapon names to modern equivalents.

## Function Characteristics

- **Parameters**: `(this, weapon_name, ...)` where `this` is likely a player pointer, `weapon_name` is the item/weapon identifier string
- **Purpose**: Gives a named item (weapon, equipment) to a player entity
- **Legacy weapon handling**: The function handles legacy weapon names (e.g., "weapon_galil", "weapon_mp5navy", "weapon_p228") and translates them to modern equivalents using a lookup table at `off_237BD00`
- **Special handling**: Contains special logic for C4 weapon (triggers "player_given_c4" event)
- **Recursion**: The function recursively calls itself after resolving weapon name aliases

## Weapon Name Translation

The function uses a global array `off_237BD00` containing weapon name mappings to handle legacy names. When a legacy name is detected, it:
1. Logs the translation with the debug string
2. Recursively calls itself with the translated name

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `GiveNamedItem.windows.yaml`
- `server.so` → `GiveNamedItem.linux.yaml`

```yaml
func_va: 0x1336e00        # Virtual address of the function - This can change when game updates.
func_rva: 0x1336e00       # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xa98          # Function size in bytes - This can change when game updates.
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - This can change when game updates.
```

Note: GiveNamedItem is a regular function, not a virtual function, so no vtable information is included.
