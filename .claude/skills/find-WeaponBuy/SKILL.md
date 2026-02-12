---
name: find-WeaponBuy
description: Find and identify the WeaponBuy (item purchase handler) function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the WeaponBuy function by searching for the "item_purchase" string reference and analyzing cross-references.
---

# Find WeaponBuy

Locate `WeaponBuy` (item purchase handler) in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="item_purchase"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

4. Verify the function:
   - Look for the "item_purchase" game event being created and fired
   - The function should handle weapon/item purchasing logic
   - Typical pattern involves:
     - Creating game event with "item_purchase"
     - Setting event fields like "userid", "team", "loadout", "weapon"
     - Firing the event

5. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "WeaponBuy"}]}
   ```

6. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

7. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `WeaponBuy`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 6

   Note: This is NOT a virtual function, so no vtable parameters are needed.

## String References

The function uses the `item_purchase` game event string which is used when a player buys a weapon or item.

## Function Characteristics

- **Purpose**: Handles item/weapon purchases by players
- **Game Event**: Fires `item_purchase` event with details about the purchase
- **Event Fields**:
  - `userid`: Player who made the purchase
  - `team`: Team of the purchasing player
  - `loadout`: Loadout slot information
  - `weapon`: The weapon/item that was purchased

## Key Behaviors

1. Validates the purchase request
2. Creates the `item_purchase` game event
3. Populates event with purchase details
4. Fires the event to notify the game system

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- This is a regular function, NOT a virtual function
- No vtable information is needed for this function
- The function is central to the buy system in CS2
- Multiple references to "item_purchase" may exist; look for the main purchase handler

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `WeaponBuy.windows.yaml`
- `server.so` -> `WeaponBuy.linux.yaml`
