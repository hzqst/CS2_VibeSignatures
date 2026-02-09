---
name: find-NetworkStateChanged
description: Find and identify the NetworkStateChanged function in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the NetworkStateChanged function by searching for the "light_capsule" string reference and analyzing cross-references.
---

# Find NetworkStateChanged

Locate `NetworkStateChanged` in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

1. Search for the string:
   ```
   mcp__ida-pro-mcp__find_regex pattern="light_capsule"
   ```

2. Get cross-references to the string:
   ```
   mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
   ```

3. Decompile the referencing function:
   ```
   mcp__ida-pro-mcp__decompile addr="<function_addr>"
   ```

   The target function should contain:
   - Multiple `V_stricmp_fast` calls comparing against light type strings:
     - `"light_omni"`
     - `"light_capsule"`
     - `"light_spot"`
     - `"light_ortho"`
     - `"light_directional"`
     - `"light_environment"`
   - Sets a light type value (1-4) based on the string comparison
   - Contains a network state notification call at the end

   Example pattern:
   ```cpp
   if ( (unsigned int)V_stricmp_fast(v6, "light_omni") )
   {
       if ( (unsigned int)V_stricmp_fast(v6, "light_capsule") )
       {
           // ... more light type checks
       }
       else
       {
           v7 = 1;
       }
   }
   // ...
   *(_DWORD *)(a1 + 112) = v7;
   // ...
   v11 = V_stricmp_fast(v3, "light_capsule");
   *(_BYTE *)(a1 + 116) = v11 == 0;
   if ( v12 && ... )
   {
       sub_XXXXXXXX(a1 + 413, -1, -1);  // Internal notification call
       *(_BYTE *)(a1 + 413) = 1;
   }
   ```

4. Rename the function:
   ```
   mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "NetworkStateChanged"}]}
   ```

5. Generate and validate unique signature:

   **ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

6. Write IDA analysis output as YAML beside the binary:

   **ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

   Required parameters:
   - `func_name`: `NetworkStateChanged`
   - `func_addr`: The function address from step 3
   - `func_sig`: The validated signature from step 5

## Function Characteristics

- **Prototype**: `void NetworkStateChanged(void *chainEntity, int offset, int a3)`
- **Parameters**:
  - `chainEntity`: Pointer to the entity/component being updated
  - `offset`: Offset parameter for network state tracking
- **Return**: char (1 on success)

## Key Behaviors

1. Compares input string against various light type names
2. Sets appropriate light type enum value (0-4)
3. Stores `light_capsule` comparison result as a flag
4. Triggers internal network state notification when conditions are met
5. Called when light entity properties change to notify the network system

## DLL Information

- **DLL**: `server.dll` (Windows) / `server.so` (Linux)

## Notes

- This is NOT a virtual function
- The function handles light type classification and network state updates
- Contains multiple string comparisons for different light types

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` → `NetworkStateChanged.windows.yaml`
- `server.so` → `NetworkStateChanged.linux.yaml`

```yaml
func_va: 0x180XXXXXX      # Virtual address of the function - This can change when game updates.
func_rva: 0xXXXXXX        # Relative virtual address (VA - image base) - This can change when game updates.
func_size: 0xXXX          # Function size in bytes - This can change when game updates.
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning - This can change when game updates.
```
