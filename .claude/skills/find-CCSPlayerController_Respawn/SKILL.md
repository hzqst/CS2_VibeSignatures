---
name: find-function-template
description: Template skill for finding and documenting CS2 functions in server.dll or server.so using IDA Pro MCP. Use this as a reference when creating new find-{FunctionName} skills for reverse engineering CS2 binaries. This template demonstrates the complete workflow including string search, function identification, vtable analysis, signature generation, and YAML documentation.
---

# Find Function Template

This is a template skill for creating find-{FunctionName} skills to locate and document CS2 functions in server.dll or server.so using IDA Pro MCP tools.

## Workflow Overview

1. **Search** - Locate the function using string references or other identifiable patterns
2. **Identify** - Verify and rename the function
3. **VTable Analysis** - Find vtable information (for virtual functions)
4. **Signature Generation** - Create unique byte signature for pattern scanning
5. **Documentation** - Write analysis results to YAML

## Method

### 1. Search for the Function

Use one of these approaches based on what's identifiable:

**Option A: String-based search** (most common)
```
mcp__ida-pro-mcp__find_regex pattern="<unique_string_pattern>"
```

**Option B: Known symbol search**
```
mcp__ida-pro-mcp__list_funcs queries={"filter": "*FunctionName*"}
```

**Option C: Pattern-based search**
```
mcp__ida-pro-mcp__find type="string" targets="<identifiable_text>"
```

### 2. Get Cross-References (if string search was used)

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
```

### 3. Decompile and Verify the Function

```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

Analyze the pseudocode to confirm this is the correct function based on:
- String references
- Function logic and parameters
- Called functions
- Class member accesses

### 4. Rename the Function

```
mcp__ida-pro-mcp__rename batch={"func": [{"addr": "<function_addr>", "name": "<FunctionName>"}]}
```

If rename fails, use Python API:
```python
mcp__ida-pro-mcp__py_eval code="""
import ida_name
addr = <function_addr>
result = ida_name.force_name(addr, "<FunctionName>")
print(f"Rename result: {result}")
"""
```

### 5. Find VTable Information (for virtual functions only)

**ALWAYS** Use SKILL `/get-vftable-index` to get vtable offset and index for the function.

VTable class names to search for:
- **Windows**: `??_7ClassName@@6B@`
- **Linux**: `_ZTVNClassName` or `_ZTVN...E`

Example for CCSPlayerController:
- Windows: `??_7CCSPlayerController@@6B@`
- Linux: `_ZTV19CCSPlayerController`

**Important**: For Linux server.so, the first 16 bytes of vtable are RTTI metadata. The real vtable starts at `_ZTV... + 0x10`.

### 6. Generate Unique Signature

**DO NOT** use `find_bytes` as it won't work for function signatures.

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

Pass the function address:
```
/generate-signature-for-function <function_addr>
```

The skill will:
- Extract function bytes
- Analyze disassembly
- Create signature with wildcards for relative offsets
- Validate uniqueness

### 7. Write Analysis Results to YAML

**ALWAYS** Use SKILL `/write-func-ida-analysis-output-as-yaml` to write the analysis results.

Pass the function address:
```
/write-func-ida-analysis-output-as-yaml <function_addr>
```

Required parameters (to be filled in the skill):
- `func_name`: The function name (e.g., "CCSPlayerController_ChangeTeam")
- `func_addr`: The function address from step 4
- `func_sig`: The validated signature from step 6

VTable parameters (for virtual functions):
- `vtable_name`: Class name (e.g., "CCSPlayerController")
- `vtable_mangled_name`: Platform-specific mangled name
  - Windows: `??_7ClassName@@6B@`
  - Linux: `_ZTVNClassName`
- `vfunc_offset`: Offset from vtable start (from step 5)
- `vfunc_index`: Index in vtable (from step 5)

## Output YAML Format

The YAML filename depends on the platform:
- `server.dll` → `<FunctionName>.windows.yaml`
- `server.so` → `<FunctionName>.linux.yaml`

### Regular Function (no vtable)

```yaml
func_va: 0x180XXXXXX      # Virtual address - changes with game updates
func_rva: 0xXXXXXX        # Relative virtual address (VA - image base) - changes with game updates
func_size: 0xXX           # Function size in bytes - changes with game updates
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning
```

### Virtual Function (with vtable)

```yaml
func_va: 0x180XXXXXX      # Virtual address - changes with game updates
func_rva: 0xXXXXXX        # Relative virtual address (VA - image base) - changes with game updates
func_size: 0xXX           # Function size in bytes - changes with game updates
func_sig: XX XX XX XX XX  # Unique byte signature for pattern scanning
vtable_name: ClassName
vtable_mangled_name: ??_7ClassName@@6B@  # or _ZTVNClassName for Linux
vfunc_offset: 0xXXX       # Offset from vtable start - changes with game updates
vfunc_index: XXX          # vtable[index] - changes with game updates
```

## Platform Differences

### Windows (server.dll)
- VTable symbol format: `??_7ClassName@@6B@`
- Image base: Non-zero (typically 0x180000000 for x64)
- RVA = VA - ImageBase

### Linux (server.so / libserver.so)
- VTable symbol format: `_ZTVNClassName` (mangled C++ name)
- Image base: 0x0
- RVA = VA
- **Important**: VTable data starts at symbol + 0x10 (skip RTTI metadata)

## Creating a New Find-Function Skill

To create a new skill for a specific function:

1. Copy this template to `.claude/skills/find-<FunctionName>/SKILL.md`
2. Update the frontmatter:
   - `name`: `find-<FunctionName>`
   - `description`: Describe the specific function and when to use this skill
3. Customize the search method (step 1) with specific patterns for the target function
4. Add function-specific characteristics:
   - Known string patterns or debug messages
   - Parameter descriptions
   - Return value information
   - Related functions or context
5. Update examples with actual addresses and values from analysis
6. Test the skill on both Windows and Linux binaries if available

## Example: CCSPlayerController_Respawn

```
1. Search: Function already identified at 0x1340df0
2. Verify: Confirmed via decompilation
3. Rename: CCSPlayerController_Respawn (already named)
4. VTable: Index 274, Offset 0x890 in _ZTV19CCSPlayerController
5. Signature: 55 48 89 E5 41 57 41 56 41 55 41 54 53 48 89 FB 48 81 EC 58 01 00 00 E8 ?? ?? ?? ?? 80 BB A9 0B 00 00 00 C6 83 FC 0A 00 00 00
6. Output: CCSPlayerController_Respawn.linux.yaml
```

## Common VTable Classes

- `CCSPlayerController` - Player controller class
- `CCSPlayerPawn` - Player pawn class
- `CBaseEntity` - Base entity class
- `CBaseModelEntity` - Base model entity class
- `CCSGameRules` - Game rules class

## Tips

- Use descriptive function names following CS2 naming conventions
- Always verify function identity before renaming
- Test signatures for uniqueness before finalizing
- Document any assumptions or uncertainties in comments
- For multi-step functions, consider breaking into sub-skills
