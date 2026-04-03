# Data Storage Guidelines

> How structured data (YAML, JSON, JSONC, VDF) is managed in this project.

**Note**: This project has no traditional database. All data is stored as flat files in YAML, JSON, JSONC, or VDF format.

---

## Overview

The data flow is:

```
config.yaml (input) → IDA analysis → bin/{gamever}/{module}/*.yaml (intermediate) → dist/{framework}/gamedata/* (output)
```

Three distinct data layers:
1. **Configuration** — `config.yaml` defines what to analyze.
2. **Analysis results** — YAML files in `bin/` store raw signatures and offsets.
3. **Gamedata output** — JSON/JSONC/VDF files in `dist/` are consumed by plugin frameworks.

---

## Configuration: `config.yaml`

### Structure

```yaml
modules:
  - name: engine                              # Module identifier
    path_windows: game/bin/win64/engine2.dll   # Binary path (Windows)
    path_linux: game/bin/linuxsteamrt64/libengine2.so  # Binary path (Linux)
    skills:
      - name: find-CNetworkGameServer_vtable   # Skill to execute
        expected_output:                        # YAML files this skill produces
          - CNetworkGameServer_vtable.{platform}.yaml
        expected_input:                         # YAML files this skill depends on (optional)
          - SomeOtherSymbol.{platform}.yaml
        max_retries: 3                          # Override default retry count (optional)
    symbols:
      - name: CNetworkGameServer_vtable         # Symbol identifier
        category: vtable                        # One of: vtable, func, vfunc, struct, structmember, patch
        alias:                                  # Alternative names (optional)
          - CNetworkGameServer
```

### Rules

- `{platform}` in `expected_output` / `expected_input` is a placeholder expanded to `windows` or `linux` at runtime.
- Skill dependency order is determined automatically via topological sort on `expected_input` / `expected_output` relationships.
- Symbol `category` must be one of: `vtable`, `func`, `vfunc`, `struct`, `structmember`, `patch`.

---

## Analysis Results: YAML Files

### Location

```
bin/{gamever}/{module}/{SymbolName}.{platform}.yaml
```

Example: `bin/14142b/engine/CNetworkGameServer_vtable.windows.yaml`

### YAML Formats by Category

**Function (`func`):**
```yaml
func_name: CGameResourceService_BuildResourceManifest
func_va: '0x8e9750'
func_rva: '0x8e9750'
func_size: '0xc5'
func_sig: 55 48 89 E5 41 57 41 56 4D 89 CE 41 55 4D 89 C5 41 54 49 89 FC
```

**Virtual function (`vfunc`):**
```yaml
func_name: CServerSideClient_IsHearingClient
func_va: '0x6a10a0'
func_rva: '0x6a10a0'
func_size: '0x42'
func_sig: 48 89 5C 24 ?? 48 8B D9 ...
vtable_class: CNetworkGameServer
vtable_index: 0
vtable_offset: '0x0'
```

**Vtable (`vtable`):**
```yaml
vtable_class: CNetworkGameServer
vtable_symbol: _ZTV18CNetworkGameServer + 0x10
vtable_va: '0x948950'
vtable_rva: '0x948950'
vtable_size: '0x2c0'
vtable_numvfunc: 88
vtable_entries:
  0: '0x6a10a0'
  1: '0x68bff0'
```

**Patch (`patch`):**
```yaml
patch_name: CCSPlayer_MovementServices_FullWalkMove_SpeedClamp
patch_va: '0x123456'
patch_rva: '0x123456'
patch_sig: 0F 2F C1 0F 86 ?? ?? ?? ??
patch_offset_in_sig: 0
```

**Struct member offset (`structmember`):**
```yaml
struct_name: CGameRulesProxy
member_name: m_pGameRules
member_offset: '0x1A8'
member_sig: 48 8B 05 ?? ?? ?? ?? 48 8B 48 ??
```

### Rules

- All hex values are quoted strings with `0x` prefix: `'0x8e9750'`.
- Signatures use uppercase hex bytes separated by spaces, with `??` for wildcards.
- YAML is always written with `yaml.safe_dump(data, default_flow_style=False, sort_keys=False)`.
- `sort_keys=False` is critical — field order must match the templates above for readability.
- Virtual address (`va`) and relative virtual address (`rva`) are both stored; they may differ when the binary has a non-zero image base.

---

## Gamedata Output Formats

### JSON (CounterStrikeSharp)

```json
{
  "CNetworkGameServer_GetFreeClient": {
    "signatures": {
      "library": "engine",
      "windows": "48 89 5C 24 ? ...",
      "linux": "55 48 89 E5 ..."
    }
  }
}
```

Wildcard format: `??` → `?` (single question mark).

### VDF (CS2Fixes)

```
"Games"
{
    "cs2"
    {
        "Signatures"
        {
            "CNetworkGameServer_GetFreeClient"
            {
                "library"  "engine"
                "windows"  "\x48\x89\x5C\x24\x2A..."
                "linux"    "\x55\x48\x89\xE5..."
            }
        }
    }
}
```

Wildcard format: `??` → `\x2A`.

### JSONC (Swiftly, plugify)

Same as JSON but with `//` comments allowed. The project includes a custom JSONC parser in `gamedata_utils.py` for reading existing files.

---

## Common Mistakes

1. **Using `sort_keys=True` in YAML dump** — Destroys the intended field order, making YAML files harder to read and diff.
2. **Forgetting to quote hex values** — `0x8e9750` without quotes is interpreted as an integer by YAML; always use `'0x8e9750'`.
3. **Mixing wildcard formats** — YAML uses `??`, CSS/Swiftly uses `?`, CS2Fixes uses `\x2A`. Use the converter functions in `gamedata_utils.py`.
4. **Hardcoding platform in file paths** — Always use `{platform}` placeholder in config and let runtime expand it.
