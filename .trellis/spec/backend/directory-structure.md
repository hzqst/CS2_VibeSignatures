# Directory Structure

> How code and data are organized in this project.

---

## Overview

The project follows a **pipeline architecture** with distinct stages: download binaries, analyze with IDA, output YAML signatures, convert to gamedata formats, and validate C++ headers.

---

## Directory Layout

```
CS2_VibeSignatures/
├── config.yaml                    # Master configuration: modules, skills, symbols
├── download_bin.py                # Stage 1: Download binaries from AlliedMods SourceBins
├── copy_depot_bin.py              # Stage 1 alt: Copy binaries from local Steam depot
├── ida_analyze_bin.py             # Stage 2: Orchestrate IDA analysis via MCP + agents
├── ida_analyze_util.py            # Stage 2: Shared utilities (IDA templates, YAML I/O, sig helpers)
├── ida_skill_preprocessor.py      # Stage 2: MCP entrypoint dispatching to skill scripts
├── update_gamedata.py             # Stage 3: Convert YAML → gamedata (JSON/JSONC/VDF)
├── gamedata_utils.py              # Stage 3: Shared gamedata conversion utilities
├── run_cpp_tests.py               # Stage 4: Validate C++ headers via clang vtable dumps
├── cpp_tests_util.py              # Stage 4: C++ vtable parsing and comparison logic
├── pyproject.toml                 # Python dependency management (uv)
│
├── bin/                           # Binary files and YAML analysis output
│   └── {gamever}/                 # e.g., 14142b
│       └── {module}/             # e.g., engine, server, client
│           └── {Symbol}.{platform}.yaml
│
├── dist/                          # Gamedata output targets (one per framework)
│   └── {framework}/              # e.g., CS2Fixes, CounterStrikeSharp
│       ├── config.yaml           # Optional: per-framework symbol overrides
│       ├── gamedata.py           # Gamedata update module (plugin interface)
│       └── gamedata/             # Generated gamedata files
│
├── ida_preprocessor_scripts/      # Skill-specific preprocessor scripts (50+)
│   ├── find-{SymbolName}.py      # One script per skill
│   └── _igamesystem_dispatch_common.py  # Shared helpers (underscore prefix)
│
├── cpp_tests/                     # C++ header validation tests
│   └── {module}/                 # Organized by game module
│
├── hl2sdk_cs2/                    # HL2SDK headers for CS2
├── patched-py/                    # Custom patched Python modules
│
├── .claude/                       # Claude Code harness
│   ├── agents/                   # Agent prompt definitions
│   ├── commands/                 # Slash command definitions
│   ├── hooks/                    # Event hooks (session-start, pre-tool-use)
│   └── skills/                   # AI skills for IDA analysis (50+)
│
├── .serena/                       # Serena memory system
├── .trellis/                      # Trellis project management
└── docs/                          # Documentation
```

---

## Module Organization

### Pipeline Scripts (root level)

Each pipeline stage has one **orchestrator script** and optionally one **utility module**:

| Stage | Orchestrator | Utility | Purpose |
|-------|-------------|---------|---------|
| 1. Download | `download_bin.py` / `copy_depot_bin.py` | — | Acquire binaries |
| 2. Analyze | `ida_analyze_bin.py` | `ida_analyze_util.py` | IDA analysis via MCP |
| 3. Convert | `update_gamedata.py` | `gamedata_utils.py` | YAML → gamedata |
| 4. Validate | `run_cpp_tests.py` | `cpp_tests_util.py` | C++ header checks |

Orchestrators are CLI entry points with `argparse`. Utility modules are importable libraries.

### Preprocessor Scripts (`ida_preprocessor_scripts/`)

- Each skill defined in `config.yaml` has a matching preprocessor script.
- File naming: `{skill-name}.py` (kebab-case matching the skill name in config).
- Shared helpers use underscore prefix: `_igamesystem_dispatch_common.py`.
- Every script exports a single async function: `preprocess_skill(session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False)`.

### Gamedata Modules (`dist/{framework}/gamedata.py`)

- Dynamically loaded via `importlib.util` by `update_gamedata.py`.
- Each module exports an `update(yaml_data, func_lib_map, platforms, ...)` function.
- Framework-specific config overlays live in `dist/{framework}/config.yaml`.

---

## Naming Conventions

### Files

| Category | Convention | Examples |
|----------|-----------|----------|
| CLI scripts | `snake_case.py` | `download_bin.py`, `ida_analyze_bin.py` |
| Utility modules | `snake_case.py` | `ida_analyze_util.py`, `gamedata_utils.py` |
| Preprocessor scripts | `kebab-case.py` (matches skill name) | `find-CNetworkGameServer_vtable.py` |
| Shared preprocessor helpers | `_underscore_prefix.py` | `_igamesystem_dispatch_common.py` |
| YAML output | `{SymbolName}.{platform}.yaml` | `CServerSideClient_IsHearingClient.linux.yaml` |

### Python Identifiers

| Category | Convention | Examples |
|----------|-----------|----------|
| Functions | `snake_case` | `parse_config()`, `preprocess_skill()` |
| Variables | `snake_case` | `default_bin_dir`, `mcp_startup_timeout` |
| Constants | `UPPER_SNAKE_CASE` | `DEFAULT_CONFIG_FILE`, `MCP_STARTUP_TIMEOUT` |
| Classes | `PascalCase` (rare) | — |
| Binary symbol names | `PascalCase_with_underscores` | `CNetworkGameServer_vtable`, `CBaseEntity_Use` |

---

## Examples

Well-organized modules to reference:

- **`download_bin.py`** — Clean CLI script pattern: docstring, argparse, config parsing, main logic.
- **`gamedata_utils.py`** — Pure utility module: no side effects, well-documented converter functions.
- **`ida_preprocessor_scripts/find-CBaseEntity_Use.py`** — Minimal preprocessor script delegating to `preprocess_common_skill`.
