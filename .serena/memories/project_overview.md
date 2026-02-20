# Project overview

Purpose:
- Automate generation of CS2 signatures/offsets via agent skills and IDA Pro MCP.
- Produce YAML signature outputs and update gamedata files for multiple CS2 mod ecosystems.

Tech stack:
- Python 3 scripts + YAML configuration.
- Dependencies: pyyaml, requests, asyncio, mcp, vdf.
- External tools: IDA Pro + ida-pro-mcp, idalib, Claude/Codex CLI.

Repository structure (top-level):
- download_bin.py: download CS2 binaries from SourceBins using config.yaml.
- ida_analyze_bin.py: headless IDA analysis using MCP + agent skills; infers skill dependency tree from expected_input/expected_output (with legacy prerequisite fallback) and generates YAML files.
- update_gamedata.py: converts YAML outputs into various gamedata formats.
- config.yaml: module + symbol catalog for analysis.
- bin/: downloaded binaries and generated YAML outputs by game version.
- dist/: generated gamedata outputs for multiple targets.
- docs/: per-function notes and references.
- .claude/skills/: project-level skills used by agents.
- patched-py/: patched libraries for IDA/MCP compatibility.
