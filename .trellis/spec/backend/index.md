# Backend Development Guidelines

> Best practices for Python scripting and binary analysis automation in this project.

---

## Overview

This project is a **reverse-engineering automation pipeline** for CS2 (Counter-Strike 2). It uses Python scripts to orchestrate IDA Pro binary analysis via MCP, generate byte signatures, and convert them into gamedata formats consumed by various CS2 plugin frameworks.

There is no traditional "frontend" or "backend" in the web-application sense. All code is Python CLI scripts and utilities.

---

## Guidelines Index

| Guide | Description | Status |
|-------|-------------|--------|
| [Directory Structure](./directory-structure.md) | Project layout, module organization, output paths | Filled |
| [Data Storage Guidelines](./database-guidelines.md) | YAML/JSON/JSONC/VDF data formats and conventions | Filled |
| [Error Handling](./error-handling.md) | Exception patterns, graceful degradation | Filled |
| [Quality Guidelines](./quality-guidelines.md) | Code standards, testing, signature validation | Filled |
| [Logging Guidelines](./logging-guidelines.md) | Print-based output, indentation levels, debug mode | Filled |

---

## Key Principles

1. **Document actual conventions** — these guidelines describe how the codebase *works today*, not aspirational ideals.
2. **Binary analysis context** — this is not a web app; conventions revolve around IDA Pro interaction, signature accuracy, and cross-platform binary analysis.
3. **Determinism matters** — signature generation must be reproducible; the same binary should always produce the same YAML output.

---

**Language**: All documentation is written in **English**.
