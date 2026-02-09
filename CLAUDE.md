# CLAUDE.md

This file provides guidance and important rules working with code in this repository.

### When coding / building plan

 - **ALWAYS** call Serena's `activate_project` on agent startup
 - Use a progressive disclosure approach for agent coding in this repository: start from high-level information in Serena memories, and only locate/read specific files or symbols when necessary to avoid expanding too much context at once.

#### Serena memories (Keep context clean)
1. Use `list_memories` first to browse existing memories in the current project (do not read all memories by default).
2. Only when needed, use `read_memory` to load a specific memory precisely (on-demand loading).
3. If memory content is insufficient or outdated, fall back to reading repository files or use Serena's symbol/search capabilities for targeted lookup, and maintain memory content with `write_memory` / `edit_memory` / `delete_memory`.

#### Source File Entry Points When Memories Are Insufficient (On-Demand Querying and Reading)
- Download CS2 binaries: `download_bin.py`
- Analyzes CS2 binary files, processes modules and symbols defined in config.yaml. and generate yaml for them:`ida_analyze_bin.py`
- Bump generated yaml into gamedata json / txt: `update_gamedata.py`

## IDA Pro MCP Tools Reference

### ida-pro-mcp.rename Usage

`rename` is a unified renaming tool that supports renaming functions, global variables, local variables, and stack variables.

#### Parameter Structure

```json
{
  "batch": {
    "func": [...],      // Function renaming
    "data": [...],      // Global/data variable renaming
    "local": [...],     // Local variable renaming
    "stack": [...]      // Stack variable renaming
  }
}
```

#### 1. Function renaming (`func`)

```json
{
  "batch": {
    "func": {
      "addr": "0x12345678",   // Function address (hex or decimal)
      "name": "NewFuncName"   // New function name
    }
  }
}
```

#### 2. Global / Data variable renaming (`data`)

```json
{
  "batch": {
    "data": {
      "old": "old_global_name",  // Current variable name
      "new": "new_global_name"   // New variable name
    }
  }
}
```

#### 3. Local variable renaming (`local`)

```json
{
  "batch": {
    "local": {
      "func_addr": "0x12345678",  // Function address containing the local variable
      "old": "v1",                 // Current variable name
      "new": "playerIndex"         // New variable name
    }
  }
}
```

#### 4. Stack variable renaming (`stack`)

```json
{
  "batch": {
    "stack": {
      "func_addr": "0x12345678",  // Function address containing the stack variable
      "old": "var_20",             // Current variable name
      "new": "bufferSize"          // New variable name
    }
  }
}
```

#### Batch Operation Example

Multiple rename operations can be performed simultaneously:

```json
{
  "batch": {
    "func": [
      {"addr": "0x1000", "name": "InitPlayer"},
      {"addr": "0x2000", "name": "UpdateHealth"}
    ],
    "local": [
      {"func_addr": "0x1000", "old": "a1", "new": "pPlayer"},
      {"func_addr": "0x1000", "old": "v5", "new": "healthValue"}
    ]
  }
}
```

### ida-pro-mcp.get_bytes Usage

`get_bytes` reads bytes from memory addresses in the binary.

#### Parameter Structure

```json
{
  "regions": {
    "addr": "0x12345678",  // Address to read from (hex or decimal)
    "size": 16             // Number of bytes to read
  }
}
```

#### Single Region Example

Read 16 bytes from a single address:

```json
{
  "regions": {
    "addr": "0x140001000",
    "size": 16
  }
}
```

#### Multiple Regions Example

Read bytes from multiple addresses simultaneously:

```json
{
  "regions": [
    {"addr": "0x140001000", "size": 16},
    {"addr": "0x140002000", "size": 32},
    {"addr": "0x140003000", "size": 8}
  ]
}