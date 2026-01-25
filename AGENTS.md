# AGENTS.md

This file provides guidance and important rules working with code in this repository.

## Important rules

### When running SKILLS with ida-pro-mcp

 - **DONT STOP** half-way until you finish all tasks in SKILL

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