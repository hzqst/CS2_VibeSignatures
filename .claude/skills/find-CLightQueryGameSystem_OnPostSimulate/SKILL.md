---
name: find-CLightQueryGameSystem_OnPostSimulate
description: >
  Find and identify CLightQueryGameSystem_OnPostSimulate function in CS2 client binary using IDA Pro MCP.
  CLightQueryGameSystem_OnPostSimulate is located via the "CLightQueryGameSystem::OnPostSimulate." string reference.
  Trigger: CLightQueryGameSystem_OnPostSimulate
disable-model-invocation: true
---

# CLightQueryGameSystem_OnPostSimulate Location Workflow

## Overview

Locate the function `CLightQueryGameSystem_OnPostSimulate` in CS2 client binary.

`CLightQueryGameSystem_OnPostSimulate` references the string `"CLightQueryGameSystem::OnPostSimulate."`.

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the `CLightQueryGameSystem::OnPostSimulate.` string:

```
mcp__ida-pro-mcp__find_regex(pattern="CLightQueryGameSystem::OnPostSimulate\\.")
```

### 2. Find CLightQueryGameSystem_OnPostSimulate via Cross-References

Use `xrefs_to` on the string address to find the function that references it:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

The function referencing this string is `CLightQueryGameSystem_OnPostSimulate`.

### 3. Rename CLightQueryGameSystem_OnPostSimulate

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<OnPostSimulate_addr>", "name": "CLightQueryGameSystem_OnPostSimulate"}})
```

### 4. Generate Signature for CLightQueryGameSystem_OnPostSimulate

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CLightQueryGameSystem_OnPostSimulate`.

### 5. Write YAML Output for CLightQueryGameSystem_OnPostSimulate

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results for `CLightQueryGameSystem_OnPostSimulate`.

Required parameters:
- `func_name`: `CLightQueryGameSystem_OnPostSimulate`
- `func_addr`: The function address from step 2
- `func_sig`: The validated signature from step 4

## Function Characteristics

### CLightQueryGameSystem_OnPostSimulate

- Regular function (not virtual)
- References the string `CLightQueryGameSystem::OnPostSimulate.`
- Handles light query post-simulation logic

## Output YAML Files

- `CLightQueryGameSystem_OnPostSimulate.windows.yaml` / `.linux.yaml`
