---
name: find-CSource1LegacyGameEventGameSystem_ClientPostDataUpdate
description: |
  Find and identify CSource1LegacyGameEventGameSystem_ClientPostDataUpdate function in CS2 client binary using IDA Pro MCP.
  CSource1LegacyGameEventGameSystem_ClientPostDataUpdate is located via the "CNetworkGameClient::OnSource1Source1LegacyGameEvent: UnserializeKeyValue failed." string reference.
  It is a virtual function in the CSource1LegacyGameEventGameSystem vtable.
  Trigger: CSource1LegacyGameEventGameSystem_ClientPostDataUpdate, ClientPostDataUpdate, OnSource1Source1LegacyGameEvent
disable-model-invocation: true
---

# CSource1LegacyGameEventGameSystem_ClientPostDataUpdate Location Workflow

## Overview

Locate the virtual function `CSource1LegacyGameEventGameSystem_ClientPostDataUpdate` in CS2 client binary.
This function references the string "CNetworkGameClient::OnSource1Source1LegacyGameEvent: UnserializeKeyValue failed." and is a virtual function in the CSource1LegacyGameEventGameSystem vtable.

## Location Steps

### 1. Search for Signature String

Use `find_regex` to search for the `CNetworkGameClient::OnSource1Source1LegacyGameEvent: UnserializeKeyValue failed.` string:

```
mcp__ida-pro-mcp__find_regex(pattern="CNetworkGameClient::OnSource1Source1LegacyGameEvent: UnserializeKeyValue failed.")
```

### 2. Find CSource1LegacyGameEventGameSystem_ClientPostDataUpdate via Cross-References

Use `xrefs_to` on the string address to find the function that references it:

```
mcp__ida-pro-mcp__xrefs_to(addrs="<string_addr>")
```

There may be multiple functions referencing this string. The target function is the one that has **no more string references** than "CNetworkGameClient::OnSource1Source1LegacyGameEvent: UnserializeKeyValue failed." — i.e., it should have minimal or only this one string reference.

### 3. Rename CSource1LegacyGameEventGameSystem_ClientPostDataUpdate

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "<ClientPostDataUpdate_addr>", "name": "CSource1LegacyGameEventGameSystem_ClientPostDataUpdate"}})
```

### 4. Load CSource1LegacyGameEventGameSystem VTable and Get VTable Index

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CSource1LegacyGameEventGameSystem`

If the skill returns an error, **STOP** and report to user.

Find `CSource1LegacyGameEventGameSystem_ClientPostDataUpdate` address in `vtable_entries` to determine `vfunc_index`.

### 5. Generate Signature

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for `CSource1LegacyGameEventGameSystem_ClientPostDataUpdate`.

### 6. Write YAML Output

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results for `CSource1LegacyGameEventGameSystem_ClientPostDataUpdate`.

Required parameters:
- `func_name`: `CSource1LegacyGameEventGameSystem_ClientPostDataUpdate`
- `func_addr`: The function address from step 2
- `func_sig`: The validated signature from step 5

VTable parameters:
- `vtable_name`: `CSource1LegacyGameEventGameSystem`
- `vfunc_offset`: calculated from vfunc_index * 8
- `vfunc_index`: from step 4

## Function Characteristics

### CSource1LegacyGameEventGameSystem_ClientPostDataUpdate

- Virtual function in CSource1LegacyGameEventGameSystem vtable
- References the string `CNetworkGameClient::OnSource1Source1LegacyGameEvent: UnserializeKeyValue failed.`
- Handles source1 legacy game event processing during client post data update

## Output YAML Files

- `CSource1LegacyGameEventGameSystem_ClientPostDataUpdate.windows.yaml` / `.linux.yaml`
