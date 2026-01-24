---
name: generate-signature-for-function
description: |
  Generate and validate unique byte signatures for functions using IDA Pro MCP. Use this skill when you need to create a pattern-scanning signature for a function that can reliably locate it across binary updates.
  Triggers: generate signature, byte signature, pattern signature, function signature, unique signature, sig for function
---

# Generate Signature for Function

Generate a unique hex byte signature for a function that can be used for pattern scanning.

## Prerequisites

- Function address (from decompilation, xrefs, or rename)
- IDA Pro MCP connection

## Method

### 1. Get Function Bytes

```python
mcp__ida-pro-mcp__py_eval code="""
import ida_bytes

func_addr = <func_addr>

# Get first 64 bytes of function
raw_bytes = ida_bytes.get_bytes(func_addr, 64)
print("Function bytes:", ' '.join(f'{b:02X}' for b in raw_bytes))
"""
```

### 2. Validate Signature Uniqueness

Test that the signature matches ONLY this function in the .text segment:

```python
mcp__ida-pro-mcp__py_eval code="""
import ida_bytes
import ida_segment

func_addr = <func_addr>

# Get .text segment bounds
seg = ida_segment.get_segm_by_name(".text")
start = seg.start_ea
end = seg.end_ea

# Candidate signature - start with first N bytes
raw_bytes = ida_bytes.get_bytes(func_addr, 64)
candidate_sig = raw_bytes[:16]  # Adjust length as needed

# Search in chunks to avoid memory issues
step = 0x200000
matches = []

for chunk_start in range(start, end, step):
    chunk_end = min(chunk_start + step + 64, end)
    data = ida_bytes.get_bytes(chunk_start, chunk_end - chunk_start)
    if data:
        pos = 0
        while True:
            idx = data.find(candidate_sig, pos)
            if idx == -1:
                break
            matches.append(hex(chunk_start + idx))
            pos = idx + 1

print(f"Signature matches: {len(matches)}")
for m in matches:
    print(m)

if len(matches) == 1:
    print("SUCCESS: Signature is unique!")
    print("Signature:", ' '.join(f'{b:02X}' for b in candidate_sig))
else:
    print("WARNING: Signature not unique, need longer/different pattern")
"""
```

## Output Format

Signature format: space-separated hex bytes with `??` for wildcards.

Example: `55 8B EC 83 E4 F8 83 EC ?? 53 56 57`

## Tips for Unique Signatures

- **Start short, extend if needed**: Begin with 16 bytes, extend to 24/32 if not unique
- **Use wildcards (`??`)** for:
  - Immediate offsets that may change
  - Relocation addresses
  - Register encodings that vary
- **Look for distinctive patterns**:
  - Unique string references
  - Unusual instruction sequences
  - Specific immediate values
- **Avoid**:
  - Common prologues (`55 8B EC` alone)
  - All-zero or all-FF sequences
  - Short repeated patterns

## Important

**DO NOT** use `find_bytes` to validate signatures - it doesn't work reliably for function pattern matching. Always use the `py_eval` method above.
