---
name: find-FireBullets-AND-TraceAttack-AND-CTakeDamageInfo
description: Find and identify the TraceAttack function and CTakeDamageInfo struct in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 server.dll or server.so to locate the TraceAttack function by searching for the "FireBullets" debug string pattern, then tracing through FireBullets to find TraceAttack, and identifying CTakeDamageInfo struct member offsets.
---

# Find TraceAttack and CTakeDamageInfo

Locate `TraceAttack` function and `CTakeDamageInfo` struct in CS2 server.dll or server.so using IDA Pro MCP tools.

## Method

### 1. Search for FireBullets Debug String

Search for the FireBullets debug string in the binary:

```
mcp__ida-pro-mcp__find_regex pattern="FireBullets"
```

Expected result: Multiple strings including `"FireBullets @ %10f [ %s ]: inaccuracy=%f  spread=%f  max dispersion=%f  mode=%2i  vel=%10f  seed=%3i  %s\n"`

### 2. Find Cross-References to Debug String

Get xrefs to the debug string address:

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_address>"
```

The xref should point to a function - this is `FireBullets`.

### 3. Decompile FireBullets

Decompile the FireBullets function:

```
mcp__ida-pro-mcp__decompile addr="<function_addr>"
```

### 4. Rename FireBullets Function

```
mcp__ida-pro-mcp__rename batch={"func": {"addr": "<function_addr>", "name": "FireBullets"}}
```

### 5. Locate TraceAttack in FireBullets

Look for the following code pattern in FireBullets that calls TraceAttack:

Windows:

```c
              if ( (unsigned int)sub_18099FAC0(  // <-- This is TraceAttack
                                     *v63,
                                     (__int64)&v76,
                                     (__int64)&v66,
                                     v42,
                                     v43,
                                     4,
                                     v45,
                                     v94,
                                     v49,
                                     v44,
                                     v14,
                                     0LL,
                                     v54,
                                     *(float *)&v87[v48],
                                     a2,
                                     v28,
                                     v107,
                                     a6,
                                     (__int64)v56,
                                     v109) == 1 )
              {
                  // SHA1 verification code follows when result == 1
                  v84 = Plat_FloatTime() + 4294967296.0;
                  v58 = RandomInt(0LL, 0x7FFFFFFFLL);
                  // ...
                  CSHA1::Reset((CSHA1 *)v89);
                  CSHA1::Update((CSHA1 *)v89, &v84, 0x10u);
                  CSHA1::Final((CSHA1 *)v89);
```

Linux:

```c
              if ( (unsigned int)sub_XXXXXXX(  // <-- This is TraceAttack
                                     ...
                                     ) == 1 )
              {
                  // Similar SHA1 verification pattern
```

**Key identifying features:**
- Called from FireBullets with ~20 parameters
- Returns 1 when bullet hits a target
- Followed by SHA1 hashing code for bullet verification
- Called twice in FireBullets (first call checks hit, second call with new seed)

### 6. Rename TraceAttack Function

```
mcp__ida-pro-mcp__rename batch={"func": {"addr": "<traceattack_addr>", "name": "TraceAttack"}}
```

### 7. Generate and Validate Unique Signature for FireBullets and TraceAttack

**ALWAYS** Use SKILL `/generate-signature-for-function` to generate a robust and unique signature for the function.

### 8. Write IDA Analysis Output as YAML for FireBullets and TraceAttack

**ALWAYS** Use SKILL `/write-func-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `TraceAttack`
- `func_addr`: The TraceAttack function address
- `func_sig`: The validated signature from step 7

### 9. Locate CTakeDamageInfo::HitGroupInfo in TraceAttack

Decompile TraceAttack and look for the damage processing loop near the end of the function:

Windows:

```c
  v104 = 0;
  if ( v184 > 0 )
  {
    v105 = v132;
    v106 = 0LL;
    do
    {
      // Get pTakeDamageInfo structure (480 bytes per entry)
      pTakeDamageInfo = (__int64)&v187[v106];

      // HitGroupInfo is at offset 288 from entry start
      HitGroupInfo = &v108[v106 + 288];
      v110 = (_QWORD *)*((_QWORD *)HitGroupInfo + 1);

      // Set CTakeDamageInfo::HitGroupInfo at offset 0x68 (104)
      *(_QWORD *)(pTakeDamageInfo + 104) = HitGroupInfo;

      // Call damage functions
      sub_1803C8520(v110, pTakeDamageInfo, 0LL);  // TakeDamageOld
      sub_1803C9740(pTakeDamageInfo, ...);

      ++v104;
      v106 += 480LL;
    }
    while ( v104 < v184 );
  }
```

Linux:

```c
  if ( (int)v247 > 0 )
  {
    v195 = 0LL;
    do
    {
      pTakeDamageInfo = (__int64)v121;

      // HitGroupInfo pointer stored at offset 104 (0x68)
      *(_QWORD *)(pTakeDamageInfo + 104) = v128;

      // Call damage functions
      sub_C8A650(v127, (__int64)v196, 0LL, v125, v52.m128_f32[0]);
      sub_C8ADC0(v196, pTakeDamageInfo + 408, pTakeDamageInfo + 420, v194);

      v195 += 480LL;
    }
    while ( v120 < (int)v247 );
  }
```

**Key pattern:**
- Loop iterates through hit entities
- Each entry is 480 bytes
- `pTakeDamageInfo + 104` (0x68) stores the HitGroupInfo pointer

### 10. Write Struct Members for CTakeDamageInfo as YAML

**ALWAYS** Use SKILL `/write-struct-as-yaml` to write CTakeDamageInfo's struct member information:

For `CTakeDamageInfo.{platform}.yaml`:
- Offset `0x68`: `HitGroupInfo` (size 8)

## Function Characteristics

### FireBullets
- **Size**: ~2600-2800 bytes
- **Parameters**: `(int, __int64, __int64, __int64*, __int64, int, int, ...)`
- **Purpose**: Main bullet firing function, handles accuracy, spread, and calls TraceAttack

### TraceAttack
- **Size**: ~4800-5000 bytes
- **Parameters**: ~20 parameters including trace info, damage values, entity pointers
- **Return**: 1 if hit target, 0 otherwise
- **Purpose**: Performs bullet trace and applies damage to hit entities

### Platform Differences

| Aspect | Windows | Linux |
|--------|---------|-------|
| Debug string path | `C:\buildworker\csgo_rel_win64\...` | `/build/src/game/server/...` |
| Entry size in loop | 480 bytes | 480 bytes |
| HitGroupInfo offset | 0x68 (104) | 0x68 (104) |
