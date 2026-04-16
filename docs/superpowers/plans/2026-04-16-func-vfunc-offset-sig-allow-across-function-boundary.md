# Func Vfunc Offset Sig Allow Across Function Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `func_sig`、`vfunc_sig`、`offset_sig` 增加与 `gv_sig_allow_across_function_boundary` 对齐的显式跨函数边界签名生成能力，并保证默认不跨边界。

**Architecture:** 先用 `unittest` 锁定 directive 解析、字段白名单、YAML 回写和参数透传行为。随后在 `ida_analyze_util.py` 中抽出共享的 IDA py_eval 边界扫描片段，让三个签名生成器复用同一套“函数内默认截止、显式开启后只跨 padding 到下一个 code head”的保守策略，同时保留各自 wildcard 和唯一性判定。最后覆盖所有公共调用点，确保未显式声明时仍保持默认关闭。

**Tech Stack:** Python 3、`unittest`、`unittest.mock.AsyncMock`、IDA MCP `py_eval`/`find_bytes`、`yaml.safe_dump`

---

## File Structure

- Modify: `ida_analyze_util.py`
  - 扩展 `FUNC_YAML_ORDER` 与 `STRUCT_MEMBER_YAML_ORDER`
  - 扩展 `_normalize_generate_yaml_desired_fields(...)`
  - 新增共享的跨函数边界 py_eval helper 片段
  - 为 `preprocess_gen_func_sig_via_mcp(...)` 增加 `allow_across_function_boundary`
  - 为 `preprocess_gen_vfunc_sig_via_mcp(...)` 增加 `allow_across_function_boundary`
  - 为 `preprocess_gen_struct_offset_sig_via_mcp(...)` 增加 `allow_across_function_boundary`
  - 为 `_preprocess_direct_func_sig_via_mcp(...)`、`_build_enriched_slot_only_vfunc_payload_via_mcp(...)`、`preprocess_func_xrefs_via_mcp(...)`、`preprocess_index_based_vfunc_via_mcp(...)`、`_preprocess_direct_struct_offset_sig_via_mcp(...)` 增加必要透传
  - 在 `preprocess_common_skill(...)` 中按 symbol 的 `generation_options` 注入生成参数和 YAML 标记
- Modify: `tests/test_ida_analyze_util.py`
  - 新增 directive 解析测试
  - 新增三个生成器的跨边界 py_eval 守卫测试
  - 新增 direct/common skill 参数透传与 YAML 回写测试
  - 保留并回归 `gv_sig_allow_across_function_boundary`
- Create: `docs/superpowers/plans/2026-04-16-func-vfunc-offset-sig-allow-across-function-boundary.md`
  - 当前实现计划文档

**仓库约束：**

- 实施阶段优先运行定向 `unittest`，不要先跑全量 build
- 本计划不会批量修改现有 `ida_preprocessor_scripts/*.py` 的字段声明；只有用户后续指定目标 symbol 时，才在对应脚本中加入新 directive
- `git commit` 消息遵循仓库约定：`<type>(scope): <中文动词开头摘要>`

## Shared Constants

实施时统一使用以下字段名，避免不同任务写出不一致的字符串：

```python
FUNC_SIG_ALLOW_ACROSS_FUNCTION_BOUNDARY = "func_sig_allow_across_function_boundary"
VFUNC_SIG_ALLOW_ACROSS_FUNCTION_BOUNDARY = "vfunc_sig_allow_across_function_boundary"
OFFSET_SIG_ALLOW_ACROSS_FUNCTION_BOUNDARY = "offset_sig_allow_across_function_boundary"
GV_SIG_ALLOW_ACROSS_FUNCTION_BOUNDARY = "gv_sig_allow_across_function_boundary"
```

## Task 1: 锁定字段契约与 YAML 回写行为

**Files:**
- Modify: `tests/test_ida_analyze_util.py`
- Modify: `ida_analyze_util.py`

- [ ] **Step 1: 写 directive 解析的 failing tests**

在 `tests/test_ida_analyze_util.py` 的 `TestGenerateYamlDesiredFieldsContract` 中，追加以下测试方法：

```python
    async def test_normalize_generate_yaml_desired_fields_parses_signature_boundary_flags(
        self,
    ) -> None:
        result = ida_analyze_util._normalize_generate_yaml_desired_fields(
            [
                (
                    "Foo",
                    [
                        "func_name",
                        "func_sig",
                        "func_sig_allow_across_function_boundary: true",
                        "vfunc_sig",
                        "vfunc_sig_max_match:10",
                        "vfunc_sig_allow_across_function_boundary: true",
                    ],
                ),
                (
                    "Bar_m_value",
                    [
                        "struct_name",
                        "member_name",
                        "offset",
                        "offset_sig",
                        "offset_sig_allow_across_function_boundary: true",
                    ],
                ),
            ],
            debug=True,
        )

        self.assertEqual(
            {
                "Foo": {
                    "desired_output_fields": [
                        "func_name",
                        "func_sig",
                        "func_sig_allow_across_function_boundary",
                        "vfunc_sig",
                        "vfunc_sig_max_match",
                        "vfunc_sig_allow_across_function_boundary",
                    ],
                    "generation_options": {
                        "func_sig_allow_across_function_boundary": True,
                        "vfunc_sig_max_match": 10,
                        "vfunc_sig_allow_across_function_boundary": True,
                    },
                },
                "Bar_m_value": {
                    "desired_output_fields": [
                        "struct_name",
                        "member_name",
                        "offset",
                        "offset_sig",
                        "offset_sig_allow_across_function_boundary",
                    ],
                    "generation_options": {
                        "offset_sig_allow_across_function_boundary": True,
                    },
                },
            },
            result,
        )

    async def test_normalize_generate_yaml_desired_fields_rejects_bare_signature_boundary_flags(
        self,
    ) -> None:
        for field_name in (
            "func_sig_allow_across_function_boundary",
            "vfunc_sig_allow_across_function_boundary",
            "offset_sig_allow_across_function_boundary",
        ):
            with self.subTest(field_name=field_name):
                result = ida_analyze_util._normalize_generate_yaml_desired_fields(
                    [("Foo", ["func_sig", field_name])],
                    debug=True,
                )

                self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_rejects_invalid_signature_boundary_flag_values(
        self,
    ) -> None:
        for field_name in (
            "func_sig_allow_across_function_boundary",
            "vfunc_sig_allow_across_function_boundary",
            "offset_sig_allow_across_function_boundary",
        ):
            with self.subTest(field_name=field_name):
                result = ida_analyze_util._normalize_generate_yaml_desired_fields(
                    [("Foo", ["func_sig", f"{field_name}: false"])],
                    debug=True,
                )

                self.assertIsNone(result)

    async def test_normalize_generate_yaml_desired_fields_rejects_duplicate_signature_boundary_flags(
        self,
    ) -> None:
        for field_name in (
            "func_sig_allow_across_function_boundary",
            "vfunc_sig_allow_across_function_boundary",
            "offset_sig_allow_across_function_boundary",
        ):
            with self.subTest(field_name=field_name):
                result = ida_analyze_util._normalize_generate_yaml_desired_fields(
                    [
                        (
                            "Foo",
                            [
                                "func_sig",
                                f"{field_name}: true",
                                f"{field_name}: true",
                            ],
                        )
                    ],
                    debug=True,
                )

                self.assertIsNone(result)
```

- [ ] **Step 2: 写 YAML 回写的 failing tests**

继续在 `TestGenerateYamlDesiredFieldsContract` 中追加以下测试方法：

```python
    async def test_preprocess_common_skill_writes_func_and_vfunc_boundary_flags(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_func_sig_via_mcp",
            AsyncMock(
                return_value={
                    "func_name": "Foo",
                    "func_va": "0x180004000",
                    "func_rva": "0x4000",
                    "func_size": "0x40",
                    "func_sig": "48 89 ??",
                    "func_sig_allow_across_function_boundary": True,
                    "vfunc_sig": "FF 90 78 00 00 00",
                    "vfunc_sig_max_match": 10,
                    "vfunc_sig_allow_across_function_boundary": True,
                }
            ),
        ), patch.object(
            ida_analyze_util,
            "write_func_yaml",
        ) as mock_write_func_yaml, patch.object(
            ida_analyze_util,
            "_rename_func_in_ida",
            AsyncMock(return_value=None),
        ):
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=["/tmp/Foo.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                func_names=["Foo"],
                generate_yaml_desired_fields=[
                    (
                        "Foo",
                        [
                            "func_name",
                            "func_sig",
                            "func_sig_allow_across_function_boundary: true",
                            "vfunc_sig",
                            "vfunc_sig_max_match:10",
                            "vfunc_sig_allow_across_function_boundary: true",
                        ],
                    )
                ],
                debug=True,
            )

        self.assertTrue(result)
        self.assertEqual(
            {
                "func_name": "Foo",
                "func_sig": "48 89 ??",
                "func_sig_allow_across_function_boundary": True,
                "vfunc_sig": "FF 90 78 00 00 00",
                "vfunc_sig_max_match": 10,
                "vfunc_sig_allow_across_function_boundary": True,
            },
            mock_write_func_yaml.call_args.args[1],
        )

    async def test_preprocess_common_skill_writes_offset_sig_boundary_flag(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_struct_offset_sig_via_mcp",
            AsyncMock(
                return_value={
                    "struct_name": "Bar",
                    "member_name": "m_value",
                    "offset": "0x58",
                    "size": 8,
                    "offset_sig": "49 8B 4E ??",
                    "offset_sig_disp": 0,
                    "offset_sig_allow_across_function_boundary": True,
                }
            ),
        ), patch.object(
            ida_analyze_util,
            "write_struct_offset_yaml",
        ) as mock_write_struct_offset_yaml:
            result = await ida_analyze_util.preprocess_common_skill(
                session="session",
                expected_outputs=["/tmp/Bar_m_value.windows.yaml"],
                old_yaml_map={},
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                struct_member_names=["Bar_m_value"],
                generate_yaml_desired_fields=[
                    (
                        "Bar_m_value",
                        [
                            "struct_name",
                            "member_name",
                            "offset",
                            "offset_sig",
                            "offset_sig_allow_across_function_boundary: true",
                        ],
                    )
                ],
                debug=True,
            )

        self.assertTrue(result)
        self.assertEqual(
            {
                "struct_name": "Bar",
                "member_name": "m_value",
                "offset": "0x58",
                "offset_sig": "49 8B 4E ??",
                "offset_sig_allow_across_function_boundary": True,
            },
            mock_write_struct_offset_yaml.call_args.args[1],
        )
```

- [ ] **Step 3: 运行新增契约测试，确认失败**

Run:

```bash
uv run python -m unittest tests.test_ida_analyze_util.TestGenerateYamlDesiredFieldsContract -v
```

Expected:

```text
FAIL: test_normalize_generate_yaml_desired_fields_parses_signature_boundary_flags
FAIL: test_preprocess_common_skill_writes_func_and_vfunc_boundary_flags
FAIL: test_preprocess_common_skill_writes_offset_sig_boundary_flag
```

- [ ] **Step 4: 实现字段顺序与 directive 解析**

在 `ida_analyze_util.py` 中把 `FUNC_YAML_ORDER` 和 `STRUCT_MEMBER_YAML_ORDER` 改成以下顺序：

```python
FUNC_YAML_ORDER = [
    "func_name",
    "func_va",
    "func_rva",
    "func_size",
    "func_sig",
    "func_sig_allow_across_function_boundary",
    "vtable_name",
    "vfunc_offset",
    "vfunc_index",
    "vfunc_sig",
    "vfunc_sig_max_match",
    "vfunc_sig_allow_across_function_boundary",
]
```

```python
STRUCT_MEMBER_YAML_ORDER = [
    "struct_name",
    "member_name",
    "offset",
    "size",
    "offset_sig",
    "offset_sig_disp",
    "offset_sig_allow_across_function_boundary",
]
```

在 `_normalize_generate_yaml_desired_fields(...)` 中新增一个内部 helper，并用它处理 `gv_sig` 和三个新字段：

```python
        def _parse_true_directive(field_name, option_name):
            if field_name == option_name:
                if debug:
                    print(
                        f"    Preprocess: bare {option_name} field is "
                        f"not allowed for {symbol_name}"
                    )
                return False

            if not field_name.startswith(f"{option_name}:"):
                return None

            if option_name in generation_options:
                if debug:
                    print(
                        f"    Preprocess: duplicated {option_name} directive "
                        f"for {symbol_name}"
                    )
                return False

            value_text = field_name.split(":", 1)[1].strip().lower()
            if value_text != "true":
                if debug:
                    print(
                        f"    Preprocess: invalid {option_name} value "
                        f"for {symbol_name}: {value_text}"
                    )
                return False

            desired_output_fields.append(option_name)
            generation_options[option_name] = True
            return True
```

在字段循环中加入：

```python
            for boundary_option in (
                "gv_sig_allow_across_function_boundary",
                "func_sig_allow_across_function_boundary",
                "vfunc_sig_allow_across_function_boundary",
                "offset_sig_allow_across_function_boundary",
            ):
                parsed_boundary_option = _parse_true_directive(
                    field_name,
                    boundary_option,
                )
                if parsed_boundary_option is False:
                    return None
                if parsed_boundary_option is True:
                    break
            else:
                desired_output_fields.append(field_name)
                continue
            continue
```

保留现有 `vfunc_sig_max_match` 逻辑，并确保它仍然在 boundary option 逻辑之前处理。

- [ ] **Step 5: 回跑字段契约测试**

Run:

```bash
uv run python -m unittest tests.test_ida_analyze_util.TestGenerateYamlDesiredFieldsContract -v
```

Expected:

```text
OK
```

- [ ] **Step 6: 提交字段契约改动**

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "feat(preprocess): 增加签名跨边界字段契约"
```

## Task 2: 抽取共享跨边界 py_eval 片段并接入 `func_sig`

**Files:**
- Modify: `tests/test_ida_analyze_util.py`
- Modify: `ida_analyze_util.py`

- [ ] **Step 1: 写 `func_sig` 默认不跨边界与开启跨边界的 failing tests**

在 `tests/test_ida_analyze_util.py` 的 `test_preprocess_gen_gv_sig_via_mcp_guards_cross_boundary_decode` 后面追加：

```python
    async def test_preprocess_gen_func_sig_via_mcp_defaults_to_function_boundary(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = False", code)
                self.assertIn("limit_end = min(f.end_ea, target_ea + max_sig_bytes)", code)
                self.assertIn("PAD_BYTES = {0xCC, 0x90}", code)
                return _py_eval_payload(
                    {
                        "func_va": "0x18004ABC0",
                        "func_size": "0x6",
                        "insts": [
                            {
                                "ea": "0x18004abc0",
                                "size": 6,
                                "bytes": "48895c2408e8",
                                "wild": [4, 5],
                            }
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(["48 89 5C 24 ?? ??"], arguments["patterns"])
                return _FakeCallToolResult(
                    [{"matches": ["0x18004ABC0"], "n": 1}]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_func_sig_via_mcp(
            session=session,
            func_va="0x18004ABC0",
            image_base=0x180000000,
            min_sig_bytes=6,
            debug=False,
        )

        self.assertEqual("48 89 5C 24 ?? ??", result["func_sig"])

    async def test_preprocess_gen_func_sig_via_mcp_guards_cross_boundary_decode(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = True", code)
                self.assertIn("PAD_BYTES = {0xCC, 0x90}", code)
                self.assertIn("SEGPERM_EXEC", code)
                self.assertIn("def _is_same_exec_segment", code)
                self.assertIn("def _consume_padding", code)
                self.assertIn(
                    "if allow_across_boundary and cursor >= f.end_ea:",
                    code,
                )
                self.assertIn(
                    "if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):",
                    code,
                )
                return _py_eval_payload(
                    {
                        "func_va": "0x18004ABC0",
                        "func_size": "0x6",
                        "insts": [
                            {
                                "ea": "0x18004abc0",
                                "size": 6,
                                "bytes": "48895c2408e8",
                                "wild": [4, 5],
                            },
                            {
                                "ea": "0x18004abc6",
                                "size": 3,
                                "bytes": "4885c9",
                                "wild": [],
                            },
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(["48 89 5C 24 ?? ??"], arguments["patterns"])
                return _FakeCallToolResult(
                    [{"matches": ["0x18004ABC0"], "n": 1}]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_func_sig_via_mcp(
            session=session,
            func_va="0x18004ABC0",
            image_base=0x180000000,
            min_sig_bytes=6,
            allow_across_function_boundary=True,
            debug=False,
        )

        self.assertEqual("48 89 5C 24 ?? ??", result["func_sig"])
```

- [ ] **Step 2: 运行 `func_sig` 新测试，确认当前实现失败**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_func_sig_via_mcp_defaults_to_function_boundary \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_func_sig_via_mcp_guards_cross_boundary_decode \
  -v
```

Expected:

```text
FAIL: test_preprocess_gen_func_sig_via_mcp_defaults_to_function_boundary
ERROR: test_preprocess_gen_func_sig_via_mcp_guards_cross_boundary_decode
```

第二条当前会报 `TypeError`，因为 `preprocess_gen_func_sig_via_mcp(...)` 尚未接受 `allow_across_function_boundary`。

- [ ] **Step 3: 新增共享 py_eval 边界 helper**

在 `ida_analyze_util.py` 的 `_build_vtable_py_eval(...)` 后面新增：

```python
def _build_signature_boundary_py_eval_helpers() -> str:
    return (
        "PAD_BYTES = {0xCC, 0x90}\\n"
        "SEGPERM_EXEC = int(getattr(idaapi, 'SEGPERM_EXEC', 4))\\n"
        "\\n"
        "def _is_same_exec_segment(ea, seg_start_ea):\\n"
        "    seg = idaapi.getseg(ea)\\n"
        "    if not seg:\\n"
        "        return False\\n"
        "    return seg.start_ea == seg_start_ea and bool(getattr(seg, 'perm', 0) & SEGPERM_EXEC)\\n"
        "\\n"
        "def _consume_padding(cursor, limit_end, seg_start_ea):\\n"
        "    padding = []\\n"
        "    while cursor < limit_end:\\n"
        "        if not _is_same_exec_segment(cursor, seg_start_ea):\\n"
        "            return cursor, padding, False\\n"
        "        flags = ida_bytes.get_full_flags(cursor)\\n"
        "        if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):\\n"
        "            return cursor, padding, True\\n"
        "        b = ida_bytes.get_byte(cursor)\\n"
        "        if b == idaapi.BADADDR or b not in PAD_BYTES:\\n"
        "            return cursor, padding, False\\n"
        "        pad_start = cursor\\n"
        "        pad_buf = bytearray()\\n"
        "        while cursor < limit_end and _is_same_exec_segment(cursor, seg_start_ea):\\n"
        "            flags = ida_bytes.get_full_flags(cursor)\\n"
        "            if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):\\n"
        "                break\\n"
        "            b = ida_bytes.get_byte(cursor)\\n"
        "            if b == idaapi.BADADDR or b not in PAD_BYTES:\\n"
        "                return cursor, padding, False\\n"
        "            pad_buf.append(b)\\n"
        "            cursor += 1\\n"
        "        if pad_buf:\\n"
        "            padding.append({'ea': hex(pad_start), 'size': len(pad_buf), 'bytes': bytes(pad_buf).hex(), 'wild': []})\\n"
        "    return cursor, padding, False\\n"
        "\\n"
    )
```

- [ ] **Step 4: 接入 `preprocess_gen_func_sig_via_mcp(...)`**

把函数签名改为：

```python
async def preprocess_gen_func_sig_via_mcp(
    session,
    func_va,
    image_base,
    min_sig_bytes=6,
    max_sig_bytes=240,
    max_instructions=100,
    extra_wildcard_offsets=None,
    allow_across_function_boundary=False,
    debug=False,
):
```

在生成的 `py_code` 中加入共享 helper，并把 loop 边界改为：

```python
        "allow_across_boundary = {bool(allow_across_function_boundary)}\\n"
        + _build_signature_boundary_py_eval_helpers()
        + (
        "f = idaapi.get_func(target_ea)\\n"
        "if not f or f.start_ea != target_ea:\\n"
        "    result = json.dumps(None)\\n"
        "else:\\n"
        "    origin_seg = idaapi.getseg(target_ea)\\n"
        "    if not origin_seg or not (getattr(origin_seg, 'perm', 0) & SEGPERM_EXEC):\\n"
        "        result = json.dumps(None)\\n"
        "    else:\\n"
        "        origin_seg_start = origin_seg.start_ea\\n"
        "        if allow_across_boundary:\\n"
        "            limit_end = target_ea + max_sig_bytes\\n"
        "        else:\\n"
        "            limit_end = min(f.end_ea, target_ea + max_sig_bytes)\\n"
        "        insts = []\\n"
        "        cursor = target_ea\\n"
        "        total = 0\\n"
        "        while cursor < limit_end and len(insts) < max_instructions and total < max_sig_bytes:\\n"
        "            if allow_across_boundary and cursor >= f.end_ea:\\n"
        "                cursor, pad_insts, ok = _consume_padding(cursor, limit_end, origin_seg_start)\\n"
        "                if not ok:\\n"
        "                    break\\n"
        "                for pad_inst in pad_insts:\\n"
        "                    if total + int(pad_inst['size']) > max_sig_bytes:\\n"
        "                        break\\n"
        "                    insts.append(pad_inst)\\n"
        "                    total += int(pad_inst['size'])\\n"
        "                if total >= max_sig_bytes or len(insts) >= max_instructions:\\n"
        "                    break\\n"
        "            insn = idautils.DecodeInstruction(cursor)\\n"
```

保留 `func_sig` 原有 wildcard 计算和返回 shape，不在返回 dict 中自动加入 `func_sig_allow_across_function_boundary`。

- [ ] **Step 5: 回跑 `func_sig` 和 `gv_sig` 边界测试**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_func_sig_via_mcp_defaults_to_function_boundary \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_func_sig_via_mcp_guards_cross_boundary_decode \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_gv_sig_via_mcp_guards_cross_boundary_decode \
  -v
```

Expected:

```text
OK
```

- [ ] **Step 6: 提交 `func_sig` 生成器改动**

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "feat(preprocess): 支持func签名跨函数边界"
```

## Task 3: 接入 `vfunc_sig` 并覆盖 direct 与 slot-only 透传

**Files:**
- Modify: `tests/test_ida_analyze_util.py`
- Modify: `ida_analyze_util.py`

- [ ] **Step 1: 写 `vfunc_sig` 生成器跨边界 failing test**

在 `tests/test_ida_analyze_util.py` 的 `test_preprocess_gen_vfunc_sig_via_mcp_generates_current_version_sig` 后面追加：

```python
    async def test_preprocess_gen_vfunc_sig_via_mcp_guards_cross_boundary_decode(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = True", code)
                self.assertIn("PAD_BYTES = {0xCC, 0x90}", code)
                self.assertIn("def _consume_padding", code)
                self.assertIn(
                    "if allow_across_boundary and cursor >= func.end_ea:",
                    code,
                )
                return _py_eval_payload(
                    {
                        "vfunc_sig_va": "0x18004abc3",
                        "vfunc_inst_length": 6,
                        "vfunc_disp_offset": 2,
                        "vfunc_disp_size": 4,
                        "insts": [
                            {
                                "ea": "0x18004abc3",
                                "size": 6,
                                "bytes": "ff9078000000",
                                "wild": [],
                            },
                            {
                                "ea": "0x18004abc9",
                                "size": 3,
                                "bytes": "4885c0",
                                "wild": [],
                            },
                        ],
                    }
                )
            if name == "find_bytes":
                self.assertEqual(["FF 90 78 00 00 00"], arguments["patterns"])
                return _FakeCallToolResult(
                    [{"matches": ["0x18004abc3"], "n": 1}]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_vfunc_sig_via_mcp(
            session=session,
            inst_va="0x18004ABC3",
            vfunc_offset="0x78",
            allow_across_function_boundary=True,
            debug=False,
        )

        self.assertEqual("FF 90 78 00 00 00", result["vfunc_sig"])
        self.assertEqual("0x78", result["vfunc_offset"])
```

- [ ] **Step 2: 写 direct 与 slot-only 透传 failing tests**

继续在 `tests/test_ida_analyze_util.py` 中追加以下两个测试：

```python
    async def test_preprocess_direct_func_sig_forwards_vfunc_boundary_flag(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_vtable_via_mcp",
            AsyncMock(
                return_value={
                    "vtable_class": "CBaseEntity",
                    "vtable_symbol": "_ZTV11CBaseEntity",
                    "vtable_va": "0x18021862e0",
                    "vtable_rva": "0x21862e0",
                    "vtable_size": "0x778",
                    "vtable_numvfunc": 239,
                    "vtable_entries": {110: "0x1809b8db0"},
                }
            ),
        ), patch.object(
            ida_analyze_util,
            "_get_func_basic_info_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x1809b8db0",
                    "func_rva": "0x9b8db0",
                    "func_size": "0x3",
                }
            ),
        ), patch.object(
            ida_analyze_util,
            "preprocess_gen_vfunc_sig_via_mcp",
            AsyncMock(
                return_value={
                    "vfunc_sig": "FF 90 70 03 00 00",
                    "vfunc_sig_max_match": 1,
                }
            ),
        ) as mock_preprocess_gen_vfunc_sig:
            result = await ida_analyze_util._preprocess_direct_func_sig_via_mcp(
                session=AsyncMock(),
                new_path="/tmp/Foo.windows.yaml",
                image_base=0x180000000,
                platform="windows",
                func_name="Foo",
                direct_vtable_class="CBaseEntity",
                direct_vfunc_offset="0x370",
                direct_vcall_inst_va="0x18016742cf",
                require_vfunc_sig=True,
                allow_vfunc_sig_across_function_boundary=True,
                debug=True,
            )

        self.assertIsNotNone(result)
        mock_preprocess_gen_vfunc_sig.assert_awaited_once_with(
            session=mock_preprocess_gen_vfunc_sig.call_args.kwargs["session"],
            inst_va="0x18016742cf",
            vfunc_offset="0x370",
            max_match_count=1,
            allow_across_function_boundary=True,
            debug=True,
        )

    async def test_slot_only_vfunc_payload_forwards_boundary_flag(
        self,
    ) -> None:
        llm_result = {
            "found_vcall": [
                {
                    "func_name": "Foo",
                    "vfunc_offset": "0x78",
                    "insn_va": "0x18004abc3",
                }
            ],
            "found_call": [],
            "found_funcptr": [],
            "found_gv": [],
            "found_struct_offset": [],
        }

        with patch.object(
            ida_analyze_util,
            "preprocess_gen_vfunc_sig_via_mcp",
            AsyncMock(
                return_value={
                    "vfunc_sig": "FF 90 78 00 00 00",
                    "vfunc_sig_max_match": 10,
                }
            ),
        ) as mock_preprocess_gen_vfunc_sig:
            result = await ida_analyze_util._build_enriched_slot_only_vfunc_payload_via_mcp(
                session="session",
                func_name="Foo",
                llm_result=llm_result,
                vtable_name="Bar",
                vfunc_sig_max_match=10,
                require_vfunc_sig=True,
                require_vtable_name=True,
                allow_vfunc_sig_across_function_boundary=True,
                debug=True,
            )

        self.assertEqual("FF 90 78 00 00 00", result["vfunc_sig"])
        mock_preprocess_gen_vfunc_sig.assert_awaited_once_with(
            session="session",
            inst_va="0x18004abc3",
            vfunc_offset="0x78",
            max_match_count=10,
            allow_across_function_boundary=True,
            debug=True,
        )
```

- [ ] **Step 3: 运行 `vfunc_sig` 新测试，确认失败**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_vfunc_sig_via_mcp_guards_cross_boundary_decode \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_direct_func_sig_forwards_vfunc_boundary_flag \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_slot_only_vfunc_payload_forwards_boundary_flag \
  -v
```

Expected:

```text
ERROR: test_preprocess_gen_vfunc_sig_via_mcp_guards_cross_boundary_decode
ERROR: test_preprocess_direct_func_sig_forwards_vfunc_boundary_flag
ERROR: test_slot_only_vfunc_payload_forwards_boundary_flag
```

- [ ] **Step 4: 实现 `vfunc_sig` 参数与 helper 透传**

把 `preprocess_gen_vfunc_sig_via_mcp(...)` 签名改为：

```python
async def preprocess_gen_vfunc_sig_via_mcp(
    session,
    inst_va,
    vfunc_offset,
    max_match_count=1,
    min_sig_bytes=6,
    max_sig_bytes=96,
    max_instructions=64,
    extra_wildcard_offsets=None,
    allow_across_function_boundary=False,
    debug=False,
):
```

在其 `py_code` 中复用 `_build_signature_boundary_py_eval_helpers()`，并将当前：

```python
"    while cursor < func.end_ea and len(insts) < max_instructions and total < max_sig_bytes:\n"
```

改为跨边界感知循环：

```python
        f"allow_across_boundary = {bool(allow_across_function_boundary)}\n"
        + _build_signature_boundary_py_eval_helpers()
```

```python
"    if allow_across_boundary:\n"
"        limit_end = target_inst + max_sig_bytes\n"
"    else:\n"
"        limit_end = min(func.end_ea, target_inst + max_sig_bytes)\n"
"    origin_seg = idaapi.getseg(target_inst)\n"
"    origin_seg_start = origin_seg.start_ea if origin_seg else None\n"
"    cursor = target_inst\n"
"    total = 0\n"
"    insts = []\n"
"    while cursor < limit_end and len(insts) < max_instructions and total < max_sig_bytes:\n"
"        if allow_across_boundary and cursor >= func.end_ea:\n"
"            cursor, pad_insts, ok = _consume_padding(cursor, limit_end, origin_seg_start)\n"
"            if not ok:\n"
"                break\n"
"            for pad_inst in pad_insts:\n"
"                if total + int(pad_inst['size']) > max_sig_bytes:\n"
"                    break\n"
"                insts.append(pad_inst)\n"
"                total += int(pad_inst['size'])\n"
"            if total >= max_sig_bytes or len(insts) >= max_instructions:\n"
"                break\n"
```

同时修改 `_preprocess_direct_func_sig_via_mcp(...)`：

```python
async def _preprocess_direct_func_sig_via_mcp(
    session,
    new_path,
    image_base,
    platform,
    func_name=None,
    direct_func_va=None,
    direct_vtable_class=None,
    direct_vfunc_offset=None,
    direct_vcall_inst_va=None,
    require_func_sig=False,
    require_vfunc_sig=False,
    vfunc_sig_max_match=1,
    allow_func_sig_across_function_boundary=False,
    allow_vfunc_sig_across_function_boundary=False,
    normalized_mangled_class_names=None,
    debug=False,
):
```

把 vfunc 生成调用改为：

```python
            sig_data = await preprocess_gen_vfunc_sig_via_mcp(
                session=session,
                inst_va=direct_vcall_inst_va,
                vfunc_offset=direct_vfunc_offset,
                max_match_count=vfunc_sig_max_match,
                allow_across_function_boundary=allow_vfunc_sig_across_function_boundary,
                debug=debug,
            )
```

修改 `_build_enriched_slot_only_vfunc_payload_via_mcp(...)`：

```python
async def _build_enriched_slot_only_vfunc_payload_via_mcp(
    session,
    func_name,
    llm_result,
    *,
    vtable_name=None,
    vfunc_sig_max_match=1,
    require_vfunc_sig=False,
    require_vtable_name=False,
    allow_vfunc_sig_across_function_boundary=False,
    debug=False,
):
```

```python
        sig_data = await preprocess_gen_vfunc_sig_via_mcp(
            session=session,
            inst_va=inst_va,
            vfunc_offset=slot_only_info["vfunc_offset"],
            max_match_count=vfunc_sig_max_match,
            allow_across_function_boundary=allow_vfunc_sig_across_function_boundary,
            debug=debug,
        )
```

- [ ] **Step 5: 在 `preprocess_common_skill(...)` 中透传并回写 `vfunc_sig` 标记**

在处理函数目标时获取：

```python
            generation_options = (
                desired_fields_map.get(func_name) or {}
            ).get("generation_options", {})
            allow_func_boundary = generation_options.get(
                "func_sig_allow_across_function_boundary",
                False,
            )
            allow_vfunc_boundary = generation_options.get(
                "vfunc_sig_allow_across_function_boundary",
                False,
            )
```

所有 `_preprocess_direct_func_sig_via_mcp(...)` 调用都补齐：

```python
                        allow_func_sig_across_function_boundary=allow_func_boundary,
                        allow_vfunc_sig_across_function_boundary=allow_vfunc_boundary,
```

`_build_enriched_slot_only_vfunc_payload_via_mcp(...)` 调用补齐：

```python
                    allow_vfunc_sig_across_function_boundary=allow_vfunc_boundary,
```

在 `_assemble_symbol_payload(...)` 之前注入 YAML 标记：

```python
        if allow_func_boundary:
            func_data["func_sig_allow_across_function_boundary"] = True
        if allow_vfunc_boundary:
            func_data["vfunc_sig_allow_across_function_boundary"] = True
```

- [ ] **Step 6: 回跑 `vfunc_sig` 相关测试**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_vfunc_sig_via_mcp_generates_current_version_sig \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_vfunc_sig_via_mcp_accepts_match_count_within_limit \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_vfunc_sig_via_mcp_guards_cross_boundary_decode \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_direct_func_sig_forwards_vfunc_boundary_flag \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_slot_only_vfunc_payload_forwards_boundary_flag \
  tests.test_ida_analyze_util.TestGenerateYamlDesiredFieldsContract.test_preprocess_common_skill_writes_func_and_vfunc_boundary_flags \
  -v
```

Expected:

```text
OK
```

- [ ] **Step 7: 提交 `vfunc_sig` 改动**

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "feat(preprocess): 支持vfunc签名跨函数边界"
```

## Task 4: 接入 `offset_sig` 并覆盖 struct-member 透传

**Files:**
- Modify: `tests/test_ida_analyze_util.py`
- Modify: `ida_analyze_util.py`

- [ ] **Step 1: 写 `offset_sig` 生成器跨边界 failing test**

在 `tests/test_ida_analyze_util.py` 的 `test_preprocess_gen_struct_offset_sig_via_mcp_generates_current_version_sig` 后面追加：

```python
    async def test_preprocess_gen_struct_offset_sig_via_mcp_guards_cross_boundary_decode(
        self,
    ) -> None:
        session = AsyncMock()

        def _fake_call_tool(*, name: str, arguments: dict[str, object]):
            if name == "py_eval":
                code = arguments["code"]
                self.assertIn("allow_across_boundary = True", code)
                self.assertIn("PAD_BYTES = {0xCC, 0x90}", code)
                self.assertIn("def _consume_padding", code)
                self.assertIn(
                    "if allow_across_boundary and cursor >= func.end_ea:",
                    code,
                )
                return _py_eval_payload(
                    [
                        {
                            "offset_inst_va": "0x1801BA12A",
                            "insts": [
                                {
                                    "ea": "0x1801ba12a",
                                    "size": 4,
                                    "bytes": "498b4e58",
                                    "wild": [3],
                                },
                                {
                                    "ea": "0x1801ba12e",
                                    "size": 3,
                                    "bytes": "4885c9",
                                    "wild": [],
                                },
                            ],
                        }
                    ]
                )
            if name == "find_bytes":
                self.assertEqual(["49 8B 4E ??"], arguments["patterns"])
                return _FakeCallToolResult(
                    [{"matches": ["0x1801BA12A"], "n": 1}]
                )
            raise AssertionError(f"unexpected MCP tool: {name}")

        session.call_tool.side_effect = _fake_call_tool

        result = await ida_analyze_util.preprocess_gen_struct_offset_sig_via_mcp(
            session=session,
            struct_name="CGameResourceService",
            member_name="m_pEntitySystem",
            offset="0x58",
            offset_inst_va="0x1801BA12A",
            image_base=0x180000000,
            size=8,
            min_sig_bytes=4,
            allow_across_function_boundary=True,
            debug=False,
        )

        self.assertEqual("49 8B 4E ??", result["offset_sig"])
```

- [ ] **Step 2: 写 direct struct-member 透传 failing test**

继续追加：

```python
    async def test_preprocess_direct_struct_offset_forwards_boundary_flag(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "preprocess_gen_struct_offset_sig_via_mcp",
            AsyncMock(
                return_value={
                    "struct_name": "Bar",
                    "member_name": "m_value",
                    "offset": "0x58",
                    "size": 8,
                    "offset_sig": "49 8B 4E ??",
                    "offset_sig_disp": 0,
                }
            ),
        ) as mock_preprocess_gen_struct_offset_sig:
            result = await ida_analyze_util._preprocess_direct_struct_offset_sig_via_mcp(
                session="session",
                new_path="/tmp/Bar_m_value.windows.yaml",
                image_base=0x180000000,
                struct_member_name="Bar_m_value",
                struct_name="Bar",
                member_name="m_value",
                offset="0x58",
                offset_inst_va="0x1801BA12A",
                size=8,
                allow_across_function_boundary=True,
                debug=True,
            )

        self.assertEqual("49 8B 4E ??", result["offset_sig"])
        mock_preprocess_gen_struct_offset_sig.assert_awaited_once_with(
            session="session",
            struct_name="Bar",
            member_name="m_value",
            offset="0x58",
            offset_inst_va="0x1801BA12A",
            image_base=0x180000000,
            size=8,
            allow_across_function_boundary=True,
            debug=True,
        )
```

- [ ] **Step 3: 运行 `offset_sig` 新测试，确认失败**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_struct_offset_sig_via_mcp_guards_cross_boundary_decode \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_direct_struct_offset_forwards_boundary_flag \
  -v
```

Expected:

```text
ERROR: test_preprocess_gen_struct_offset_sig_via_mcp_guards_cross_boundary_decode
ERROR: test_preprocess_direct_struct_offset_forwards_boundary_flag
```

- [ ] **Step 4: 实现 `offset_sig` 生成器参数**

把 `preprocess_gen_struct_offset_sig_via_mcp(...)` 签名改为：

```python
async def preprocess_gen_struct_offset_sig_via_mcp(
    session,
    struct_name,
    member_name,
    offset,
    offset_inst_va,
    image_base,
    size=None,
    min_sig_bytes=8,
    max_sig_bytes=96,
    max_instructions=64,
    extra_wildcard_offsets=None,
    allow_across_function_boundary=False,
    debug=False,
):
```

在其 `py_code` 中复用 `_build_signature_boundary_py_eval_helpers()`，把当前函数内 loop 改为与 `vfunc_sig` 相同的 `func.end_ea` 守卫：

```python
        f"allow_across_boundary = {bool(allow_across_function_boundary)}\n"
        + _build_signature_boundary_py_eval_helpers()
```

```python
"    func = idaapi.get_func(target_inst)\n"
"    if not func:\n"
"        result = json.dumps([])\n"
"    else:\n"
"        origin_seg = idaapi.getseg(target_inst)\n"
"        if not origin_seg or not (getattr(origin_seg, 'perm', 0) & SEGPERM_EXEC):\n"
"            result = json.dumps([])\n"
"        else:\n"
"            origin_seg_start = origin_seg.start_ea\n"
"            if allow_across_boundary:\n"
"                limit_end = target_inst + max_sig_bytes\n"
"            else:\n"
"                limit_end = min(func.end_ea, target_inst + max_sig_bytes)\n"
"            cursor = target_inst\n"
"            total = 0\n"
"            insts = []\n"
"            while cursor < limit_end and len(insts) < max_instructions and total < max_sig_bytes:\n"
"                if allow_across_boundary and cursor >= func.end_ea:\n"
"                    cursor, pad_insts, ok = _consume_padding(cursor, limit_end, origin_seg_start)\n"
"                    if not ok:\n"
"                        break\n"
```

保留现有 struct-offset wildcard 规则和 `offset_sig_disp` 语义。

- [ ] **Step 5: 实现 direct struct-member 透传与 YAML 标记**

修改 `_preprocess_direct_struct_offset_sig_via_mcp(...)` 签名：

```python
async def _preprocess_direct_struct_offset_sig_via_mcp(
    session,
    new_path,
    image_base,
    struct_member_name=None,
    struct_name=None,
    member_name=None,
    offset=None,
    offset_inst_va=None,
    size=None,
    old_path=None,
    allow_across_function_boundary=False,
    debug=False,
):
```

把生成调用改为：

```python
    payload = await preprocess_gen_struct_offset_sig_via_mcp(
        session=session,
        struct_name=resolved_struct_name,
        member_name=resolved_member_name,
        offset=offset,
        offset_inst_va=offset_inst_va,
        image_base=image_base,
        size=resolved_size,
        allow_across_function_boundary=allow_across_function_boundary,
        debug=debug,
    )
```

在 `preprocess_common_skill(...)` 的 struct-member 分支中读取 options：

```python
        struct_generation_options = (
            desired_fields_map.get(struct_member_name) or {}
        ).get("generation_options", {})
        allow_offset_boundary = struct_generation_options.get(
            "offset_sig_allow_across_function_boundary",
            False,
        )
```

调用 `_preprocess_direct_struct_offset_sig_via_mcp(...)` 时加入：

```python
                    allow_across_function_boundary=allow_offset_boundary,
```

在 `_assemble_symbol_payload(...)` 之前加入：

```python
        if allow_offset_boundary:
            struct_data["offset_sig_allow_across_function_boundary"] = True
```

- [ ] **Step 6: 回跑 `offset_sig` 相关测试**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_struct_offset_sig_via_mcp_generates_current_version_sig \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_struct_offset_sig_via_mcp_guards_cross_boundary_decode \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_direct_struct_offset_forwards_boundary_flag \
  tests.test_ida_analyze_util.TestGenerateYamlDesiredFieldsContract.test_preprocess_common_skill_writes_offset_sig_boundary_flag \
  -v
```

Expected:

```text
OK
```

- [ ] **Step 7: 提交 `offset_sig` 改动**

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "feat(preprocess): 支持offset签名跨函数边界"
```

## Task 5: 补齐 `func_sig` 所有公共调用点并做最终回归

**Files:**
- Modify: `tests/test_ida_analyze_util.py`
- Modify: `ida_analyze_util.py`

- [ ] **Step 1: 写 direct func 与 func-xrefs 透传 failing tests**

在 `tests/test_ida_analyze_util.py` 中追加：

```python
    async def test_preprocess_direct_func_sig_forwards_func_boundary_flag(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_get_func_basic_info_via_mcp",
            AsyncMock(
                return_value={
                    "func_va": "0x180123450",
                    "func_rva": "0x123450",
                    "func_size": "0x40",
                }
            ),
        ), patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(return_value={"func_sig": "48 89 ??"}),
        ) as mock_preprocess_gen_func_sig:
            result = await ida_analyze_util._preprocess_direct_func_sig_via_mcp(
                session=AsyncMock(),
                new_path="/tmp/Foo.windows.yaml",
                image_base=0x180000000,
                platform="windows",
                func_name="Foo",
                direct_func_va="0x180123450",
                require_func_sig=True,
                allow_func_sig_across_function_boundary=True,
                debug=True,
            )

        self.assertEqual("48 89 ??", result["func_sig"])
        mock_preprocess_gen_func_sig.assert_awaited_once_with(
            session=mock_preprocess_gen_func_sig.call_args.kwargs["session"],
            func_va=0x180123450,
            image_base=0x180000000,
            allow_across_function_boundary=True,
            debug=True,
        )

    async def test_preprocess_func_xrefs_forwards_func_boundary_flag(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "_find_function_addr_by_names_via_mcp",
            AsyncMock(return_value="0x180100000"),
        ), patch.object(
            ida_analyze_util,
            "_find_string_xref_funcs_via_mcp",
            AsyncMock(return_value={0x180123450}),
        ), patch.object(
            ida_analyze_util,
            "_find_signature_xref_funcs_via_mcp",
            AsyncMock(return_value=set()),
        ), patch.object(
            ida_analyze_util,
            "_load_func_addrs_from_yaml_names",
            return_value=set(),
        ), patch.object(
            ida_analyze_util,
            "_load_string_xref_func_addrs_from_yaml_names",
            AsyncMock(return_value=set()),
        ), patch.object(
            ida_analyze_util,
            "preprocess_gen_func_sig_via_mcp",
            AsyncMock(return_value={"func_sig": "48 89 ??"}),
        ) as mock_preprocess_gen_func_sig:
            result = await ida_analyze_util.preprocess_func_xrefs_via_mcp(
                session="session",
                func_name="Foo",
                xref_strings=["hello"],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                new_binary_dir="/tmp",
                platform="windows",
                image_base=0x180000000,
                allow_func_sig_across_function_boundary=True,
                debug=True,
            )

        self.assertEqual("Foo", result["func_name"])
        self.assertEqual("48 89 ??", result["func_sig"])
        mock_preprocess_gen_func_sig.assert_awaited_once_with(
            session="session",
            func_va=0x180123450,
            image_base=0x180000000,
            allow_across_function_boundary=True,
            debug=True,
        )
```

- [ ] **Step 2: 写 common skill 透传 failing test**

追加：

```python
    async def test_preprocess_common_skill_forwards_func_boundary_flag_to_direct_generation(
        self,
    ) -> None:
        func_name = "Foo"
        normalized_payload = {
            "found_call": [
                {
                    "func_name": func_name,
                    "insn_va": "0x180777700",
                    "insn_disasm": "call sub_180123450",
                }
            ],
            "found_funcptr": [],
            "found_vcall": [],
            "found_gv": [],
            "found_struct_offset": [],
        }
        target_detail_payload = {
            "func_name": "Caller",
            "func_va": "0x180555500",
            "disasm_code": "call sub_180123450",
            "procedure": "return Foo();",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "references").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{symbol_name_list}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                target_detail_payload,
            )

            with patch.object(
                ida_analyze_util,
                "_get_preprocessor_scripts_dir",
                return_value=preprocessor_dir,
            ), patch.object(
                ida_analyze_util,
                "create_openai_client",
                return_value=object(),
                create=True,
            ), patch.object(
                ida_analyze_util,
                "preprocess_func_sig_via_mcp",
                AsyncMock(return_value=None),
            ), patch.object(
                ida_analyze_util,
                "_load_llm_decompile_target_detail_via_mcp",
                AsyncMock(return_value=target_detail_payload),
            ), patch.object(
                ida_analyze_util,
                "_resolve_direct_call_target_via_mcp",
                AsyncMock(return_value="0x180123450"),
            ), patch.object(
                ida_analyze_util,
                "_preprocess_direct_func_sig_via_mcp",
                AsyncMock(
                    return_value={
                        "func_name": func_name,
                        "func_va": "0x180123450",
                        "func_sig": "48 89 ??",
                    }
                ),
            ) as mock_preprocess_direct_func_sig, patch.object(
                ida_analyze_util,
                "call_llm_decompile",
                create=True,
                new_callable=AsyncMock,
                return_value=normalized_payload,
            ), patch.object(
                ida_analyze_util,
                "write_func_yaml",
            ) as mock_write_func_yaml, patch.object(
                ida_analyze_util,
                "_rename_func_in_ida",
                AsyncMock(return_value=None),
            ):
                result = await ida_analyze_util.preprocess_common_skill(
                    session="session",
                    expected_outputs=[f"/tmp/{func_name}.windows.yaml"],
                    old_yaml_map={},
                    new_binary_dir="/tmp",
                    platform="windows",
                    image_base=0x180000000,
                    func_names=[func_name],
                    generate_yaml_desired_fields=[
                        (
                            func_name,
                            [
                                "func_name",
                                "func_sig",
                                "func_sig_allow_across_function_boundary: true",
                            ],
                        )
                    ],
                    llm_decompile_specs=[
                        (
                            func_name,
                            "prompt/call_llm_decompile.md",
                            "references/reference.yaml",
                        )
                    ],
                    llm_config={
                        "model": "gpt-4.1-mini",
                        "api_key": "test-api-key",
                    },
                    debug=True,
                )

        self.assertTrue(result)
        mock_preprocess_direct_func_sig.assert_awaited_once()
        self.assertTrue(
            mock_preprocess_direct_func_sig.call_args.kwargs[
                "allow_func_sig_across_function_boundary"
            ]
        )
        self.assertTrue(
            mock_write_func_yaml.call_args.args[1][
                "func_sig_allow_across_function_boundary"
            ]
        )
```

- [ ] **Step 3: 运行新增 `func_sig` 透传测试，确认失败**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_direct_func_sig_forwards_func_boundary_flag \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_func_xrefs_forwards_func_boundary_flag \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_common_skill_forwards_func_boundary_flag_to_direct_generation \
  -v
```

Expected:

```text
ERROR: test_preprocess_direct_func_sig_forwards_func_boundary_flag
ERROR: test_preprocess_func_xrefs_forwards_func_boundary_flag
FAIL: test_preprocess_common_skill_forwards_func_boundary_flag_to_direct_generation
```

- [ ] **Step 4: 实现所有 `func_sig` 透传点**

在 `_preprocess_direct_func_sig_via_mcp(...)` 的 func 生成调用中加入：

```python
            gen_data = await preprocess_gen_func_sig_via_mcp(
                session=session,
                func_va=resolved_func_va,
                image_base=image_base,
                allow_across_function_boundary=allow_func_sig_across_function_boundary,
                debug=debug,
            )
```

修改 `preprocess_func_xrefs_via_mcp(...)` 签名：

```python
async def preprocess_func_xrefs_via_mcp(
    session,
    func_name,
    xref_strings,
    xref_signatures,
    xref_funcs,
    exclude_funcs,
    exclude_strings,
    new_binary_dir,
    platform,
    image_base,
    vtable_class=None,
    allow_func_sig_across_function_boundary=False,
    debug=False,
):
```

并在它的生成调用中加入：

```python
    sig_data = await preprocess_gen_func_sig_via_mcp(
        session=session,
        func_va=target_va,
        image_base=image_base,
        allow_across_function_boundary=allow_func_sig_across_function_boundary,
        debug=debug,
    )
```

修改 `_preprocess_func_with_fast_paths(...)` 签名：

```python
async def _preprocess_func_with_fast_paths(
    session,
    *,
    func_name,
    target_output,
    old_path,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    func_xrefs_map,
    vtable_relations_map,
    normalized_mangled_class_names,
    allow_func_sig_across_function_boundary=False,
    debug=False,
):
```

并在 `preprocess_func_xrefs_via_mcp(...)` 调用中加入：

```python
            allow_func_sig_across_function_boundary=allow_func_sig_across_function_boundary,
```

修改 `preprocess_index_based_vfunc_via_mcp(...)` 签名：

```python
async def preprocess_index_based_vfunc_via_mcp(
    session,
    target_func_name,
    target_output,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    base_vfunc_name,
    inherit_vtable_class,
    generate_func_sig=True,
    allow_func_sig_across_function_boundary=False,
    debug=False,
):
```

并在它的生成调用中加入：

```python
        gen_data = await preprocess_gen_func_sig_via_mcp(
            session=session,
            func_va=func_va_int,
            image_base=image_base,
            allow_across_function_boundary=allow_func_sig_across_function_boundary,
            debug=debug,
        )
```

在 `preprocess_common_skill(...)` 的 inherit-vfunc fallback 调用中加入：

```python
                    allow_func_sig_across_function_boundary=generation_options.get(
                        "func_sig_allow_across_function_boundary",
                        False,
                    ),
```

在 `_preprocess_func_with_fast_paths(...)` 调用中加入：

```python
                allow_func_sig_across_function_boundary=generation_options.get(
                    "func_sig_allow_across_function_boundary",
                    False,
                ),
```

- [ ] **Step 5: 回跑 `func_sig` 透传与生成器测试**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_func_sig_via_mcp_defaults_to_function_boundary \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_func_sig_via_mcp_guards_cross_boundary_decode \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_direct_func_sig_forwards_func_boundary_flag \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_func_xrefs_forwards_func_boundary_flag \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_common_skill_forwards_func_boundary_flag_to_direct_generation \
  -v
```

Expected:

```text
OK
```

- [ ] **Step 6: 运行最终定向回归**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestGenerateYamlDesiredFieldsContract \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_gv_sig_via_mcp_guards_cross_boundary_decode \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_func_sig_via_mcp_defaults_to_function_boundary \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_func_sig_via_mcp_guards_cross_boundary_decode \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_vfunc_sig_via_mcp_generates_current_version_sig \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_vfunc_sig_via_mcp_accepts_match_count_within_limit \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_vfunc_sig_via_mcp_guards_cross_boundary_decode \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_struct_offset_sig_via_mcp_generates_current_version_sig \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_gen_struct_offset_sig_via_mcp_guards_cross_boundary_decode \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_direct_func_sig_forwards_func_boundary_flag \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_direct_func_sig_forwards_vfunc_boundary_flag \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_direct_struct_offset_forwards_boundary_flag \
  -v
```

Expected:

```text
OK
```

- [ ] **Step 7: 提交最终透传与回归**

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "fix(preprocess): 补齐签名跨边界透传"
```

## Final Verification

- [ ] **Step 1: 运行核心定向测试文件**

Run:

```bash
uv run python -m unittest tests.test_ida_analyze_util -v
```

Expected:

```text
OK
```

- [ ] **Step 2: 检查没有误改脚本声明**

Run:

```bash
git diff -- ida_preprocessor_scripts
```

Expected:

```text

```

也就是命令输出为空；本计划不批量修改现有预处理脚本。

- [ ] **Step 3: 检查最终 diff 只包含预期文件**

Run:

```bash
git status --short
```

Expected:

```text
 M ida_analyze_util.py
 M tests/test_ida_analyze_util.py
?? docs/superpowers/plans/2026-04-16-func-vfunc-offset-sig-allow-across-function-boundary.md
?? docs/superpowers/specs/2026-04-16-func-vfunc-offset-sig-allow-across-function-boundary-design.md
```

如果实施过程中按任务提交了代码，`git status --short` 可能只剩文档文件或完全干净；这也是可接受结果。
