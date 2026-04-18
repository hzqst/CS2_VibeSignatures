# Function Disasm Chunk Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `generate_reference_yaml.py` 与 `ida_analyze_util.py` 统一函数详情导出逻辑，按 function chunk 完整收集 `disasm_code`，并在可用时插入 IDA 注释行。

**Architecture:** 先在 `ida_analyze_util.py` 中新增共享的 IDA `py_eval` builder，用字符串级单元测试锁定 chunk 枚举、控制流遍历、注释采集与 fallback 片段。然后分别把 `generate_reference_yaml.py` 与 `_export_function_detail_via_mcp(...)` 切到共享 builder，并更新 `TestLlmDecompileSupport` 中依赖旧魔法字符串的 MCP stub。最后用定向 `unittest` 验证 reference YAML 路径与 `LLM_DECOMPILE` 路径都走同一 builder，且不再依赖 `idautils.FuncItems(func.start_ea)` 作为唯一导出策略。

**Tech Stack:** Python 3、`unittest`、`unittest.mock.AsyncMock`、IDA MCP `py_eval`、`yaml.safe_dump`

---

## 实际落地调整（2026-04-18）

- 共享 builder 的最终 chunk fallback 已调整为：`idautils.Chunks`（完整枚举成功才采纳）-> `ida_funcs.func_tail_iterator_t` -> 单区间 `[(func.start_ea, func.end_ea)]`。
- `idautils.Chunks` 路径使用临时列表收集，避免“枚举中途异常导致保留部分 chunk”。
- 两套 chunk API 失败后的输出仍走 chunk/range code heads 渲染路径，不再使用旧 `idautils.FuncItems(func.start_ea)` 线性 fallback。
- 文档中若出现早期 `FuncItems` fallback 片段，视为历史草案，不代表当前实现。

---

## File Structure

- Modify: `ida_analyze_util.py`
  - 新增 `build_function_detail_export_py_eval(func_va_int: int) -> str`
  - 在共享 builder 内实现 chunk 枚举、控制流遍历、注释读取、fallback 线性导出
  - 让 `_export_function_detail_via_mcp(...)` 复用该 builder
- Modify: `generate_reference_yaml.py`
  - 从 `ida_analyze_util` 导入共享 builder
  - 让 `export_reference_payload_via_mcp(...)` 复用同一 builder
- Modify: `tests/test_ida_analyze_util.py`
  - 新增共享 builder 的字符串级测试
  - 新增 `_export_function_detail_via_mcp(...)` 走共享 builder 的测试
  - 更新 `TestLlmDecompileSupport` 中的 MCP stub，改为匹配共享 builder 输出
- Modify: `tests/test_generate_reference_yaml.py`
  - 新增 `export_reference_payload_via_mcp(...)` 走共享 builder 的测试
- Create: `docs/superpowers/plans/2026-04-17-function-disasm-chunk-export.md`
  - 当前实现计划文档

**仓库约束：**

- 实施阶段只跑定向 `unittest`，不要先跑全量 build
- 本计划只改共享导出器与测试，不改 `ida_preprocessor_scripts/*.py`
- 当前会话默认不自动提交；若执行环境允许提交，可使用每个任务末尾给出的 commit 命令

## Shared Contract

实施时统一使用以下函数名，避免任务之间写出不一致接口：

```python
def build_function_detail_export_py_eval(func_va_int: int) -> str:
    ...


async def export_reference_payload_via_mcp(
    session: Any,
    *,
    func_name: str,
    func_va: str,
    debug: bool = False,
) -> dict[str, str]:
    ...


async def _export_function_detail_via_mcp(session, func_name, func_va, debug=False):
    ...
```

## Task 1: 在 `ida_analyze_util.py` 锁定共享 builder 契约

**Files:**
- Modify: `tests/test_ida_analyze_util.py`
- Modify: `ida_analyze_util.py`

- [ ] **Step 1: 写共享 builder 的 failing tests**

在 `tests/test_ida_analyze_util.py` 里、`class TestLlmDecompileSupport(unittest.IsolatedAsyncioTestCase):` 之前插入下面这个测试类：

```python
class TestFunctionDetailExportPyEvalBuilder(unittest.IsolatedAsyncioTestCase):
    def test_build_function_detail_export_py_eval_contains_chunk_comment_and_fallback_logic(
        self,
    ) -> None:
        py_code = ida_analyze_util.build_function_detail_export_py_eval(0x180123450)

        self.assertIn("for start_ea, end_ea in idautils.Chunks(func.start_ea):", py_code)
        self.assertIn("pending_eas = [int(func.start_ea)]", py_code)
        self.assertIn("mnem == 'jmp'", py_code)
        self.assertIn("mnem.startswith('j')", py_code)
        self.assertIn("idc.get_cmt(ea, repeatable)", py_code)
        self.assertIn("get_extra_cmt = getattr(idc, 'get_extra_cmt', None)", py_code)
        self.assertIn("for ea in idautils.FuncItems(func.start_ea):", py_code)

    async def test_export_function_detail_via_mcp_uses_shared_py_eval_builder(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "func_name": "sub_180123450",
                "func_va": "0x180123450",
                "disasm_code": "text:180123450 push rbp",
                "procedure": "",
            }
        )

        payload = await ida_analyze_util._export_function_detail_via_mcp(
            session,
            "CNetworkMessages_FindNetworkGroup",
            "0x180123450",
            debug=False,
        )

        expected_py_code = ida_analyze_util.build_function_detail_export_py_eval(0x180123450)
        session.call_tool.assert_awaited_once_with(
            name="py_eval",
            arguments={"code": expected_py_code},
        )
        self.assertEqual(
            {
                "func_name": "CNetworkMessages_FindNetworkGroup",
                "func_va": "0x180123450",
                "disasm_code": "text:180123450 push rbp",
                "procedure": "",
            },
            payload,
        )
```

- [ ] **Step 2: 运行新增测试，确认当前实现失败**

Run:

```bash
uv run python -m unittest tests.test_ida_analyze_util.TestFunctionDetailExportPyEvalBuilder -v
```

Expected:

```text
ERROR: module 'ida_analyze_util' has no attribute 'build_function_detail_export_py_eval'
```

- [ ] **Step 3: 在 `ida_analyze_util.py` 实现共享 builder**

在 `_find_function_addr_by_names_via_mcp(...)` 与 `_export_function_detail_via_mcp(...)` 之间插入以下函数：

```python
def build_function_detail_export_py_eval(func_va_int: int) -> str:
    return textwrap.dedent(
        f"""
        import ida_bytes, ida_funcs, ida_lines, ida_segment, idautils, idc, json
        try:
            import ida_hexrays
        except Exception:
            ida_hexrays = None

        func_ea = {func_va_int}

        def _collect_chunk_ranges(func):
            chunk_ranges = []
            try:
                for start_ea, end_ea in idautils.Chunks(func.start_ea):
                    start_ea = int(start_ea)
                    end_ea = int(end_ea)
                    if start_ea < end_ea:
                        chunk_ranges.append((start_ea, end_ea))
            except Exception:
                chunk_ranges = []
            if not chunk_ranges:
                chunk_ranges = [(int(func.start_ea), int(func.end_ea))]
            return sorted(set(chunk_ranges))

        def _find_chunk_end(ea, chunk_ranges):
            for start_ea, end_ea in chunk_ranges:
                if start_ea <= ea < end_ea:
                    return end_ea
            return None

        def _is_in_chunk_ranges(ea, chunk_ranges):
            return _find_chunk_end(ea, chunk_ranges) is not None

        def _format_address(ea):
            seg = ida_segment.getseg(ea)
            seg_name = ida_segment.get_segm_name(seg) if seg else ''
            return f"{{seg_name}}:{{ea:016X}}" if seg_name else f"{{ea:016X}}"

        def _iter_comment_lines(ea):
            seen = set()
            for repeatable in (0, 1):
                try:
                    comment = idc.get_cmt(ea, repeatable)
                except Exception:
                    comment = None
                if not comment:
                    continue
                text = ida_lines.tag_remove(comment).strip()
                if text and text not in seen:
                    seen.add(text)
                    yield text

            get_extra_cmt = getattr(idc, "get_extra_cmt", None)
            if get_extra_cmt is None:
                return

            for index in range(-10, 11):
                try:
                    comment = get_extra_cmt(ea, index)
                except Exception:
                    continue
                if not comment:
                    continue
                text = ida_lines.tag_remove(comment).strip()
                if text and text not in seen:
                    seen.add(text)
                    yield text

        def _iter_chunk_code_heads(chunk_ranges):
            for start_ea, end_ea in chunk_ranges:
                ea = int(start_ea)
                while ea != idc.BADADDR and ea < end_ea:
                    flags = ida_bytes.get_flags(ea)
                    if ida_bytes.is_code(flags):
                        yield ea
                    next_ea = idc.next_head(ea, end_ea)
                    if next_ea == idc.BADADDR or next_ea <= ea:
                        break
                    ea = next_ea

        def get_disasm(start_ea):
            func = ida_funcs.get_func(start_ea)
            if func is None:
                return ''

            def _fallback_linear_disasm():
                lines = []
                for ea in idautils.FuncItems(func.start_ea):
                    if ea < func.start_ea or ea >= func.end_ea:
                        continue
                    address_text = _format_address(ea)
                    disasm_line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or '').strip()
                    if disasm_line:
                        lines.append(f"{{address_text}}                 {{disasm_line}}")
                return '\\n'.join(lines).strip()

            try:
                chunk_ranges = _collect_chunk_ranges(func)
                pending_eas = [int(func.start_ea)]
                visited_eas = set()
                collected_eas = set()
                code_head_count = sum(1 for _ in _iter_chunk_code_heads(chunk_ranges))
                max_steps = code_head_count * 4 + 256
                steps = 0

                while pending_eas and steps < max_steps:
                    ea = int(pending_eas.pop())
                    while True:
                        if not _is_in_chunk_ranges(ea, chunk_ranges):
                            break
                        flags = ida_bytes.get_flags(ea)
                        if not ida_bytes.is_code(flags):
                            break
                        if ea in visited_eas:
                            break

                        visited_eas.add(ea)
                        collected_eas.add(ea)
                        steps += 1

                        mnem = (idc.print_insn_mnem(ea) or '').lower()
                        refs = [
                            int(ref)
                            for ref in idautils.CodeRefsFrom(ea, False)
                            if _is_in_chunk_ranges(int(ref), chunk_ranges)
                        ]
                        chunk_end = _find_chunk_end(ea, chunk_ranges)
                        next_ea = idc.next_head(ea, chunk_end) if chunk_end is not None else idc.BADADDR

                        if mnem in ('ret', 'retn', 'retf', 'iret', 'iretd', 'iretq', 'int3', 'hlt', 'ud2'):
                            break
                        if mnem == 'jmp':
                            for ref in reversed(refs):
                                if ref not in visited_eas:
                                    pending_eas.append(ref)
                            break
                        if mnem.startswith('j'):
                            for ref in reversed(refs):
                                if ref not in visited_eas:
                                    pending_eas.append(ref)
                            if next_ea == idc.BADADDR or next_ea <= ea:
                                break
                            ea = int(next_ea)
                            continue
                        if next_ea == idc.BADADDR or next_ea <= ea:
                            break
                        ea = int(next_ea)

                for ea in _iter_chunk_code_heads(chunk_ranges):
                    collected_eas.add(int(ea))

                lines = []
                for ea in sorted(collected_eas):
                    address_text = _format_address(ea)
                    for comment in _iter_comment_lines(ea):
                        lines.append(f"{{address_text}}                 ; {{comment}}")
                    disasm_line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or '').strip()
                    if disasm_line:
                        lines.append(f"{{address_text}}                 {{disasm_line}}")
                return '\\n'.join(lines).strip()
            except Exception:
                return _fallback_linear_disasm()

        def get_pseudocode(start_ea):
            if ida_hexrays is None:
                return ''
            try:
                if not ida_hexrays.init_hexrays_plugin():
                    return ''
                cfunc = ida_hexrays.decompile(start_ea)
            except Exception:
                return ''
            if not cfunc:
                return ''
            return '\\n'.join(ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode())

        func = ida_funcs.get_func(func_ea)
        if func is None:
            raise ValueError(f"Function not found: {{hex(func_ea)}}")

        func_start = int(func.start_ea)
        result = json.dumps(
            {{
                "func_name": ida_funcs.get_func_name(func_start) or f"sub_{{func_start:X}}",
                "func_va": hex(func_start),
                "disasm_code": get_disasm(func_start),
                "procedure": get_pseudocode(func_start),
            }}
        )
        """
    ).strip() + "\n"
```

- [ ] **Step 4: 让 `_export_function_detail_via_mcp(...)` 调用共享 builder**

把 `ida_analyze_util.py` 里 `_export_function_detail_via_mcp(...)` 中手写 `py_code = (...)` 的整段替换为：

```python
    py_code = build_function_detail_export_py_eval(func_va_int)
```

其余 `session.call_tool(...)`、payload 校验、`None` 返回语义全部保持不变。

- [ ] **Step 5: 重新运行 Task 1 测试，确认通过**

Run:

```bash
uv run python -m unittest tests.test_ida_analyze_util.TestFunctionDetailExportPyEvalBuilder -v
```

Expected:

```text
OK
```

- [ ] **Step 6: 记录检查点（若当前执行环境允许提交）**

Run:

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "fix(ida): 统一函数详情导出builder"
```

Expected:

```text
[current-branch ...] fix(ida): 统一函数详情导出builder
```

## Task 2: 让 reference YAML 导出路径复用共享 builder

**Files:**
- Modify: `generate_reference_yaml.py`
- Modify: `tests/test_generate_reference_yaml.py`

- [ ] **Step 1: 写 `export_reference_payload_via_mcp(...)` 的 failing test**

在 `tests/test_generate_reference_yaml.py` 的 `class TestExportReferencePayload(unittest.IsolatedAsyncioTestCase):` 中追加下面的测试：

```python
    async def test_export_reference_payload_uses_shared_py_eval_builder(self) -> None:
        session = AsyncMock()
        session.call_tool.return_value = _py_eval_payload(
            {
                "func_name": "sub_180123450",
                "func_va": "0x180123450",
                "disasm_code": "text:180123450 push rbp",
                "procedure": "",
            }
        )

        with patch.object(
            generate_reference_yaml,
            "build_function_detail_export_py_eval",
            return_value="PY-CODE",
        ) as mock_builder:
            payload = await generate_reference_yaml.export_reference_payload_via_mcp(
                session=session,
                func_name="CNetworkMessages_FindNetworkGroup",
                func_va="0x180123450",
                debug=False,
            )

        mock_builder.assert_called_once_with(0x180123450)
        session.call_tool.assert_awaited_once_with(
            name="py_eval",
            arguments={"code": "PY-CODE"},
        )
        self.assertEqual(
            {
                "func_name": "CNetworkMessages_FindNetworkGroup",
                "func_va": "0x180123450",
                "disasm_code": "text:180123450 push rbp",
                "procedure": "",
            },
            payload,
        )
```

- [ ] **Step 2: 运行 reference YAML 定向测试，确认当前实现失败**

Run:

```bash
uv run python -m unittest tests.test_generate_reference_yaml.TestExportReferencePayload -v
```

Expected:

```text
AttributeError: <module 'generate_reference_yaml' ...> does not have the attribute 'build_function_detail_export_py_eval'
```

- [ ] **Step 3: 修改 `generate_reference_yaml.py` 使用共享 builder**

把顶部 import 从：

```python
from ida_analyze_util import parse_mcp_result
```

改为：

```python
from ida_analyze_util import build_function_detail_export_py_eval, parse_mcp_result
```

再把 `export_reference_payload_via_mcp(...)` 中手写 `py_code = (...)` 的整段替换为：

```python
    py_code = build_function_detail_export_py_eval(func_va_int)
```

其余 `ReferenceGenerationError` 语义、payload 校验与 `procedure` 规范化逻辑保持不变。

- [ ] **Step 4: 重新运行 reference YAML 定向测试，确认通过**

Run:

```bash
uv run python -m unittest tests.test_generate_reference_yaml.TestExportReferencePayload -v
```

Expected:

```text
OK
```

- [ ] **Step 5: 记录检查点（若当前执行环境允许提交）**

Run:

```bash
git add generate_reference_yaml.py tests/test_generate_reference_yaml.py
git commit -m "fix(reference): 复用共享反汇编导出builder"
```

Expected:

```text
[current-branch ...] fix(reference): 复用共享反汇编导出builder
```

## Task 3: 更新 `LLM_DECOMPILE` 回归测试，移除旧魔法字符串依赖

**Files:**
- Modify: `tests/test_ida_analyze_util.py`
- Modify: `ida_analyze_util.py`

- [ ] **Step 1: 让 `TestLlmDecompileSupport` 先按共享 builder 断言失败**

在 `tests/test_ida_analyze_util.py` 中，修改这两个测试里的 `_session_call_tool(...)` stub：

- `test_preprocess_common_skill_uses_llm_decompile_vcall_fallback_for_func_yaml`
- `test_preprocess_common_skill_uses_llm_decompile_direct_call_fallback_without_vtable_relation`

把：

```python
                if "'disasm_code': get_disasm(func_start)" in code:
                    return _py_eval_payload(target_detail_payload)
```

改成：

```python
            expected_export_code = ida_analyze_util.build_function_detail_export_py_eval(
                int(target_detail_payload["func_va"], 0)
            )

            async def _session_call_tool(*, name, arguments):
                self.assertEqual("py_eval", name)
                code = arguments["code"]
                if "candidate_names =" in code:
                    return _py_eval_payload(
                        [
                            {
                                "name": target_detail_payload["func_name"],
                                "func_va": target_detail_payload["func_va"],
                            }
                        ]
                    )
                if code == expected_export_code:
                    return _py_eval_payload(target_detail_payload)
                raise AssertionError(f"unexpected py_eval code: {code}")
```

先只改测试，不改其他断言，让它暴露所有仍依赖旧字符串的地方。

- [ ] **Step 2: 运行 `LLM_DECOMPILE` 定向回归测试，确认失败点收敛**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_common_skill_uses_llm_decompile_vcall_fallback_for_func_yaml \
  tests.test_ida_analyze_util.TestLlmDecompileSupport.test_preprocess_common_skill_uses_llm_decompile_direct_call_fallback_without_vtable_relation \
  -v
```

Expected:

```text
FAIL or ERROR only if there are remaining stale string checks or builder wiring mismatches
```

- [ ] **Step 3: 清理所有残留的旧字符串匹配**

运行下面的搜索命令，确认没有残留对旧导出片段的硬编码依赖：

```bash
rg -n "\"'disasm_code': get_disasm\\(func_start\\)\"" tests/test_ida_analyze_util.py tests/test_generate_reference_yaml.py
```

Expected:

```text
no output
```

如果 `rg` 仍有输出，把对应 stub 全部替换成 `build_function_detail_export_py_eval(...)` 的精确比较；应用代码不需要新增任何分支。

- [ ] **Step 4: 运行合并后的定向回归测试**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestFunctionDetailExportPyEvalBuilder \
  tests.test_ida_analyze_util.TestLlmDecompileSupport \
  tests.test_generate_reference_yaml.TestExportReferencePayload \
  -v
```

Expected:

```text
OK
```

- [ ] **Step 5: 记录检查点（若当前执行环境允许提交）**

Run:

```bash
git add tests/test_ida_analyze_util.py tests/test_generate_reference_yaml.py ida_analyze_util.py generate_reference_yaml.py
git commit -m "test(ida): 更新反汇编导出回归断言"
```

Expected:

```text
[current-branch ...] test(ida): 更新反汇编导出回归断言
```

## Manual Acceptance

代码与定向 `unittest` 全部通过后，在可连接 IDA MCP 的环境中做一次手工验收：

- 重新生成：

```bash
uv run generate_reference_yaml.py -gamever 14141 -module server -platform linux -func_name ParticleTestStart_CommandHandler -mcp_host 127.0.0.1 -mcp_port 13337
```

- 打开输出文件：

```bash
sed -n '1,260p' ida_preprocessor_scripts/references/server/ParticleTestStart_CommandHandler.linux.yaml
```

- 预期：
  - `disasm_code` 包含离散 chunk 中的地址段，例如 `0x158C520`、`0x158C570`、`0x158C588`、`0x158C5A0`
  - 指令仍按地址升序输出
  - 可读取注释时，注释行位于对应指令之前
  - `procedure` 字段保持现有行为

## Self-Review Checklist

实施前和实施后按下面顺序自检：

1. 手动通读本计划，确认没有模糊表述、占位词或“后面再补”之类的句子。
2. 对实现文件运行下面的脚本，确认没有残留常见占位标记：

```bash
python - <<'PY'
from pathlib import Path

markers = ["T" + "BD", "TO" + "DO", "FIX" + "ME"]
paths = [
    Path("ida_analyze_util.py"),
    Path("generate_reference_yaml.py"),
    Path("tests/test_ida_analyze_util.py"),
    Path("tests/test_generate_reference_yaml.py"),
]

for path in paths:
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker in text:
            raise SystemExit(f"{path}: found {marker}")
PY
```

预期无输出；如果有输出，必须在继续前改成具体实现或具体测试代码。
