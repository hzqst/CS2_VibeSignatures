# IDB String Setup Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Change IDA string enumeration so unset or blank `CS2VIBE_STRING_MIN_LENGTH` skips `Strings.setup`, while explicit values use a per-IDB netnode guard that reruns setup when the effective `minlen` changes.

**Architecture:** Keep `ida_analyze_util.py` as the only shared code-generation entry point for `idautils.Strings`. Replace the old always-setup helper with an enumerator helper that returns either a plain `Strings(default_setup=False)` iterator or a guarded setup block backed by `ida_netnode`. Existing preprocessors continue to call shared helpers so matching, xref collection, and YAML output behavior stay unchanged.

**Tech Stack:** Python 3.10+, IDAPython `idautils.Strings`, IDAPython `ida_netnode.netnode`, `unittest`, `uv`

---

## File Structure

- Modify: `ida_analyze_util.py`
  - Change env parsing to return `None` for unset or blank `CS2VIBE_STRING_MIN_LENGTH`.
  - Add a unified `_build_ida_strings_enumerator_py_lines()` helper.
  - Generate netnode guarded setup code only when `min_length` is an integer.
  - Keep `_build_ida_exact_string_index_py_lines()` as the exact-match indexing helper, but make it call the new enumerator helper.
  - Update `_collect_xref_func_starts_for_string()` to call the new enumerator helper.
- Modify: `ida_preprocessor_scripts/_define_inputfunc.py`
  - Replace `_build_ida_strings_setup_py_lines` import and usage with `_build_ida_strings_enumerator_py_lines`.
- Modify: `ida_preprocessor_scripts/find-CBaseFilter_InputTestActivator.py`
  - Replace `_build_ida_strings_setup_py_lines` import and usage with `_build_ida_strings_enumerator_py_lines`.
- Modify: `ida_preprocessor_scripts/_registerconcommand.py`
  - Keep `_build_ida_exact_string_index_py_lines()` usage; behavior changes through the shared helper.
- Modify: `ida_preprocessor_scripts/_register_event_listener_abstract.py`
  - Keep `_build_ida_exact_string_index_py_lines()` usage; behavior changes through the shared helper.
- Modify: `tests/test_ida_analyze_util.py`
  - Replace default-minlen assertions with no-setup default assertions.
  - Add explicit env netnode guard assertions.
- Modify: `tests/test_define_inputfunc_preprocessor.py`
  - Update generated `py_eval` assertions for default no-setup and explicit setup.
- Modify: `tests/test_registerconcommand_preprocessor.py`
  - Update exact-index generated code assertions for default no-setup and explicit setup.
- Modify: `tests/test_register_event_listener_abstract_preprocessor.py`
  - Update generated code assertions and fake execution expectations.
- Modify: `tests/test_ida_preprocessor_scripts.py`
  - Update `find-CBaseFilter_InputTestActivator.py` Linux fallback assertions.
- Modify: `README.md`
  - Document new env semantics and IDB-level setup state.

### Task 1: Rewrite shared string-enumeration tests

**Files:**
- Modify: `tests/test_ida_analyze_util.py:2008`

- [ ] **Step 1: Replace `TestIdaStringEnumerationSupport` with tests for the new config and enumerator helper**

Replace the whole `TestIdaStringEnumerationSupport` class with:

```python
class TestIdaStringEnumerationSupport(unittest.TestCase):
    def test_resolve_ida_string_min_length_config_skips_setup_when_unset_or_blank(
        self,
    ) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(
                ida_analyze_util._resolve_ida_string_min_length_config()
            )

        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": ""},
            clear=True,
        ):
            self.assertIsNone(
                ida_analyze_util._resolve_ida_string_min_length_config()
            )

        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "   "},
            clear=True,
        ):
            self.assertIsNone(
                ida_analyze_util._resolve_ida_string_min_length_config()
            )

    def test_resolve_ida_string_min_length_config_handles_invalid_zero_and_valid_value(
        self,
    ) -> None:
        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "invalid"},
            clear=True,
        ):
            self.assertEqual(
                4,
                ida_analyze_util._resolve_ida_string_min_length_config(),
            )

        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "0"},
            clear=True,
        ):
            self.assertEqual(
                4,
                ida_analyze_util._resolve_ida_string_min_length_config(),
            )

        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "6"},
            clear=True,
        ):
            self.assertEqual(
                6,
                ida_analyze_util._resolve_ida_string_min_length_config(),
            )

    def test_build_ida_strings_enumerator_py_lines_skips_setup_by_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            py_lines = ida_analyze_util._build_ida_strings_enumerator_py_lines()

        self.assertEqual(
            ["strings = idautils.Strings(default_setup=False)"],
            py_lines,
        )

    def test_build_ida_strings_enumerator_py_lines_skips_setup_for_blank_env(
        self,
    ) -> None:
        with patch.dict(
            os.environ,
            {ida_analyze_util.IDA_STRING_MIN_LENGTH_ENV_VAR: " "},
            clear=True,
        ):
            py_lines = ida_analyze_util._build_ida_strings_enumerator_py_lines()

        self.assertEqual(
            ["strings = idautils.Strings(default_setup=False)"],
            py_lines,
        )

    def test_build_ida_strings_enumerator_py_lines_uses_netnode_guard_for_env_min_length(
        self,
    ) -> None:
        with patch.dict(
            os.environ,
            {ida_analyze_util.IDA_STRING_MIN_LENGTH_ENV_VAR: "8"},
            clear=True,
        ):
            py_lines = ida_analyze_util._build_ida_strings_enumerator_py_lines()

        code = "\n".join(py_lines)
        self.assertIn("import ida_netnode, json", code)
        self.assertIn("strings = idautils.Strings(default_setup=False)", code)
        self.assertIn(
            "CS2VIBE_STRING_SETUP_STATE_NODE = '$CS2VIBE_STRING_SETUP_STATE'",
            code,
        )
        self.assertIn(
            "expected_state = {'version': 1, 'minlen': 8, 'strtypes': 'STRTYPE_C'}",
            code,
        )
        self.assertIn(
            "if _cs2vibe_read_string_setup_state() != expected_state:",
            code,
        )
        self.assertIn(
            "    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=8)",
            code,
        )
        self.assertIn(
            "    _cs2vibe_write_string_setup_state(expected_state)",
            code,
        )

    def test_build_ida_strings_enumerator_py_lines_supports_explicit_none(self) -> None:
        with patch.dict(
            os.environ,
            {ida_analyze_util.IDA_STRING_MIN_LENGTH_ENV_VAR: "8"},
            clear=True,
        ):
            py_lines = ida_analyze_util._build_ida_strings_enumerator_py_lines(
                min_length=None,
            )

        self.assertEqual(
            ["strings = idautils.Strings(default_setup=False)"],
            py_lines,
        )

    def test_build_ida_strings_enumerator_py_lines_supports_custom_var_name(
        self,
    ) -> None:
        with patch.dict(os.environ, {}, clear=True):
            py_lines = ida_analyze_util._build_ida_strings_enumerator_py_lines(
                min_length=6,
                strings_var_name="ida_strings",
            )

        code = "\n".join(py_lines)
        self.assertIn("ida_strings = idautils.Strings(default_setup=False)", code)
        self.assertIn(
            "ida_strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=6)",
            code,
        )

    def test_build_ida_exact_string_index_py_lines_skips_setup_by_default(
        self,
    ) -> None:
        with patch.dict(os.environ, {}, clear=True):
            py_lines = ida_analyze_util._build_ida_exact_string_index_py_lines()

        self.assertEqual(
            [
                "exact_string_hits = {text: [] for text in target_strings if text}",
                "strings = idautils.Strings(default_setup=False)",
                "for item in strings:",
                "    try:",
                "        text = str(item)",
                "        ea = int(item.ea)",
                "    except Exception:",
                "        continue",
                "    if text in exact_string_hits:",
                "        exact_string_hits[text].append(ea)",
            ],
            py_lines,
        )

    def test_build_ida_exact_string_index_py_lines_reads_env_min_length(self) -> None:
        with patch.dict(
            os.environ,
            {ida_analyze_util.IDA_STRING_MIN_LENGTH_ENV_VAR: "8"},
            clear=True,
        ):
            py_lines = ida_analyze_util._build_ida_exact_string_index_py_lines()

        code = "\n".join(py_lines)
        self.assertIn(
            "exact_string_hits = {text: [] for text in target_strings if text}",
            code,
        )
        self.assertIn("strings = idautils.Strings(default_setup=False)", code)
        self.assertIn(
            "strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=8)",
            code,
        )
        self.assertIn("for item in strings:", code)
        self.assertEqual(1, code.count("for item in strings:"))

    def test_build_ida_exact_string_index_py_lines_supports_custom_var_names(
        self,
    ) -> None:
        with patch.dict(os.environ, {}, clear=True):
            py_lines = ida_analyze_util._build_ida_exact_string_index_py_lines(
                target_texts_var_name="target_texts",
                result_var_name="result_map",
                min_length=6,
            )

        code = "\n".join(py_lines)
        self.assertIn("result_map = {text: [] for text in target_texts if text}", code)
        self.assertIn("strings = idautils.Strings(default_setup=False)", code)
        self.assertIn(
            "strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=6)",
            code,
        )
        self.assertIn("for item in strings:", code)
        self.assertIn("    if text in result_map:", code)
        self.assertIn("        result_map[text].append(ea)", code)
```

- [ ] **Step 2: Run the shared helper tests and verify they fail before implementation**

Run:

```bash
uv run python -m unittest tests.test_ida_analyze_util.TestIdaStringEnumerationSupport
```

Expected: FAIL with `AttributeError` for `_resolve_ida_string_min_length_config` or `_build_ida_strings_enumerator_py_lines`.

### Task 2: Implement shared enumerator and netnode guarded setup

**Files:**
- Modify: `ida_analyze_util.py:210-285`
- Test: `tests/test_ida_analyze_util.py`

- [ ] **Step 1: Replace the old string setup helper block in `ida_analyze_util.py`**

Replace the constants and helper functions from `DEFAULT_IDA_STRING_MIN_LENGTH` through `_build_ida_exact_string_index_py_lines()` with:

```python
DEFAULT_IDA_STRING_MIN_LENGTH = 4
IDA_STRING_MIN_LENGTH_ENV_VAR = "CS2VIBE_STRING_MIN_LENGTH"
IDA_STRING_SETUP_STATE_NODE = "$CS2VIBE_STRING_SETUP_STATE"
IDA_STRING_SETUP_STATE_VERSION = 1
IDA_STRING_SETUP_STRTYPES_LABEL = "STRTYPE_C"
_IDA_STRING_MIN_LENGTH_AUTO = object()


def _coerce_ida_string_min_length(value):
    try:
        min_length = int(str(value).strip())
    except (TypeError, ValueError):
        return DEFAULT_IDA_STRING_MIN_LENGTH
    if min_length < 1:
        return DEFAULT_IDA_STRING_MIN_LENGTH
    return min_length


def _resolve_ida_string_min_length_config():
    raw_min_length = os.getenv(IDA_STRING_MIN_LENGTH_ENV_VAR)
    if raw_min_length is None:
        return None
    if not str(raw_min_length).strip():
        return None
    return _coerce_ida_string_min_length(raw_min_length)


def _resolve_ida_string_min_length():
    resolved = _resolve_ida_string_min_length_config()
    if resolved is None:
        return DEFAULT_IDA_STRING_MIN_LENGTH
    return resolved


def _resolve_ida_string_min_length_for_py_lines(min_length):
    if min_length is _IDA_STRING_MIN_LENGTH_AUTO:
        return _resolve_ida_string_min_length_config()
    if min_length is None:
        return None
    return _coerce_ida_string_min_length(min_length)


def _build_ida_strings_enumerator_py_lines(
    *,
    min_length=_IDA_STRING_MIN_LENGTH_AUTO,
    strings_var_name: str = "strings",
) -> list[str]:
    """Return py_eval code lines for IDA string enumeration.

    ``None`` min_length means using the IDB's current string-list state without
    calling ``Strings.setup``. Integer min_length emits a netnode-guarded setup.
    """
    resolved_min_length = _resolve_ida_string_min_length_for_py_lines(min_length)
    lines = [
        f"{strings_var_name} = idautils.Strings(default_setup=False)",
    ]
    if resolved_min_length is None:
        return lines

    expected_state = {
        "version": IDA_STRING_SETUP_STATE_VERSION,
        "minlen": resolved_min_length,
        "strtypes": IDA_STRING_SETUP_STRTYPES_LABEL,
    }
    return [
        "import ida_netnode, json",
        *lines,
        f"CS2VIBE_STRING_SETUP_STATE_NODE = {IDA_STRING_SETUP_STATE_NODE!r}",
        "def _cs2vibe_string_setup_node():",
        "    return ida_netnode.netnode(CS2VIBE_STRING_SETUP_STATE_NODE, 0, True)",
        "def _cs2vibe_read_string_setup_state():",
        "    try:",
        "        raw = _cs2vibe_string_setup_node().valobj()",
        "        if isinstance(raw, bytes):",
        "            raw = raw.decode('utf-8', errors='ignore')",
        "        if raw is None or raw == '':",
        "            return None",
        "        return json.loads(str(raw))",
        "    except Exception:",
        "        return None",
        "def _cs2vibe_write_string_setup_state(state):",
        "    try:",
        "        payload = json.dumps(state, sort_keys=True)",
        "        _cs2vibe_string_setup_node().set(payload)",
        "    except Exception:",
        "        pass",
        f"expected_state = {expected_state!r}",
        "if _cs2vibe_read_string_setup_state() != expected_state:",
        (
            f"    {strings_var_name}.setup("
            "strtypes=[ida_nalt.STRTYPE_C], "
            f"minlen={resolved_min_length}"
            ")"
        ),
        "    _cs2vibe_write_string_setup_state(expected_state)",
    ]


def _build_ida_strings_setup_py_lines(
    *,
    min_length=_IDA_STRING_MIN_LENGTH_AUTO,
    strings_var_name: str = "strings",
) -> list[str]:
    return _build_ida_strings_enumerator_py_lines(
        min_length=min_length,
        strings_var_name=strings_var_name,
    )


def _build_ida_exact_string_index_py_lines(
    target_texts_var_name="target_strings",
    result_var_name="exact_string_hits",
    min_length=_IDA_STRING_MIN_LENGTH_AUTO,
    *,
    target_strings_var_name=None,
    hits_var_name=None,
):
    """Return py_eval code lines that build `{text: [ea_list]}` exact-hit index.

    调用方需先在 py_eval 代码中导入 ``idautils`` 与 ``ida_nalt``；本 helper 在
    显式 minlen 配置时会额外注入 ``ida_netnode`` 与 ``json`` import。
    """
    if target_strings_var_name is not None:
        target_texts_var_name = target_strings_var_name
    if hits_var_name is not None:
        result_var_name = hits_var_name

    return [
        f"{result_var_name} = {{text: [] for text in {target_texts_var_name} if text}}",
        *_build_ida_strings_enumerator_py_lines(min_length=min_length),
        "for item in strings:",
        "    try:",
        "        text = str(item)",
        "        ea = int(item.ea)",
        "    except Exception:",
        "        continue",
        f"    if text in {result_var_name}:",
        f"        {result_var_name}[text].append(ea)",
    ]
```

- [ ] **Step 2: Run the shared helper tests and verify they pass**

Run:

```bash
uv run python -m unittest tests.test_ida_analyze_util.TestIdaStringEnumerationSupport
```

Expected: PASS.

- [ ] **Step 3: Commit the shared helper foundation**

Run:

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "test(ida): 覆盖字符串 setup 缓存辅助"
```

Expected: commit succeeds with only `ida_analyze_util.py` and `tests/test_ida_analyze_util.py` staged.

### Task 3: Update `xref_strings` collection generated code

**Files:**
- Modify: `ida_analyze_util.py:6046-6051`
- Modify: `tests/test_ida_analyze_util.py:2179-2282`

- [ ] **Step 1: Update `_collect_xref_func_starts_for_string()` assertions**

In `test_collect_xref_func_starts_for_string_uses_substring_by_default`, replace the default setup assertion block:

```python
self.assertIn("strings = idautils.Strings(default_setup=False)", py_code)
self.assertNotIn("strings.setup(", py_code)
self.assertNotIn("ida_netnode", py_code)
self.assertIn("for s in strings:", py_code)
self.assertNotIn("for s in idautils.Strings():", py_code)
```

In `test_collect_xref_func_starts_for_string_reads_env_min_length`, replace the `minlen=6` assertion with:

```python
self.assertIn("import ida_netnode, json", py_code)
self.assertIn("CS2VIBE_STRING_SETUP_STATE_NODE", py_code)
self.assertIn(
    "expected_state = {'version': 1, 'minlen': 6, 'strtypes': 'STRTYPE_C'}",
    py_code,
)
self.assertIn(
    "strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=6)",
    py_code,
)
self.assertIn("_cs2vibe_write_string_setup_state(expected_state)", py_code)
```

- [ ] **Step 2: Run the two focused async tests and verify the default test fails before the production change**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_collect_xref_func_starts_for_string_uses_substring_by_default \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_collect_xref_func_starts_for_string_reads_env_min_length
```

Expected: FAIL because `_collect_xref_func_starts_for_string()` still emits the old setup helper call.

- [ ] **Step 3: Change `_collect_xref_func_starts_for_string()` to use the new enumerator helper**

In `ida_analyze_util.py`, replace:

```python
        *_build_ida_strings_setup_py_lines(strings_var_name="strings"),
```

with:

```python
        *_build_ida_strings_enumerator_py_lines(strings_var_name="strings"),
```

- [ ] **Step 4: Run the focused async tests and verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_collect_xref_func_starts_for_string_uses_substring_by_default \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_collect_xref_func_starts_for_string_reads_env_min_length
```

Expected: PASS.

- [ ] **Step 5: Commit the `xref_strings` generated-code update**

Run:

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "fix(ida): 跳过默认字符串 setup"
```

Expected: commit succeeds with only `ida_analyze_util.py` and `tests/test_ida_analyze_util.py` staged.

### Task 4: Update single-target preprocessor string scans

**Files:**
- Modify: `ida_preprocessor_scripts/_define_inputfunc.py:7-116`
- Modify: `ida_preprocessor_scripts/find-CBaseFilter_InputTestActivator.py:11-73`
- Modify: `tests/test_define_inputfunc_preprocessor.py:1-79`
- Modify: `tests/test_ida_preprocessor_scripts.py:792-804`

- [ ] **Step 1: Update `_define_inputfunc.py` tests for default no-setup and explicit setup**

In `tests/test_define_inputfunc_preprocessor.py`, add `import os` after `import json`.

Replace `test_build_define_inputfunc_py_eval_uses_shared_strings_setup` with:

```python
    def test_build_define_inputfunc_py_eval_skips_strings_setup_by_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            code = define_inputfunc._build_define_inputfunc_py_eval(
                input_name="ShowHudHint",
                handler_ptr_offset=0x10,
                allowed_segment_names=(".data",),
            )

        self.assertIn(
            "strings = idautils.Strings(default_setup=False)",
            code,
        )
        self.assertNotIn("strings.setup(", code)
        self.assertNotIn("ida_netnode", code)
        self.assertIn("for item in strings:", code)
        self.assertNotIn("for item in idautils.Strings():", code)

    def test_build_define_inputfunc_py_eval_uses_netnode_guard_for_explicit_minlen(
        self,
    ) -> None:
        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "6"},
            clear=True,
        ):
            code = define_inputfunc._build_define_inputfunc_py_eval(
                input_name="ShowHudHint",
                handler_ptr_offset=0x10,
                allowed_segment_names=(".data",),
            )

        self.assertIn("import ida_netnode, json", code)
        self.assertIn(
            "expected_state = {'version': 1, 'minlen': 6, 'strtypes': 'STRTYPE_C'}",
            code,
        )
        self.assertIn(
            "strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=6)",
            code,
        )
```

- [ ] **Step 2: Update `find-CBaseFilter_InputTestActivator.py` Linux fallback test for default no-setup**

In `tests/test_ida_preprocessor_scripts.py`, replace the old `minlen=4` assertion block in `test_cbasefilter_inputtestactivator_linux_fallback_uses_shared_string_setup` with:

```python
self.assertIn(
    "strings = idautils.Strings(default_setup=False)",
    py_code,
)
self.assertNotIn("strings.setup(", py_code)
self.assertNotIn("ida_netnode", py_code)
self.assertIn("for s in strings:", py_code)
self.assertNotIn("for s in idautils.Strings():", py_code)
```

- [ ] **Step 3: Run the single-target generated-code tests and verify they fail before import changes**

Run:

```bash
uv run python -m unittest \
  tests.test_define_inputfunc_preprocessor.TestBuildDefineInputFuncPyEval \
  tests.test_ida_preprocessor_scripts.TestIdaPreprocessorScripts.test_cbasefilter_inputtestactivator_linux_fallback_uses_shared_string_setup
```

Expected: FAIL if either script still imports or calls the old always-setup helper.

- [ ] **Step 4: Change single-target preprocessors to import and call the enumerator helper**

In `ida_preprocessor_scripts/_define_inputfunc.py`, replace:

```python
from ida_analyze_util import (
    _build_ida_strings_setup_py_lines,
    parse_mcp_result,
    preprocess_gen_func_sig_via_mcp,
    write_func_yaml,
)
```

with:

```python
from ida_analyze_util import (
    _build_ida_strings_enumerator_py_lines,
    parse_mcp_result,
    preprocess_gen_func_sig_via_mcp,
    write_func_yaml,
)
```

Then replace:

```python
        _build_ida_strings_setup_py_lines(strings_var_name="strings")
```

with:

```python
        _build_ida_strings_enumerator_py_lines(strings_var_name="strings")
```

In `ida_preprocessor_scripts/find-CBaseFilter_InputTestActivator.py`, replace:

```python
from ida_analyze_util import (
    _build_ida_strings_setup_py_lines,
    parse_mcp_result,
    preprocess_gen_func_sig_via_mcp,
    write_func_yaml,
)
```

with:

```python
from ida_analyze_util import (
    _build_ida_strings_enumerator_py_lines,
    parse_mcp_result,
    preprocess_gen_func_sig_via_mcp,
    write_func_yaml,
)
```

Then replace:

```python
py_lines.extend(_build_ida_strings_setup_py_lines(strings_var_name="strings"))
```

with:

```python
py_lines.extend(_build_ida_strings_enumerator_py_lines(strings_var_name="strings"))
```

- [ ] **Step 5: Run the single-target generated-code tests and verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_define_inputfunc_preprocessor.TestBuildDefineInputFuncPyEval \
  tests.test_ida_preprocessor_scripts.TestIdaPreprocessorScripts.test_cbasefilter_inputtestactivator_linux_fallback_uses_shared_string_setup
```

Expected: PASS.

- [ ] **Step 6: Commit the single-target preprocessor update**

Run:

```bash
git add \
  ida_preprocessor_scripts/_define_inputfunc.py \
  ida_preprocessor_scripts/find-CBaseFilter_InputTestActivator.py \
  tests/test_define_inputfunc_preprocessor.py \
  tests/test_ida_preprocessor_scripts.py
git commit -m "fix(preprocess): 避免默认字符串 setup"
```

Expected: commit succeeds with only the listed files staged.

### Task 5: Update exact-index preprocessor generated-code tests

**Files:**
- Modify: `tests/test_registerconcommand_preprocessor.py:1-73`
- Modify: `tests/test_register_event_listener_abstract_preprocessor.py:1-265`

- [ ] **Step 1: Update `registerconcommand` tests**

In `tests/test_registerconcommand_preprocessor.py`, add `import os` after `import json`.

In `test_build_registerconcommand_py_eval_linux_embeds_exact_match_and_linux_registers`, wrap the build call with an empty env:

```python
        with patch.dict(os.environ, {}, clear=True):
            code = registerconcommand._build_registerconcommand_py_eval(
                platform="linux",
                command_name="bot_add",
                help_string=(
                    "bot_add <t|ct> <type> <difficulty> <name> - "
                    "Adds a bot matching the given criteria."
                ),
                search_window_before_call=48,
                search_window_after_xref=24,
            )
```

Then keep the existing exact-index assertions and add:

```python
        self.assertNotIn("strings.setup(", code)
        self.assertNotIn("ida_netnode", code)
```

Add this new test method to `TestBuildRegisterConCommandPyEval`:

```python
    def test_build_registerconcommand_py_eval_uses_netnode_guard_for_explicit_minlen(
        self,
    ) -> None:
        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "6"},
            clear=True,
        ):
            code = registerconcommand._build_registerconcommand_py_eval(
                platform="linux",
                command_name="bot_add",
                help_string="Adds a bot matching the given criteria.",
                search_window_before_call=48,
                search_window_after_xref=24,
            )

        self.assertIn("import ida_netnode, json", code)
        self.assertIn(
            "expected_state = {'version': 1, 'minlen': 6, 'strtypes': 'STRTYPE_C'}",
            code,
        )
        self.assertIn(
            "strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=6)",
            code,
        )
        self.assertEqual(1, code.count("for item in strings:"))
```

- [ ] **Step 2: Update `register_event_listener` generated-code tests**

In `tests/test_register_event_listener_abstract_preprocessor.py`, add `import os` after `import importlib`.

In `test_build_register_event_listener_py_eval_windows_embeds_hexrays_and_slot_recovery`, wrap the build call with an empty env:

```python
        with patch.dict(os.environ, {}, clear=True):
            code = register_event_listener._build_register_event_listener_py_eval(
                platform="windows",
                source_func_va="0x180010000",
                anchor_event_name="CLoopModeGame::OnClientPollNetworking",
                search_window_after_anchor=24,
                search_window_before_call=64,
            )
```

Then add:

```python
        self.assertNotIn("strings.setup(", code)
        self.assertNotIn("ida_netnode", code)
```

Add this new test method to `TestBuildRegisterEventListenerPyEval`:

```python
    def test_build_register_event_listener_py_eval_uses_netnode_guard_for_explicit_minlen(
        self,
    ) -> None:
        register_event_listener = _import_register_event_listener_module()

        with patch.dict(
            os.environ,
            {"CS2VIBE_STRING_MIN_LENGTH": "6"},
            clear=True,
        ):
            code = register_event_listener._build_register_event_listener_py_eval(
                platform="windows",
                source_func_va="0x180010000",
                anchor_event_name="CLoopModeGame::OnClientPollNetworking",
                search_window_after_anchor=24,
                search_window_before_call=64,
            )

        self.assertIn("import ida_netnode, json", code)
        self.assertIn(
            "expected_state = {'version': 1, 'minlen': 6, 'strtypes': 'STRTYPE_C'}",
            code,
        )
        self.assertIn(
            "strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=6)",
            code,
        )
        self.assertEqual(1, code.count("for item in strings:"))
```

- [ ] **Step 3: Update the fake execution test to assert no setup by default**

In `test_build_register_event_listener_py_eval_linux_recovers_reused_temp_base_register`, wrap the code generation with an empty env:

```python
        with patch.dict(os.environ, {}, clear=True):
            code = register_event_listener._build_register_event_listener_py_eval(
                platform="linux",
                source_func_va=hex(source_func_va),
                anchor_event_name="CLoopModeGame::OnClientPollNetworking",
                search_window_after_anchor=64,
                search_window_before_call=64,
            )
```

Replace the setup kwargs assertion:

```python
        self.assertIsNone(strings_instance.setup_kwargs)
```

- [ ] **Step 4: Run the exact-index preprocessor tests and verify they pass**

Run:

```bash
uv run python -m unittest \
  tests.test_registerconcommand_preprocessor.TestBuildRegisterConCommandPyEval \
  tests.test_register_event_listener_abstract_preprocessor.TestBuildRegisterEventListenerPyEval
```

Expected: PASS.

- [ ] **Step 5: Commit the exact-index test update**

Run:

```bash
git add \
  tests/test_registerconcommand_preprocessor.py \
  tests/test_register_event_listener_abstract_preprocessor.py
git commit -m "test(preprocess): 覆盖字符串 setup 缓存生成代码"
```

Expected: commit succeeds with only the listed test files staged.

### Task 6: Update README environment documentation

**Files:**
- Modify: `README.md:86-90`

- [ ] **Step 1: Replace the old `CS2VIBE_STRING_MIN_LENGTH` README bullets**

Replace:

```markdown
* IDA preprocessor environment:
  - `CS2VIBE_STRING_MIN_LENGTH`: controls the minimum string length used by IDA preprocessor string enumeration logic only
  - Default: `4`
  - Empty, non-integer, or values `<1` fall back to `4`
  - This is not an LLM parameter
```

with:

```markdown
* IDA preprocessor environment:
  - `CS2VIBE_STRING_MIN_LENGTH`: controls optional IDA string-list setup for preprocessor string enumeration only
  - Unset or empty: do not call `idautils.Strings.setup`; use the IDB's current string-list state
  - Integer `>=1`: call `idautils.Strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=<value>)` when the current IDB has not already been set up with the same parameters
  - Non-integer or values `<1`: fall back to `4` and use the same IDB-level setup guard
  - Setup state is stored per IDB; changing the effective `minlen` triggers setup again
  - This is not an LLM parameter
```

- [ ] **Step 2: Commit the README update**

Run:

```bash
git add README.md
git commit -m "docs: 更新字符串最小长度配置说明"
```

Expected: commit succeeds with only `README.md` staged.

### Task 7: Final focused verification

**Files:**
- Read: `ida_analyze_util.py`
- Read: `ida_preprocessor_scripts/_define_inputfunc.py`
- Read: `ida_preprocessor_scripts/find-CBaseFilter_InputTestActivator.py`
- Read: `ida_preprocessor_scripts/_registerconcommand.py`
- Read: `ida_preprocessor_scripts/_register_event_listener_abstract.py`
- Read: `README.md`

- [ ] **Step 1: Confirm no production call sites use the old helper name directly**

Run:

```bash
rg -n "_build_ida_strings_setup_py_lines\\(" ida_analyze_util.py ida_preprocessor_scripts tests
```

Expected: only the compatibility wrapper definition in `ida_analyze_util.py`, or no matches outside `ida_analyze_util.py`.

- [ ] **Step 2: Run all string setup cache related unit tests**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_util.TestIdaStringEnumerationSupport \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_collect_xref_func_starts_for_string_uses_substring_by_default \
  tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_collect_xref_func_starts_for_string_reads_env_min_length \
  tests.test_define_inputfunc_preprocessor.TestBuildDefineInputFuncPyEval \
  tests.test_registerconcommand_preprocessor.TestBuildRegisterConCommandPyEval \
  tests.test_register_event_listener_abstract_preprocessor.TestBuildRegisterEventListenerPyEval \
  tests.test_ida_preprocessor_scripts.TestIdaPreprocessorScripts.test_cbasefilter_inputtestactivator_linux_fallback_uses_shared_string_setup
```

Expected: PASS.

- [ ] **Step 3: Run whitespace check for changed files**

Run:

```bash
git diff --check
```

Expected: no output and exit code `0`.

- [ ] **Step 4: Review the final diff**

Run:

```bash
git diff --stat HEAD
git diff -- ida_analyze_util.py README.md
```

Expected: diff only covers string enumerator setup cache logic and README documentation.

- [ ] **Step 5: Commit any final integration fixes**

If Step 2 or Step 3 required edits, run:

```bash
git add ida_analyze_util.py README.md tests ida_preprocessor_scripts
git commit -m "fix(ida): 整合字符串 setup 缓存"
```

Expected: commit succeeds only if final integration edits were necessary. If no edits were necessary, skip this commit.
