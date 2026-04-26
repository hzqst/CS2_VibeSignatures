# IDB 字符串 setup 缓存设计

## 背景

此前 `docs/superpowers/specs/2026-04-23-string-min-length-design.md` 与对应实施计划将 IDA 字符串枚举统一改为通过 `CS2VIBE_STRING_MIN_LENGTH` 控制最小字符串长度，默认值为 `4`。该改动解决了 4 字节字符串无法被 `idautils.Strings()` 默认枚举发现的问题。

实际使用中发现，每次调用 `idautils.Strings(default_setup=False)` 后再执行 `strings.setup(...)` 都会花费数秒，即使同一 IDA / IDB 上此前已经执行过 setup。由于 `xref_strings` 路径会频繁触发字符串枚举，这个开销会明显放大。

本设计调整环境变量语义，并使用 IDB 内的 `netnode` 记录字符串 setup 状态，以减少重复 setup 开销，同时保留显式最小长度配置能力。

## 目标

- 允许 `CS2VIBE_STRING_MIN_LENGTH` 未设置或为空时跳过 `strings.setup(...)`。
- 当 `CS2VIBE_STRING_MIN_LENGTH` 非空时，仍支持显式设置字符串最小长度。
- 使用 per-IDB 的 `netnode` 记录已执行 setup 的参数。
- 当后续 env 改成其他有效 `minlen` 时，能够检测到参数变化并重新 setup。
- 保持 `xref_strings` 的精确匹配、子串匹配、`XrefsTo`、函数归一化与 YAML 输出语义不变。

## 非目标

- 不新增 CLI 参数。
- 不改变 IDA 字符串类型范围，继续使用 `ida_nalt.STRTYPE_C`。
- 不做跨 IDB、跨项目或跨机器的共享缓存。
- 不自动清理 `netnode` 状态。
- 不重构与字符串枚举无关的预处理流程。

## 配置语义

`CS2VIBE_STRING_MIN_LENGTH` 改为显式 opt-in 配置：

- 未设置：返回 `None`，不调用 `strings.setup(...)`。
- 设置为空字符串或仅空白：返回 `None`，不调用 `strings.setup(...)`。
- 设置为合法整数且 `>= 1`：使用该整数作为 `minlen`。
- 设置为非法值或 `< 1`：回退为 `4`，并视为显式配置。

因此，默认路径不再主动重建 IDA 字符串列表，而是使用当前 IDB 已有的字符串枚举状态。需要保证短字符串可见时，用户应显式设置 `CS2VIBE_STRING_MIN_LENGTH=4` 或其他目标值。

## 设计概览

在 `ida_analyze_util.py` 中将字符串枚举 helper 从“总是 setup”改为“按配置构造枚举器”。

建议新增或替换为以下本地 helper：

```python
def _resolve_ida_string_min_length_config() -> int | None
```

返回值语义：

- `None` 表示不主动 setup。
- `int` 表示需要按该 `minlen` 显式 setup。

建议新增统一生成 helper：

```python
def _build_ida_strings_enumerator_py_lines(
    *,
    strings_var_name: str = "strings",
    min_length: int | None | _Auto = AUTO,
) -> list[str]
```

生成逻辑：

- 配置为 `None` 时，只生成 `strings = idautils.Strings(default_setup=False)`。
- 配置为整数时，生成 `Strings` 初始化、`netnode` 状态读取、参数比较、必要时 setup、setup 后写入状态。

现有 `_build_ida_exact_string_index_py_lines()` 应改为调用新的枚举器 helper，使多目标精确匹配路径自动继承新语义。

## netnode 状态

显式配置时，在 IDB 内使用命名 `netnode` 保存 setup 状态。建议名称为：

```python
"$CS2VIBE_STRING_SETUP_STATE"
```

状态内容使用 JSON 字符串，建议字段如下：

```json
{
  "version": 1,
  "minlen": 4,
  "strtypes": "STRTYPE_C"
}
```

字段用途：

- `version`：状态格式版本，用于未来失效旧标记。
- `minlen`：本次 setup 使用的最小字符串长度。
- `strtypes`：当前固定为 `STRTYPE_C`，用于避免未来扩展时误复用旧状态。

显式配置时的远端逻辑：

1. 构造 `expected_state`。
2. 读取 `$CS2VIBE_STRING_SETUP_STATE`。
3. 如果已存状态与 `expected_state` 完全一致，跳过 `strings.setup(...)`。
4. 如果状态缺失、损坏、版本不匹配、`minlen` 不匹配或 `strtypes` 不匹配，执行 `strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=<resolved>)`。
5. setup 成功后写入新的 `expected_state`。

这样，同一个 IDB 中相同参数不会重复 setup；如果后续 env 改成其他 `minlen`，会触发重新 setup 并更新状态。

## 远端代码形态

未设置或空 env 时，生成代码应接近：

```python
strings = idautils.Strings(default_setup=False)
```

不应包含 `strings.setup(`、`ida_netnode` 或状态写入逻辑。

显式配置时，生成代码应接近：

```python
import ida_netnode

strings = idautils.Strings(default_setup=False)
expected_state = {"version": 1, "minlen": 4, "strtypes": "STRTYPE_C"}

if _cs2vibe_read_string_setup_state() != expected_state:
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    _cs2vibe_write_string_setup_state(expected_state)
```

`_cs2vibe_read_string_setup_state()` 与 `_cs2vibe_write_string_setup_state()` 可由 helper 生成到 `py_eval` 中，负责 `netnode` 读写和 JSON 解析。

## 调用点范围

以下路径应接入新的枚举器 helper：

- `ida_analyze_util._collect_xref_func_starts_for_string()`
- `ida_preprocessor_scripts/_define_inputfunc.py`
- `ida_preprocessor_scripts/find-CBaseFilter_InputTestActivator.py`
- `ida_preprocessor_scripts/_registerconcommand.py`
- `ida_preprocessor_scripts/_register_event_listener_abstract.py`

其中 `_registerconcommand.py` 与 `_register_event_listener_abstract.py` 继续保留一次扫描建立精确匹配索引的优化，只替换底层字符串枚举器构造逻辑。

## 错误处理

- env 未设置或为空：不读写 `netnode`，不 setup。
- env 非空但非法或 `<1`：回退到 `4`，并进入显式 setup 流程。
- 读取 `netnode` 失败：视为未 setup，重新 setup。
- `netnode` 内容无法解析：视为未 setup，重新 setup。
- `strings.setup(...)` 抛异常：不写 `netnode`，让现有 `py_eval` 外层错误处理暴露失败。
- 写入 `netnode` 失败：不让分析失败，但下次可能再次 setup。

## 兼容性与性能

兼容性：

- 默认行为从“自动按 `minlen=4` setup”改为“不主动 setup”。这会提升默认性能，但默认情况下不再保证 4 字节字符串可见。
- 需要短字符串可见的场景应显式设置 `CS2VIBE_STRING_MIN_LENGTH=4`。
- 显式配置后，同一 IDB 的状态会持久保存；相同参数后续跳过 setup。
- 如果 env 改成不同 `minlen`，会重新 setup。

性能：

- 默认路径消除 `strings.setup(...)` 成本。
- 显式配置路径只在当前 IDB 缺少匹配 setup 状态时调用 setup。
- 多目标匹配路径仍保持单次扫描字符串表。

## 文档更新

`README.md` 中 `CS2VIBE_STRING_MIN_LENGTH` 说明需要更新为：

- 未设置或为空：不主动 setup，使用 IDB 当前字符串枚举状态。
- 设置为整数：按该最小长度 setup IDA 字符串列表。
- 非法或 `<1`：回退到 `4`。
- setup 状态按 IDB 存储；相同参数不会重复 setup，参数变化会重新 setup。

## 验证方案

实现时建议使用定向单元测试覆盖生成代码和配置解析：

1. env 未设置时，解析结果为 `None`。
2. env 为空字符串或仅空白时，解析结果为 `None`。
3. env 为 `"4"` 时，解析结果为 `4`。
4. env 为 `"6"` 时，解析结果为 `6`。
5. env 为非法值或 `<1` 时，解析结果为 `4`。
6. 默认生成代码不包含 `strings.setup(`、`ida_netnode` 或 `CS2VIBE_STRING_SETUP_STATE`。
7. 显式配置生成代码包含 `strings.setup(...)`、`ida_netnode`、`CS2VIBE_STRING_SETUP_STATE` 与 expected state。
8. `_build_ida_exact_string_index_py_lines()` 在默认路径仍只生成一个 `for item in strings:`。
9. 各调用点的测试断言从“默认包含 `minlen=4`”改为“默认无 setup，显式 env 才有 setup”。

如需人工验证，可在同一 IDB 中分别执行：

- 未设置 env，确认不触发 setup。
- 设置 `CS2VIBE_STRING_MIN_LENGTH=4`，确认首次 setup 后写入状态。
- 再次设置 `4`，确认跳过 setup。
- 改为 `6`，确认重新 setup 并更新状态。

## 实施边界

本设计是对 2026-04-23 字符串最小长度设计的性能修订。实施时应保持改动集中在字符串枚举 helper、相关预处理调用点、对应测试与 README 文档，不扩大到其他预处理架构或缓存系统。
