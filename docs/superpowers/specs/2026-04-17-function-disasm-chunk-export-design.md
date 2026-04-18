# 函数反汇编 chunk 完整导出设计

## 背景

`ParticleTestStart_CommandHandler` 的 Linux reference YAML 中，`disasm_code` 只导出了函数入口到第一次 `jmp` 为止的连续指令。IDA listing 中后续仍有多个属于同一函数的离散 function chunk，例如 `0x158C520`、`0x158C570`、`0x158C588`、`0x158C5A0` 等，但当前导出逻辑没有把它们纳入 `disasm_code`。

当前仓库中存在两份几乎相同的函数详情导出逻辑：

- `generate_reference_yaml.py` 的 `export_reference_payload_via_mcp(...)`
- `ida_analyze_util.py` 的 `_export_function_detail_via_mcp(...)`

历史实现曾在 IDA `py_eval` 脚本中通过 `idautils.FuncItems(func.start_ea)` 线性生成 `disasm_code`。该路径会导致 standalone reference YAML 生成链路与 `LLM_DECOMPILE` 运行时目标函数详情导出链路存在漏 chunk 风险。

## 目标

- 用一套共享导出策略同时覆盖 `generate_reference_yaml.py` 与 `ida_analyze_util.py`。
- 保持 YAML 顶层字段结构不变：`func_name`、`func_va`、`disasm_code`、`procedure`。
- 保持现有逐行反汇编格式基础不变，同时补齐属于同一函数的离散 chunk。
- 在 IDA API 可稳定获取时，在对应指令前额外插入注释行。
- 保持现有 prompt 与 `LLM_DECOMPILE` 数据流兼容。

## 非目标

- 不调整 `procedure` 生成逻辑。
- 不修改 prompt 模板或 LLM response 解析逻辑。
- 不尝试反编译或跨函数内联 call target。
- 不强制复刻 IDA listing 中所有 banner，例如 `START OF FUNCTION CHUNK`、`END OF FUNCTION CHUNK`、`CODE XREF`、`align`。
- 不依赖真实 IDA 环境做单元测试；真实 IDA 生成结果作为人工或集成验收。

## 推荐方案

采用“chunk 归属 + 控制流遍历 + 缺口补齐”的混合方案。

1. 先通过 IDA API 获取目标函数所有 function chunk 范围，形成“属于当前函数”的地址边界。
2. 从函数入口开始做控制流遍历，遇到条件跳转同时跟踪跳转目标与 fallthrough，遇到无条件直接跳转只跟踪目标，遇到 `ret`、`int3`、无效指令或越出 chunk 时停止当前路径。
3. 遍历结束后扫描全部 function chunk 内的 code heads，将仍未收集的指令地址补齐。
4. 最终按地址升序输出所有指令。
5. 对每条指令，在指令行前插入可稳定读取到的 IDA 注释行。

该方案比单纯递归跳转目标更稳，因为它不会漏掉 IDA 已归属到函数但入口控制流没有直接连到的 tail chunk；也比单纯枚举 chunk 更可控，因为控制流遍历可作为主路径，chunk 扫描只做保守补齐。

## 架构设计

新增一份共享的 IDA `py_eval` 代码生成器，供两条链路复用。

### 共享导出器

建议新增函数：

```python
def build_function_detail_export_py_eval(func_va_int: int) -> str:
    ...
```

职责：

- 生成完整 IDA `py_eval` 脚本。
- 在脚本内定义统一的 `get_disasm(...)`、`get_pseudocode(...)` 与辅助函数。
- 返回 JSON payload，字段与现有实现一致。

### 调用方

`generate_reference_yaml.py`：

- `export_reference_payload_via_mcp(...)` 不再内嵌旧版 `get_disasm(...)` 字符串。
- 改为调用共享导出器生成 `py_eval` 代码。
- 保留现有 payload 校验与 `ReferenceGenerationError` 行为。

`ida_analyze_util.py`：

- `_export_function_detail_via_mcp(...)` 改为调用同一共享导出器。
- 保留现有 `None` 失败语义和 debug 输出。
- 保证 `LLM_DECOMPILE` 运行时目标详情与 reference YAML 使用同一 `disasm_code` 生成策略。

## 反汇编收集算法

### chunk 范围

在 `py_eval` 中：

- 使用 `ida_funcs.get_func(func_ea)` 获取函数对象。
- 优先完整枚举 `idautils.Chunks(func.start_ea)`，得到 `(start_ea, end_ea)` 范围列表。
- 若 `Chunks` 失败或为空，回退到 `ida_funcs.func_tail_iterator_t`（先尝试 `func_tail_iterator_t(func)`，再尝试无参构造 + `set_ea(func.start_ea)`）。
- 若两套 chunk API 都失败或仍为空，回退到单区间 `[(func.start_ea, func.end_ea)]`。
- 所有 fallback 均继续走 chunk/range code heads 渲染路径，不再使用 `FuncItems` 线性主块逻辑。

所有控制流遍历与补齐扫描都必须限制在 chunk 范围内。

### 控制流遍历

从 `func.start_ea` 入队，维护：

- `pending_eas`：待扫描起点。
- `visited_eas`：已处理指令地址。
- `collected_eas`：最终导出的指令地址集合。
- `chunk_ranges`：当前函数的全部地址范围。

单条路径内逐指令前进：

- 当前地址不在 chunk 范围内则停止。
- 当前地址不是 code head 或无法生成有效反汇编则停止。
- 当前地址已访问则停止。
- 成功处理后加入 `visited_eas` 与 `collected_eas`。

分支处理：

- 条件跳转：收集直接跳转目标，并继续收集 fallthrough。
- 无条件直接跳转：收集直接跳转目标，当前路径停止。
- `ret`、`int3`、`hlt` 等终止指令：当前路径停止。
- `call`：不进入 call target，继续当前函数内下一条指令。
- 间接跳转：无法稳定解析时停止当前路径，后续由 chunk 缺口补齐兜底。

为避免异常控制流导致死循环，遍历应设置最大步数。建议以上限 `chunk_code_head_count * 4 + 256` 作为保守保护。

### 缺口补齐

控制流遍历完成后，再扫描所有 chunk 范围内的 code heads。

- 对未进入 `collected_eas` 的指令地址，补入结果。
- 只补 code heads，不补数据或 alignment 字节。
- 最终统一排序，避免遍历顺序影响输出稳定性。

## 输出格式

指令行保持现有基础格式：

```text
{seg_name}:{ea:016X}                 {disasm}
```

若地址没有 segment 名，则使用：

```text
{ea:016X}                 {disasm}
```

注释行插在对应指令行之前，建议格式：

```text
{seg_name}:{ea:016X}                 ; {comment}
```

注释读取策略：

- 优先读取普通注释。
- 同时读取 repeatable 注释。
- 尝试读取前置或后置 extra comment。
- 去掉 IDA tag，过滤空行。
- 对同一地址去重，避免重复输出相同注释。
- 注释读取失败时静默跳过，不影响指令导出。

## 错误处理

- 找不到函数：返回空 `disasm_code`，沿用外层现有失败处理。
- chunk 枚举失败：按 `Chunks -> func_tail_iterator_t -> 单区间` 回退，并继续走 chunk/range 渲染。
- 注释读取失败：只跳过注释。
- 指令解码失败：停止当前路径，由缺口补齐兜底。
- `next_head` 不前进：停止当前路径，避免死循环。
- `py_eval` 抛出异常：调用方保持现有错误处理语义。

## 测试计划

### 单元测试

更新并新增不依赖真实 IDA 的字符串级测试：

- 断言共享导出器生成的 `py_eval` 脚本包含 chunk 枚举逻辑。
- 断言脚本包含控制流目标收集逻辑。
- 断言脚本包含注释读取逻辑，例如普通注释、repeatable 注释或 extra comment 读取。
- 断言 `generate_reference_yaml.py` 与 `ida_analyze_util.py` 调用同一共享导出器。
- 更新现有 mock 判断，不再依赖旧字符串 `"'disasm_code': get_disasm(func_start)"` 作为唯一识别条件。

### 集成验收

在可连接 IDA MCP 的环境中，重新生成：

```bash
uv run generate_reference_yaml.py -gamever 14141 -module server -platform linux -func_name ParticleTestStart_CommandHandler -mcp_host 127.0.0.1 -mcp_port 13337
```

验收点：

- `ida_preprocessor_scripts/references/server/ParticleTestStart_CommandHandler.linux.yaml` 的 `disasm_code` 包含入口外离散 chunk。
- 应至少覆盖类似 `0x158C520`、`0x158C570`、`0x158C588`、`0x158C5A0` 的地址段。
- YAML 字段结构不变。
- `procedure` 字段仍按现有逻辑生成。
- 注释可用时出现注释行，不可用时不影响反汇编输出。

## 风险与权衡

- IDA 对 function chunk 的归属仍是基础事实来源；如果 IDA 自身没有把某段代码归入目标函数，新导出器不会强行跨函数收集。
- 间接跳转的真实目标不一定可静态解析，因此设计中不强行追踪间接目标，而依赖 chunk 缺口补齐兜底。
- 注释 API 的可用性受 IDA 版本和 listing 状态影响，因此注释是增强项，不作为导出成功条件。
- 输出内容会比原来更长，尤其是包含多个 tail chunk 或注释时，但这符合 `LLM_DECOMPILE` 对完整上下文的需求。

## 通过标准

- 两条导出链路均使用同一共享 py_eval 生成器。
- 存在离散 function chunk 的目标函数不再只导出入口连续块。
- 现有 YAML schema 与 prompt 输入字段保持兼容。
- 单元测试覆盖共享导出器、两处调用方与关键脚本内容。
- 在真实 IDA 环境中重新生成 `ParticleTestStart_CommandHandler.linux.yaml` 后，`disasm_code` 包含后续离散 chunk。
