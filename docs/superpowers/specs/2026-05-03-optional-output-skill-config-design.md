# `config.yaml` `optional_output` 可选产物设计

## 背景

`find-CEngineServiceMgr_DeactivateLoop` 现在遇到一个新的调度问题：

- `CEngineServiceMgr_DeactivateLoop` 在部分当前版本中可能被编译器 inline 到 `CEngineServiceMgr__MainLoop`
- 这种情况下 `CEngineServiceMgr_DeactivateLoop.{platform}.yaml` 合法缺失
- 但首次运行时，`skip_if_exists` 依赖的下游产物还不存在，无法提前跳过该 skill
- preprocessor 若没有产出 YAML，调度层会继续尝试运行 Agent SKILL
- `.claude/skills/find-CEngineServiceMgr_DeactivateLoop/SKILL.md` 不存在时，整个 skill 会被记为 `Failed`

已有的 `absent_ok` 三态可以表达“preprocessor 明确确认目标合法缺失”。但它要求具体 preprocessor 在失败路径上能证明缺失原因。当前需求更直接：某些 YAML 本身就是可选产物，缺失不应触发 Agent fallback，也不应导致整个 skill 失败。

因此需要在 `config.yaml` 中正式支持 `optional_output`，将“必须产出”和“可选产出”从调度语义上分开。

## 目标

- 在 `modules[].skills[]` 下支持可选字段 `optional_output`
- `optional_output` 与 `expected_output` 一样支持 `{platform}` 占位符
- `optional_output` 路径以当前 module binary 目录为基准解析
- `optional_output` 缺失不计为 skill 失败
- 当 skill 没有 `expected_output`，只有 `optional_output`，且 optional YAML 未生成时，不进入 Agent fallback，计为 skip
- 保持 `expected_output` 的硬成功语义不变
- 保持 `expected_input`、`prerequisite`、`skip_if_exists` 的既有语义不变

## 非目标

- 不把 `optional_output` 用作依赖排序依据
- 不引入 optional `expected_input`
- 不改变 symbol YAML schema
- 不修改 `update_gamedata.py` 的缺失 YAML 处理策略
- 不要求所有 preprocessor 都返回 `absent_ok`
- 不为不存在的 `.claude/skills/find-CEngineServiceMgr_DeactivateLoop` 新增 Agent SKILL

## 方案比较

### 方案 A：新增独立 `optional_output` 调度语义

做法：

- `parse_config()` 读取 `optional_output`
- 调度时把 `expected_output` 视为必需产物
- 调度时把 `optional_output` 视为可选产物
- preprocessor 执行时接收 `expected_output + optional_output`，以便仍可生成可选 YAML
- 成功判定只检查 `expected_output`
- 若没有 `expected_output`，且可选产物未生成，则不跑 Agent fallback，记为 skip

优点：

- 语义直接，配置作者能清楚表达“此 YAML 可合法缺失”
- 不依赖每个 preprocessor 都能准确证明 inline 缺失
- 不破坏现有 `expected_output` 硬成功语义
- 可复用于后续类似“辅助 YAML 可选”的场景

缺点：

- 调度层需要理解第二类输出
- 测试需要覆盖必需输出与可选输出的组合行为

### 方案 B：继续只使用 `absent_ok`

做法：

- 不新增配置字段
- 要求 `find-CEngineServiceMgr_DeactivateLoop.py` 在所有 inline 缺失场景返回 `absent_ok`

优点：

- 现有调度层已经支持 `absent_ok`

缺点：

- 依赖具体 preprocessor 的缺失证明能力
- 普通失败路径仍可能进入 Agent fallback
- 不能表达“这个 output 本身就是 optional”的配置意图

### 方案 C：把 optional 输出混入 `expected_output`

做法：

- 仍使用 `expected_output`
- 在 missing output 校验时按某种规则忽略部分文件

优点：

- 改动表面较少

缺点：

- 混淆必需产物与可选产物
- 容易让依赖排序和成功判定产生歧义
- 后续维护者难以判断某个 `expected_output` 是否真的必需

## 选定方案

采用方案 A：新增独立 `optional_output` 调度语义。

原因：

- 本次问题的核心不是定位算法，而是调度层把“可选产物缺失”误判为“skill 失败”
- `optional_output` 能直接表达该意图
- 它与已有 `skip_if_exists` 互补：
  - `skip_if_exists` 解决“替代终态 artifact 已存在，所以无需执行”
  - `optional_output` 解决“当前 skill 的某个辅助 artifact 可合法缺失”
- 它不会改变已有依赖模型，也不会要求下游 skill 读取不存在的 optional YAML

## 详细设计

### 1. 配置语义

在 `modules[].skills[]` 下新增可选字段：

```yaml
optional_output:
  - SomeOptionalSymbol.{platform}.yaml
```

规则：

- 字段缺失或为空列表时，视为没有 optional 输出
- 每个路径使用现有 artifact path 解析规则
- 支持 `{platform}` 占位符
- 路径必须限制在当前 module binary 目录内，安全规则与 `expected_output` 一致
- `optional_output` 不表示 skill 必须生成这些文件

### 2. `find-CEngineServiceMgr_DeactivateLoop` 配置

目标配置为：

```yaml
- name: find-CEngineServiceMgr_DeactivateLoop
  optional_output:
    - CEngineServiceMgr_DeactivateLoop.{platform}.yaml
  expected_input:
    - CEngineServiceMgr__MainLoop.{platform}.yaml
  skip_if_exists:
    - CLoopTypeBase_DeallocateLoopMode.{platform}.yaml
```

语义：

- `CEngineServiceMgr__MainLoop` 仍是硬输入
- `CEngineServiceMgr_DeactivateLoop` YAML 可生成，但不是硬要求
- 若 `CLoopTypeBase_DeallocateLoopMode` 已存在，仍按 `skip_if_exists` 提前跳过
- 若首次运行且 `CLoopTypeBase_DeallocateLoopMode` 尚不存在，则仍允许 preprocessor 尝试生成 optional YAML
- 若 preprocessor 未生成 optional YAML，不再运行不存在的 Agent SKILL

### 3. 配置解析

`parse_config()` 为每个 skill 保留：

- `expected_output`: `skill.get("expected_output", []) or []`
- `optional_output`: `skill.get("optional_output", []) or []`

这样调度层可以同时获得必需输出和可选输出。

### 4. 预筛选阶段

构建 `skills_to_process` 时：

1. 展开 `expected_output`
2. 展开 `optional_output`
3. 若 `expected_output` 非空且全部存在，按现有逻辑跳过
4. 若 `expected_output` 为空、`optional_output` 非空且全部存在，也可按“all outputs exist”跳过
5. 否则继续检查 `skip_if_exists`
6. 未跳过时，把该 skill 加入待处理列表，并携带：
   - 必需输出路径
   - 可选输出路径
   - 传给 preprocessor 的全部输出路径

第 4 点用于避免 optional YAML 已经存在时重复启动 IDA。

### 5. 执行前二次检查

真正执行某个 skill 前重新检查：

- `expected_output` 非空且全部存在：跳过
- `expected_output` 为空、`optional_output` 非空且全部存在：跳过
- `skip_if_exists` 全部存在：跳过

原因是前序 skill 可能在本轮执行中刚刚生成相关 artifact。

### 6. preprocessor 调用

传给 `_run_preprocess_single_skill_via_mcp(...)` 的 `expected_outputs` 应为：

```python
required_outputs + optional_outputs
```

原因：

- 现有 preprocessor 多数通过 `expected_outputs` 决定写入路径
- 对只有 optional 输出的 skill，若只传 required outputs，会导致 preprocessor 没有输出目标
- 命名保持兼容，不在本次重命名底层参数

### 7. preprocessor 成功判定

当 preprocessor 返回 `success`：

- 只检查 `required_outputs`
- 若必需输出缺失，则计为失败
- optional 输出缺失不计失败
- 若没有必需输出，则计为 success 还是 skip 取决于是否生成 optional 输出：
  - optional 输出至少生成一个：计为 success
  - optional 输出一个都未生成：计为 skip

该规则避免“没有任何产物但返回 success”被误报为成功。

### 8. preprocessor 失败判定

当 preprocessor 返回 `failed`：

- 若存在缺失的 `required_outputs`，保持现有行为：进入 Agent fallback
- 若没有 `required_outputs`，且只存在 `optional_outputs`，不进入 Agent fallback，计为 skip

日志建议：

```text
Skipping skill: <name> (optional outputs not generated)
```

这与 `absent_ok` 日志区分开：

```text
Skipping skill: <name> (preprocess reported absent_ok)
```

### 9. Agent SKILL 校验

`run_skill()` 的 `expected_yaml_paths` 只传 `required_outputs`。

理由：

- Agent SKILL 成功后仍必须满足必需输出
- optional 输出不是 Agent 成功条件
- 对没有 required outputs 的 optional-only skill，调度层不会进入 Agent fallback

### 10. 拓扑排序

`optional_output` 不参与 `topological_sort_skills()`。

依赖仍只来自：

- `expected_input`
- platform-specific expected input
- `prerequisite`

这样可以避免 optional artifact 被误用为 producer dependency。

## 数据流

`find-CEngineServiceMgr_DeactivateLoop` 的首次运行路径：

1. `CEngineServiceMgr_DeactivateLoop.{platform}.yaml` 不存在
2. `CLoopTypeBase_DeallocateLoopMode.{platform}.yaml` 不存在，`skip_if_exists` 不满足
3. `CEngineServiceMgr__MainLoop.{platform}.yaml` 存在，输入校验通过
4. preprocessor 尝试定位或生成 `CEngineServiceMgr_DeactivateLoop.{platform}.yaml`
5. 若目标已 inline，optional YAML 未生成
6. 调度层不运行 Agent SKILL
7. 该 skill 计为 skip
8. 后续 `find-CLoopTypeBase_DeallocateLoopMode` 继续执行

## 错误处理

- `optional_output` 路径非法时，当前 skill 计为失败
- `optional_output` 部分存在不影响继续执行
- required 输出缺失仍按失败处理
- required 输出存在时，optional 输出缺失不影响跳过或成功判定
- 没有 required 输出且没有 optional 输出的 skill 保持现有行为，不引入特殊成功规则

## 测试设计

在 `tests/test_ida_analyze_bin.py` 补充或调整以下测试：

1. `parse_config()` 能读取 `optional_output`
2. `parse_config()` 对缺失 `optional_output` 默认返回空列表
3. optional-only skill 在 optional 输出已存在时，预筛选阶段跳过且不启动 IDA
4. optional-only skill 在 preprocessor 返回 `failed` 且 optional 输出未生成时，计为 skip，不调用 `run_skill()`
5. optional-only skill 在 preprocessor 返回 `success` 且 optional 输出生成时，计为 success
6. 同时含 `expected_output` 与 `optional_output` 时，preprocessor 成功只要求 required 输出存在
7. 同时含 `expected_output` 与 `optional_output` 时，required 输出缺失仍进入现有失败或 Agent fallback 路径
8. `_run_preprocess_single_skill_via_mcp(...)` 接收到 `required + optional` 的输出路径
9. `run_skill()` 只校验 required 输出
10. `optional_output` 不影响拓扑排序

测试只覆盖调度语义，不需要启动真实 IDA。

## 风险与权衡

主要风险：

- 配置作者可能误把真正必需的 YAML 放到 `optional_output`
- optional-only skill 没有产物时计为 skip，统计上不会暴露为失败

控制方式：

- 文档明确 `expected_output` 表示硬产物，`optional_output` 表示辅助产物
- 下游必需读取的 YAML 必须继续使用 `expected_output`
- `optional_output` 不参与拓扑排序，避免形成隐式依赖
- 日志使用明确文案区分 optional 缺失和普通跳过

## 验收标准

- `config.yaml` 中的 `optional_output` 能被解析
- `find-CEngineServiceMgr_DeactivateLoop` 可声明 optional-only 输出
- 首次运行且 `CEngineServiceMgr_DeactivateLoop` 已 inline 时，不再因为缺失 `.claude/skills/find-CEngineServiceMgr_DeactivateLoop/SKILL.md` 记为 Failed
- optional-only 输出缺失时计为 skip
- required 输出缺失时仍按现有失败路径处理
- `skip_if_exists` 既有行为不变
- `optional_output` 不影响拓扑排序
- 对应单元测试覆盖调度语义
