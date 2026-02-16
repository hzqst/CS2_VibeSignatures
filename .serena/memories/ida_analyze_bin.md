# ida_analyze_bin

## 概述
`ida_analyze_bin.py` 是 CS2 二进制签名分析的总编排入口：读取 `config.yaml` 后按模块/平台/技能顺序执行，优先走预处理与后处理校验，必要时再调用 Claude/Codex 技能补全 YAML 输出。

## 职责
- 解析 CLI 参数并生成运行上下文（平台过滤、模块过滤、`oldgamever` 推断、默认重试次数等）。
- 解析 `config.yaml` 的 `modules[*].skills[*]` 元数据，提取 `expected_input/expected_output/prerequisite/max_retries`。
- 对每个二进制内的技能做拓扑排序与跳过判定（输出已存在则直接跳过）。
- 启动并管理 `idalib-mcp` 生命周期（启动等待、任务执行、优雅退出/强制回收）。
- 执行“预处理 -> 后处理校验 -> 失败回退 Agent -> 再后处理校验”的双阶段流程。
- 汇总成功/失败/跳过统计，并在存在失败时以非 0 退出码结束。

## 涉及文件 (不要带行号)
- ida_analyze_bin.py
- config.yaml
- ida_skill_preprocessor.py
- ida_skill_postprocess.py
- ida_analyze_util.py
- .claude/agents/sig-finder.md
- .claude/skills/<skill>/SKILL.md

## 架构
主入口以 `main -> process_binary -> (preprocess/run_skill) -> postprocess` 的分层方式工作：

```mermaid
flowchart TD
  A[parse_args] --> B[parse_config]
  B --> C[遍历模块/平台]
  C --> D[process_binary]
  D --> E[topological_sort_skills]
  E --> F[检查 expected_output 是否已存在]
  F -->|全部存在| G[skip]
  F -->|存在待处理技能| H[start_idalib_mcp]
  H --> I[逐技能执行]
  I --> J[检查 expected_input]
  J -->|缺失| K[fail]
  J -->|满足| L[preprocess_single_skill_via_mcp]
  L -->|成功| M[postprocess_single_skill_via_mcp]
  L -->|失败| N[run_skill Claude/Codex]
  N --> M
  M -->|成功| O[success]
  M -->|失败| P[remove_invalid_yaml_outputs + fail]
  I --> Q[quit_ida_gracefully]
```

关键实现点：
- `topological_sort_skills` 使用 Kahn 算法，并对同层节点排序，保证执行顺序稳定。
- `run_skill` 按 `agent` 名称分流：
  - Claude：`--session-id/--resume` 复用会话重试。
  - Codex：读取 `.claude/agents/sig-finder.md`，去除 frontmatter 后通过 `developer_instructions=` 注入；重试时 `exec resume --last`。
- `process_binary` 中技能级 `max_retries` 可覆盖全局 `-maxretry`。

## 依赖
- 外部库：`pyyaml`、`httpx`、`mcp` Python SDK。
- 外部工具：`uv run idalib-mcp`、`claude` CLI 或 `codex` CLI。
- 内部模块：`ida_skill_preprocessor.preprocess_single_skill_via_mcp`、`ida_skill_postprocess.postprocess_single_skill_via_mcp`、`ida_skill_postprocess.remove_invalid_yaml_outputs`。

## 注意事项
- `-oldgamever` 未显式指定时会尝试 `int(gamever)-1`；`gamever` 非数字则自动禁用旧版本复用。
- `old_binary_dir` 仅检查目录存在，不保证每个旧 YAML 存在；预处理脚本需自行处理旧文件缺失。
- `ida_args` 使用字符串 `split()`，对带空格或复杂引号参数不友好。
- `expected_input` 缺失会直接记失败，不会进入 Agent 回退路径。
- 后处理校验失败会删除本次生成的 YAML，避免无效签名落盘。
- MCP 启动失败时，该二进制下所有待处理技能直接计为失败。

## 调用方（可选）
- 命令行直接执行：`python ida_analyze_bin.py -gamever 14135 [-agent=claude] [-platform windows] [-debug]`