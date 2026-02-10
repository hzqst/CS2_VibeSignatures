# ida_analyze_bin

## 概述
`ida_analyze_bin.py` 是IDA二进制分析总编排脚本：按 `config.yaml` 的模块/技能配置遍历平台二进制，先尝试通过 `ida_skill_preprocessor` 复用旧版本签名快速生成 YAML，失败时再回退到 Claude/Codex 执行技能。

## 职责
- 解析命令行参数并规范化平台/模块过滤（含 `-oldgamever` 推断、`-maxretry`、`-modules`）。
- 读取 `config.yaml`，提取模块与技能元数据（`expected_output` / `expected_input` / `prerequisite` / `max_retries`）。
- 对技能按依赖做拓扑排序，按输出文件存在性决定跳过或执行。
- 启动并等待 `idalib-mcp`，对每个技能执行“预处理优先、Agent 回退”的双阶段流程。
- 汇总成功/失败/跳过数量，统一关闭 IDA 进程并以失败数决定退出码。

## 涉及文件 (不要带行号)
- ida_analyze_bin.py
- ida_skill_preprocessor.py
- config.yaml
- .claude/skills/<skill>/SKILL.md

## 架构
主入口 `main`：
1. `parse_args`：解析参数，平台仅允许 `windows/linux`；`oldgamever` 未显式给定时会尝试 `int(gamever)-1`，传 `none` 可禁用旧版本复用。
2. `parse_config`：读取模块和技能配置，保留每个技能的依赖与重试参数。
3. 逐模块逐平台处理：
   - 通过 `get_binary_path` 生成 `{bindir}/{gamever}/{module}/{filename}`。
   - 若存在 `oldgamever` 目录，则构造 `old_binary_dir` 用于签名复用。
   - 调用 `process_binary` 执行该二进制的全部技能。
4. 输出总计并在 `total_fail > 0` 时 `sys.exit(1)`。

`process_binary` 核心流程：
- `topological_sort_skills`（Kahn）得到技能顺序。
- 展开 `expected_output` 里的 `{platform}` 并拼接到 `binary_dir`；若输出全存在则跳过。
- 仅当有待处理技能时才 `start_idalib_mcp`。
- 对每个技能：
  - 若有 `old_binary_dir`，先构造 `old_yaml_map` 并调用 `preprocess_single_skill_via_mcp(...)`。
  - 预处理成功则直接记成功；失败则调用 `run_skill(...)` 走 Agent。
- `finally` 中调用 `quit_ida_gracefully`：优先 MCP `py_eval(idc.qexit(0))`，超时后 `kill`。

`run_skill` 流程：
- 根据 `agent` 名称包含关系分派：
  - Claude：`-p /{skill}` + `--agent sig-finder` + `--allowedTools mcp__ida-pro-mcp__*`，并用 `--session-id/--resume` 做重试续跑。
  - Codex：`codex exec "Run SKILL: .claude/skills/{skill}/SKILL.md"`。
- 每次尝试均校验退出码和 `expected_yaml_paths` 是否全部落盘；失败按 `max_retries` 重试。

## 依赖
- PyYAML（`yaml.safe_load`）
- asyncio + mcp Python SDK（`ClientSession`、`streamable_http_client`）
- `uv` + `idalib-mcp`（本地 MCP 服务）
- Claude CLI 或 Codex CLI（按 `-agent` 选择）

## 注意事项
- 默认 `agent` 为 `claude`（不是 `codex`）。
- `get_binary_path` 只取配置路径的文件名，不保留原子目录层级。
- `expected_input` 在 `process_binary` 中会在执行技能前检查：展开 `{platform}` 后拼接 `binary_dir`，若有文件缺失则记为失败并输出缺失文件名提示。
- 仅当 `old_binary_dir` 存在时才会触发签名复用预处理；否则直接走 Agent SKILL。
- `preprocess_single_skill_via_mcp` 当前为脚本分发模式：按 skill 名动态加载 `ida_preprocessor_scripts/{skill_name}.py` 的 `preprocess_skill`，脚本缺失或失败时回退 Agent。
- 技能级 `max_retries` 可覆盖命令行 `-maxretry`。
- 若 MCP 启动失败，当前二进制所有待处理技能都记为失败。

## 调用方（可选）
- 命令行直接执行 `ida_analyze_bin.py`