# ida_analyze_bin

## 概述
用于批量分析 CS2 二进制文件的命令行编排脚本，读取配置后按模块/平台驱动 IDA Pro MCP 启动与技能执行，产出每个技能(skill)的 yaml 结果。

## 职责
- 解析命令行参数与配置文件，确定模块、平台与技能(skills)列表。
- 按技能依赖进行拓扑排序，并跳过所有 expected_output 已存在的技能。
- 启动/等待 idalib-mcp 服务，按技能调用 agent（claude/codex）并统计结果。
- 通过 MCP 尝试优雅退出 IDA，必要时强制结束进程。

## 涉及文件 (不要带行号)
- ida_analyze_bin.py
- config.yaml（默认配置文件；路径可由 `-configyaml` 参数指定）

## 架构
主流程由 `main` 负责串联：

```
main
  -> parse_args / parse_config
  -> for module + platform
       -> get_binary_path
       -> process_binary
            -> topological_sort_skills
            -> skip if all expected_output exist
            -> start_idalib_mcp (uv run idalib-mcp)
            -> for skill: run_skill -> expected_output yamls
            -> quit_ida_gracefully (MCP py_eval idc.qexit)
```

核心分层：
- 配置/参数层：`parse_args`、`parse_config` 产出模块与技能(skills)信息。
- 编排层：`main` 负责模块/平台循环与统计汇总。
- 执行层：`process_binary` 管理 IDA 生命周期与技能执行顺序；`run_skill` 负责 CLI 调用与重试。
- 资源退出层：`quit_ida_via_mcp` / `quit_ida_gracefully` 保障 IDA 关闭。

## 数据结构
config.yaml 中每个模块包含 `skills` 列表，每个 skill 包含：
- `name`: 技能名称（如 `find-CServerSideClient_vtable`）
- `expected_output`: 期望生成的 yaml 文件列表（支持 `{platform}` 占位符）
- `expected_input`: 期望输入的 yaml 文件列表（可选）
- `prerequisite`: 前置依赖的技能名称列表（可选）

## 依赖
- PyYAML（`yaml.safe_load`）
- idalib-mcp（通过 `uv run idalib-mcp` 启动）
- Claude CLI / Codex CLI（技能执行）
- MCP Python 客户端（`streamablehttp_client`、`ClientSession`）
- Python 标准库：argparse、os/sys、pathlib、socket、time、subprocess、asyncio、uuid

## 注意事项
- 产物 yaml 路径由 skill 的 `expected_output` 指定，支持 `{platform}` 占位符展开。
- 只有当 skill 的所有 `expected_output` 文件都存在时才跳过该 skill。
- `run_skill` 会验证所有 `expected_output` 文件是否生成，未全部生成则重试。
- MCP 端口启动超时会直接判失败并中止该二进制的处理。
- `quit_ida_gracefully` 超时会强制 kill，极端情况下可能影响 IDB 完整性。
- 需确保 claude/codex 可执行文件在 PATH 中（或由 `CODEX_CMD` 常量指向）。

## 调用方（可选）
- 命令行直接执行 `ida_analyze_bin.py`