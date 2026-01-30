# ida_analyze_bin

## 概述
用于批量分析 CS2 二进制文件的命令行编排脚本，读取 config.yaml 后按模块/平台启动 idalib-mcp，并用 Claude/Codex 运行技能，产出各技能的 yaml 结果。

## 职责
- 解析命令行与配置，确定平台、模块与技能依赖顺序（含循环依赖告警）。
- 根据 expected_output 是否存在决定跳过/执行技能，并支持每个 skill 的 max_retries。
- 启动/等待 idalib-mcp MCP 服务，执行技能并校验输出 yaml。
- 通过 MCP 发送 idc.qexit(0) 关闭 IDA，必要时强制 kill。

## 涉及文件 (不要带行号)
- ida_analyze_bin.py
- config.yaml

## 架构
主流程 main：parse_args -> parse_config -> 遍历 modules 与 platforms -> get_binary_path -> process_binary -> 汇总统计并根据失败退出码。
process_binary：按 prerequisite 做拓扑排序 -> 展开 expected_output 的 `{platform}` 并拼到 binary 目录 -> 已存在则跳过 -> 启动 idalib-mcp -> 逐个 run_skill -> finally 调用 quit_ida_gracefully。
run_skill：根据 agent 名称选择 claude 或 codex CLI；claude 使用 `-p /{skill}` 且带 session-id/resume；codex 走 `.claude/skills/{skill}/SKILL.md`。

## 依赖
- PyYAML（yaml.safe_load）
- mcp（ClientSession、streamablehttp_client）与 asyncio
- uv + idalib-mcp（`uv run idalib-mcp ...`）
- Claude CLI 或 Codex CLI（由 `-agent` 传入）

## 注意事项
- expected_output 会按 binary_dir + `{platform}` 展开；全部存在才跳过该 skill。
- `expected_input` 仅在配置解析中保留，目前未在执行路径中使用。
- `max_retries` 可在 skill 级别覆盖全局 `-maxretry`。
- MCP 启动等待超时受 `MCP_STARTUP_TIMEOUT` 影响；失败会直接终止该二进制处理。
- 命令行参数文档与实现存在不一致：脚本头部写 `-idaargs`/默认 agent=codex，但 `parse_args` 实际是 `-ida_args` 且默认 `claude`。
- agent 名称必须包含 `claude` 或 `codex`，否则直接失败。

## 调用方（可选）
- 命令行直接执行 `ida_analyze_bin.py`
