# ida_analyze_bin

## 概述
面向 CS2 二进制分析的命令行编排脚本：读取 config.yaml 的模块/技能配置，按平台与依赖顺序启动 idalib-mcp，并调用 Claude/Codex 执行技能、生成 yaml 结果并汇总统计。

## 职责
- 解析命令行与 config.yaml，构建模块/技能列表与平台过滤。
- 对技能进行拓扑排序并根据 expected_output 判断跳过/执行。
- 启动与等待 idalib-mcp MCP 服务，按重试策略运行技能并校验输出。
- 通过 MCP 触发 IDA 退出并在必要时强制终止，输出汇总结果/退出码。

## 涉及文件 (不要带行号)
- ida_analyze_bin.py
- config.yaml
- .claude/skills/<skill>/SKILL.md

## 架构
主流程 main：parse_args -> parse_config -> 遍历 modules/platforms -> get_binary_path -> process_binary -> 统计成功/失败/跳过并根据失败数退出。
process_binary：构建 skill_map -> topological_sort_skills(Kahn)（检测循环依赖并警告）-> 展开 expected_output 的 `{platform}` 并拼到 binary_dir -> 若全部存在则跳过 -> 启动 start_idalib_mcp(uv run idalib-mcp ...) 并 wait_for_port -> 逐个 run_skill -> finally 调用 quit_ida_gracefully。
run_skill：基于 agent 名称选择 claude/codex；claude 使用 `-p /{skill}`、`--agent sig-finder`、`--allowedTools mcp__ida-pro-mcp__*` 并用 session-id/resume 支持重试；codex 使用 `codex exec "Run SKILL: .claude/skills/{skill}/SKILL.md"`。执行后按 expected_yaml_paths 校验输出是否生成。
quit_ida_gracefully：MCP py_eval 执行 `idc.qexit(0)`（5s 超时）-> 等待进程退出 -> 超时则 kill。

## 依赖
- PyYAML（yaml.safe_load）
- mcp（ClientSession、streamable_http）与 asyncio
- uv + idalib-mcp（`uv run idalib-mcp ...`）
- Claude CLI 或 Codex CLI

## 注意事项
- get_binary_path 仅取 module_path 的文件名，实际路径固定为 `{bindir}/{gamever}/{module_name}/{filename}`，不会保留配置中的子目录。
- expected_output 会先替换 `{platform}` 并拼到 binary_dir；只有全部存在才会跳过该技能。
- expected_input 仅在配置解析中保留，当前执行路径未使用。
- agent 名称必须包含 `claude` 或 `codex`，否则 run_skill 直接失败。
- MCP 启动等待超时由 `MCP_STARTUP_TIMEOUT=120s` 控制；单技能超时 `SKILL_TIMEOUT=600s`。

## 调用方（可选）
- 命令行直接执行 `ida_analyze_bin.py`
