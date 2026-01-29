# ida_analyze_bin

## 概述
用于批量分析 CS2 二进制文件的命令行编排脚本，读取配置后按模块/平台驱动 IDA Pro MCP 启动与技能执行，产出每个符号的 yaml 结果。

## 职责
- 解析命令行参数与配置文件，确定模块、平台与符号列表。
- 按符号依赖进行拓扑排序，并跳过已存在的 yaml 产物。
- 启动/等待 idalib-mcp 服务，按符号调用技能（claude/codex）并统计结果。
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
            -> topological_sort_symbols
            -> skip existing yaml
            -> start_idalib_mcp (uv run idalib-mcp)
            -> for symbol: run_skill -> {symbol}.{platform}.yaml
            -> quit_ida_gracefully (MCP py_eval idc.qexit)
```

核心分层：
- 配置/参数层：`parse_args`、`parse_config` 产出模块与符号信息。
- 编排层：`main` 负责模块/平台循环与统计汇总。
- 执行层：`process_binary` 管理 IDA 生命周期与技能执行顺序；`run_skill` 负责 CLI 调用与重试。
- 资源退出层：`quit_ida_via_mcp` / `quit_ida_gracefully` 保障 IDA 关闭。

## 依赖
- PyYAML（`yaml.safe_load`）
- idalib-mcp（通过 `uv run idalib-mcp` 启动）
- Claude CLI / Codex CLI（技能执行）
- MCP Python 客户端（`streamablehttp_client`、`ClientSession`）
- Python 标准库：argparse、os/sys、pathlib、socket、time、subprocess、asyncio、uuid

## 注意事项
- 配置文件中的依赖字段使用 `prerequsite`（拼写错误），代码按此键读取。
- 产物 yaml 路径固定为二进制文件同目录的 `{symbol}.{platform}.yaml`，已存在则跳过。
- MCP 端口启动超时会直接判失败并中止该二进制的处理。
- `quit_ida_gracefully` 超时会强制 kill，极端情况下可能影响 IDB 完整性。
- 需确保 claude/codex 可执行文件在 PATH 中（或由 `CODEX_CMD` 常量指向）。

## 调用方（可选）
- 命令行直接执行 `ida_analyze_bin.py`