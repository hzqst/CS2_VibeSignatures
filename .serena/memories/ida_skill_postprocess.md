# ida_skill_postprocess

## 概述
`ida_skill_postprocess.py` 是技能输出的后处理校验模块：在 YAML 生成后通过 IDA MCP 二次验证 `func_sig` 的可定位性与函数头合法性，并提供失败时的 YAML 清理能力。

## 职责
- 建立 MCP 会话并对单个技能的全部输出执行后处理校验。
- 逐个读取输出 YAML，抽取并校验 `func_sig`。
- 使用 `find_bytes` 验证签名唯一命中（必须恰好 1 个匹配）。
- 使用 `py_eval + idaapi.get_func` 验证命中地址是否为函数起始地址。
- 提供 `remove_invalid_yaml_outputs`，在后处理失败时删除无效产物。

## 涉及文件 (不要带行号)
- ida_skill_postprocess.py
- ida_analyze_bin.py
- ida_analyze_util.py

## 架构
后处理由 `postprocess_single_skill_via_mcp` 统一驱动，核心校验在 `validate_func_sig_in_yaml_via_mcp`：

```mermaid
flowchart TD
  A[postprocess_single_skill_via_mcp] --> B[建立 MCP 会话]
  B --> C[遍历 expected_outputs]
  C --> D[validate_func_sig_in_yaml_via_mcp]
  D --> E[读取 YAML]
  E -->|无 func_sig| F[pass]
  E -->|有 func_sig| G[find_bytes(limit=2)]
  G -->|命中数!=1| H[fail]
  G -->|命中数=1| I[py_eval idaapi.get_func]
  I -->|非函数头| H
  I -->|函数头| F
  C --> J[汇总 all_valid]
```

实现细节：
- `validate_func_sig_in_yaml_via_mcp` 通过 `parse_mcp_result` 解析 MCP 返回值，严格校验 YAML 结构与返回格式。
- `remove_invalid_yaml_outputs` 仅做文件删除与警告打印，不参与校验决策；由调用方在校验失败后触发。

## 依赖
- 外部库：`httpx`、`pyyaml`、`mcp` Python SDK。
- MCP 工具：`find_bytes`、`py_eval`。
- 内部模块：`ida_analyze_util.parse_mcp_result`。
- 标准库：`json`、`os`。

## 注意事项
- `func_sig` 缺失会被视为通过（后处理不会因此失败）。
- YAML 不是 mapping（dict）会直接判定失败。
- `find_bytes` 使用 `limit=2`，用于快速判定“唯一命中/非唯一命中”。
- 匹配地址必须是函数头（`f.start_ea == addr`），仅“落在函数体内”不算通过。
- 顶部依赖导入使用 `try/except ImportError: pass`；缺依赖时会在运行期表现为校验失败而非进程直接退出。
- 该模块本身不会自动删除失败产物；需要由上层显式调用 `remove_invalid_yaml_outputs` 执行清理。

## 调用方（可选）
- `ida_analyze_bin.py` 的 `process_binary`：
  - 预处理成功后调用 `postprocess_single_skill_via_mcp`
  - Agent 执行成功后再次调用 `postprocess_single_skill_via_mcp`
  - 校验失败时调用 `remove_invalid_yaml_outputs`