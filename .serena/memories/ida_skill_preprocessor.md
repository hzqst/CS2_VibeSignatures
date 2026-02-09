# ida_skill_preprocessor

## 概述
`ida_skill_preprocessor.py` 提供技能执行前的快速预处理通道：连接 IDA MCP，优先尝试复用旧版本签名或直接生成 vtable YAML；若任一输出无法可靠生成，则返回失败让上层回退到 Agent 全流程。

## 职责
- 识别输出类型（vtable vs function）并分派到对应预处理逻辑。
- 通过 MCP `py_eval`/`find_bytes` 获取新版本地址信息，生成与技能产物兼容的 YAML 数据。
- 对 vfunc 结果补全 `vtable_name`、`vfunc_offset`、`vfunc_index`。
- 仅在“当前技能全部 expected outputs 都成功”时统一落盘，避免部分写入。
- 向 `ida_analyze_bin.py` 返回布尔结果，决定是否跳过 Agent 执行。

## 涉及文件 (不要带行号)
- ida_skill_preprocessor.py
- ida_analyze_bin.py
- bin/<gamever>/<module>/*.yaml

## 架构
入口 `preprocess_single_skill_via_mcp(...)`：
1. 连接 `http://{host}:{port}/mcp`，初始化 `ClientSession`。
2. 通过一次 `py_eval` 获取 `image_base`。
3. 遍历 `expected_outputs`：
   - 若文件名匹配 `*_vtable.{platform}.yaml`：
     - `_extract_class_name` 提取类名。
     - `_preprocess_vtable_via_mcp` 运行内置 `_VTABLE_PY_EVAL_TEMPLATE`，直接从符号/RTTI 推断 vtable 并返回结构化数据。
   - 否则走 `_preprocess_func_sig_via_mcp`：
     - 读取旧 YAML 的 `func_sig`。
     - `find_bytes`（`limit=2`）搜索新二进制，要求唯一命中。
     - `py_eval` 校验命中地址是函数起始并读取函数大小，构造 `func_va/func_rva/func_size/func_sig`。
     - 若旧 YAML 包含 `vtable_name`，则加载/按需生成对应新 vtable YAML，并在 `vtable_entries` 中反查索引补全 `vfunc_*` 字段。
4. 只有当所有输出都成功时，才调用 `write_vtable_yaml` / `write_func_yaml` 批量写盘并返回 `True`；否则返回 `False`。

辅助函数：
- `parse_mcp_result`：统一解析 MCP `CallToolResult` 的 JSON/文本。
- `_is_vtable_output`：按文件名模式判定 vtable 输出。
- `_build_vtable_py_eval`：将类名注入 py_eval 模板。
- `write_vtable_yaml`、`write_func_yaml`：按既定 key 顺序与格式写入 YAML。

## 依赖
- PyYAML（读取旧 YAML / 读取 vtable YAML）
- mcp Python SDK（`ClientSession`、`streamable_http_client`）
- IDA MCP 工具：`py_eval`、`find_bytes`
- 标准库：`json`、`os`

## 注意事项
- 该预处理是“加速路径”，任一条件不满足都会返回失败并让上层回退 Agent，属于预期行为。
- `find_bytes` 要求唯一命中；0 或多命中都视为不可用签名。
- vfunc 偏移按 `index * 8` 计算，默认按 64 位指针宽度处理。
- `_is_vtable_output` 仅按 `"_vtable."` + `.yaml` 判断，不校验平台字符串本身。
- `try/except ImportError: pass` 会吞掉导入错误；若依赖缺失，实际调用阶段才会失败。

## 调用方（可选）
- `ida_analyze_bin.py` 的 `process_binary`（在 `run_skill` 之前调用）