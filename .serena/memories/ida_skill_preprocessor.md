# ida_skill_preprocessor

## 概述
`ida_skill_preprocessor.py` 现在是“预处理分发入口”：负责建立 IDA MCP 会话、获取 `image_base`，然后把具体预处理逻辑委托给 `ida_preprocessor_scripts/{skill_name}.py`。

与旧流程不同：不再在入口里硬编码按输出类型分支（vtable/function）。具体流程由每个 skill 脚本自行决定。

## 职责
- 动态加载并缓存 `ida_preprocessor_scripts/{skill_name}.py` 的导出方法 `preprocess_skill`。
- 连接 MCP（`ClientSession` + `streamable_http_client`），统一初始化会话。
- 通过一次 `py_eval` 获取 `image_base`，作为上下文参数传给 skill 脚本。
- 调用 skill 脚本导出方法（支持 async/sync），把结果归一为布尔值返回给上层。
- 在脚本缺失、导出方法缺失、脚本执行异常、MCP连接异常时返回 `False`，让上层回退到 Agent 流程。

## 涉及文件 (不要带行号)
- ida_skill_preprocessor.py
- ida_analyze_util.py
- ida_preprocessor_scripts/*.py
- ida_preprocessor_scripts/find-CTriggerPush_vtable.py
- ida_preprocessor_scripts/find-CTriggerPush_Touch.py
- ida_analyze_bin.py

## 架构
入口 `preprocess_single_skill_via_mcp(...)`：
1. 通过 `_get_preprocess_entry(skill_name)` 加载 `ida_preprocessor_scripts/{skill_name}.py`。
   - 期望脚本导出可调用对象 `preprocess_skill`。
   - 脚本入口会被缓存，避免重复导入开销。
2. 若脚本不存在/导出方法无效，直接返回 `False`。
3. 建立 MCP 会话并初始化。
4. 用一次 `py_eval` 获取 `image_base`。
5. 调用脚本导出方法：
   - 传入参数：`session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug`。
   - 若返回 awaitable 则 `await`，最后 `bool(result)` 作为预处理结果。
6. 任何异常均返回 `False`。

### skill 脚本约定
- 文件名：`ida_preprocessor_scripts/{skill_name}.py`
- 导出方法：`preprocess_skill(...)`
- 大多数脚本只需声明常量并委托给 `preprocess_common_skill`：
  - func/vfunc 脚本：声明 `TARGET_FUNCTION_NAMES`，传 `func_names=TARGET_FUNCTION_NAMES`
  - gv 脚本：声明 `TARGET_GLOBALVAR_NAMES`，传 `gv_names=TARGET_GLOBALVAR_NAMES`
  - vtable 脚本：声明 `TARGET_CLASS_NAME`，传 `vtable_class_names=[TARGET_CLASS_NAME]`
  - 混合脚本：可同时传多个参数
- 特殊脚本（如 CTriggerPush_Touch、CBaseTrigger_StartTouch、CPointTeleport_Teleport）有自定义逻辑，直接使用底层方法

## 公共能力 ida_analyze_util.py

- MCP结果解析：`parse_mcp_result`
- vtable py_eval模板与构建：`_VTABLE_PY_EVAL_TEMPLATE`、`_build_vtable_py_eval`
- YAML写盘：`write_vtable_yaml`、`write_func_yaml`、`write_gv_yaml`
- `preprocess_vtable_via_mcp`：按类名在 IDA 中定位并读取 vtable，输出标准化 vtable YAML 数据。
- `preprocess_func_sig_via_mcp`：优先复用旧 `func_sig` 定位函数，缺失时回退 `vfunc_sig` + vtable 索引并补全新函数元数据。
- `preprocess_gen_func_sig_via_mcp`：从函数头自动生成最短唯一 `func_sig`，用于新版本函数定位与写盘。
- `preprocess_gen_gv_sig_via_mcp`：围绕访问全局变量的指令生成最短唯一 `gv_sig`，并返回指令位移元数据。
- `preprocess_gv_sig_via_mcp`：复用旧 `gv_sig` 在新二进制中重定位全局变量并重建 `gv_*` 字段。
- **`preprocess_common_skill`**：统一的 `preprocess_skill` 模板函数，支持 func/vfunc、gv、vtable 三种目标类型的任意组合。大多数 skill 脚本只需声明常量并委托给此函数。

其中 `write_vtable_yaml` / `write_func_yaml` 现使用 `yaml.safe_dump` 导出：
- 保证 key 集合与顺序控制（`sort_keys=False`）
- 具体标量引号/样式由 PyYAML 决定

## 依赖
- PyYAML（读写 YAML）
- mcp Python SDK（`ClientSession`、`streamable_http_client`）
- IDA MCP 工具：`py_eval`、`find_bytes`
- 标准库：`importlib.util`、`inspect`、`re`、`pathlib`、`json`、`os`

## 注意事项
- 预处理属于“加速路径”：返回 `False` 是可接受结果，上层会回退 Agent SKILL。
- 现在“是否预处理成功”由脚本控制；脚本应自行保证输出完整性。
- `preprocess_func_sig_via_mcp` 仍要求 `find_bytes` 唯一命中；0或多命中都会失败。
- vfunc 偏移仍按 `index * 8` 计算（64位假设）。
- 若缺少脚本或脚本导出不符合约定，该 skill 会直接走 Agent SKILL，不会阻断主流程。

## 调用方（可选）
- `ida_analyze_bin.py` 的 `process_binary`（在 `run_skill` 之前调用）
