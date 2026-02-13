# preprocess_gen_gv_sig_via_mcp

## 概述
`preprocess_gen_gv_sig_via_mcp` 是 `ida_analyze_util.py` 中用于“基于已知全局变量地址生成最短唯一签名”的异步预处理函数。它强制要求签名命中地址必须是访问该全局变量的那条指令（`gv_inst_offset = 0`），最终返回可直接写入全局变量 YAML 的字段集合。

## 职责
- 解析并校验输入参数（`gv_va`、可选 `gv_access_inst_va/gv_access_func_va`、长度与候选上限、额外通配偏移）。
- 通过 MCP `py_eval` 在 IDA 侧收集“访问目标 GV 的候选指令”及其后续可扩展指令流。
- 在 Python 侧按指令边界逐步增长签名前缀，并通过 MCP `find_bytes` 验证“唯一命中 + 命中地址等于候选 GV 访问指令地址”。
- 在多候选中选择最短可用签名，产出 `gv_va/gv_rva/gv_sig/gv_sig_va/gv_inst_*`。

## 涉及文件 (不要带行号)
- ida_analyze_util.py

## 架构
整体是“两阶段生成 + 验证”：
1. **IDA 侧候选发现（`py_eval`）**
   - `_resolve_disp_off`：从指令操作数 `offb/offo` 中定位 4-byte 位移字段，验证 `inst_ea + insn.size + disp_i32 == target_gv`。
   - `_collect_sig_stream`：从候选指令起向后采集指令流（受 `max_sig_bytes`、`max_instructions` 限制），并标记每条指令中的通配字节：
     - 操作数字节（`o_imm/o_near/o_far/o_mem/o_displ`）
     - 跳转/调用位移字节（`E8/E9/EB`、`0F 8x`、`70-7F`）
     - 首条 GV 访问指令的位移字段（`disp_off..disp_off+4`）
   - 候选来源优先级：
     - 指定 `gv_access_inst_va`：只尝试该地址
     - 否则指定 `gv_access_func_va`：遍历函数内代码头并逐条尝试
     - 否则：遍历 `DataRefsTo(target_gv)` 中代码引用
2. **Python 侧签名搜索（`find_bytes`）**
   - 将候选指令流扁平化为 token，结合 `extra_wildcard_offsets` 追加绝对偏移通配。
   - 仅在“完整指令边界”尝试前缀（且长度 >= `min_sig_bytes`，且不能全 `??`）。
   - 每个前缀调用 `find_bytes(limit=2)`：必须 `n == 1`，且唯一命中地址必须等于当前候选 `gv_inst_va`。
   - 对所有候选取最短签名作为 `best`。
3. **结果封装**
   - 成功返回：
     - `gv_inst_offset` 固定为 `0`
     - `gv_inst_length/gv_inst_disp` 来自首条 GV 访问指令
     - `gv_rva = gv_va - image_base`

```mermaid
flowchart TD
    A[参数解析/校验] --> B[py_eval: 生成 candidates]
    B --> C{candidate list 非空?}
    C -- 否 --> Z[返回 None]
    C -- 是 --> D[按候选构建 token + wildcard]
    D --> E[按指令边界递增长度]
    E --> F[find_bytes(limit=2) 唯一性验证]
    F --> G{唯一且命中==gv_inst_va?}
    G -- 否 --> E
    G -- 是 --> H[更新 best(最短)]
    H --> I{还有候选?}
    I -- 是 --> D
    I -- 否 --> J{best 存在?}
    J -- 否 --> Z
    J -- 是 --> K[返回 gv YAML 字段]
```

## 依赖
- 内部依赖：`parse_mcp_result`（解析 `py_eval/find_bytes` 返回）
- MCP 工具：`py_eval`、`find_bytes`
- IDA Python API（在 `py_eval` 脚本中）：`idaapi`、`ida_bytes`、`idautils`、`ida_ua`
- 标准库：`json`

## 注意事项
- 该函数要求 `image_base` 为可参与整数减法的值；返回阶段会计算 `gv_rva = gv_va - image_base`。
- 仅识别/验证 **4 字节位移** 的 GV 访问模式（`disp_i32`）；不覆盖其它寻址编码。
- `extra_wildcard_offsets` 是相对签名起点的绝对偏移；设置过多会使签名退化并导致无法唯一命中。
- 唯一性判定不仅要求 `find_bytes` 结果唯一，还要求命中地址与候选 `gv_inst_va` 完全一致，避免“签名唯一但锚点错位”。
- 当前仓库内未检索到该函数的直接调用点；现有全局变量预处理链路主要使用 `preprocess_gv_sig_via_mcp`（复用旧签名）。

## 调用方（可选）
- 当前仓库内无直接调用方（文本检索仅命中函数定义本身）