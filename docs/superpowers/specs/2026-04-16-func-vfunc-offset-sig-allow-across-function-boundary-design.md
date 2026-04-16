# `func_sig` / `vfunc_sig` / `offset_sig` 跨函数边界签名生成设计

## 背景

当前仓库已经为 `gv_sig` 实现了 `gv_sig_allow_across_function_boundary: true` 的能力：

- 默认不允许签名生成跨越函数边界
- 只有显式声明 `: true` 才允许跨越函数尾继续取签名字节
- 跨越时采用保守策略：仅允许穿过显式 padding，并且只能在同一可执行 segment 中、从下一个 IDA 识别的代码头继续解码

但 `func_sig`、`vfunc_sig`、结构成员偏移签名链路 `offset_sig` 目前仍只能在所属函数内部取字节，且没有与 `gv_sig` 对齐的显式控制开关。

这带来两个问题：

1. 某些目标在函数内可用字节不足，签名无法达到唯一性
2. 三类签名与 `gv_sig` 的行为语义不一致，用户需要记住不同规则

本次需求是把 `gv_sig` 已有的“允许跨函数边界生成签名”的能力扩展到：

- `func_sig`
- `vfunc_sig`
- `offset_sig`

并明确保持默认收紧语义：在没有显式指定 `*_allow_across_function_boundary: true` 时，默认不允许生成的 signature 跨越函数边界。

## 目标

- 为 `func_sig` 新增 `func_sig_allow_across_function_boundary: true`
- 为 `vfunc_sig` 新增 `vfunc_sig_allow_across_function_boundary: true`
- 为 `offset_sig` 新增 `offset_sig_allow_across_function_boundary: true`
- 三类签名的默认行为统一为：不允许跨越函数边界
- 三类签名的 directive 解析规则与 `gv_sig` 完全对齐
- 三类签名的跨边界收集策略与 `gv_sig` 完全对齐
- 仅当显式启用时，输出 YAML 才回写对应 `*_allow_across_function_boundary: true`
- 不改变未显式启用目标的既有输出语义

## 非目标

- 本次不改造 `patch_sig`、`vtable` 等与本需求无关的产物类型
- 本次不修改旧 YAML 的兼容读取语义，旧 YAML 缺少该字段时仍按默认关闭处理
- 本次不顺带重构 `find_bytes` 唯一性策略
- 本次不引入 `false` 显式写法；只有 `: true` 是合法开启方式
- 本次不把 `offset_sig` 重命名为 `struct_sig`

## 方案比较

### 方案 1：抽取共享的“前向签名字节流收集器”

把 `gv_sig` 中与“按指令边界前向取字节、可选跨越函数尾”相关的部分抽成共享能力，供 `func_sig`、`vfunc_sig`、`offset_sig` 调用；三类签名继续保留各自的 wildcard 与锚点语义。

优点：

- 与 `gv_sig` 行为最一致
- 默认关闭和显式开启的语义可以完全统一
- 避免三份近似逻辑在后续演化时产生漂移
- 后续若再给其他签名类型加同类能力，扩展成本最低

缺点：

- 需要对现有生成函数做适度整理
- 共享层边界需要设计清楚，避免把不同签名类型的 wildcard 语义混在一起

### 方案 2：在三个生成函数中分别复制 `gv_sig` 的跨边界逻辑

分别在 `preprocess_gen_func_sig_via_mcp`、`preprocess_gen_vfunc_sig_via_mcp`、`preprocess_gen_struct_offset_sig_via_mcp` 内部各自嵌入一套跨边界收集逻辑。

优点：

- 改动路径直接
- 每个生成函数都可独立落地

缺点：

- 重复代码明显
- 后续很难保证三处逻辑持续一致
- 与仓库里已经存在的 `gv_sig` 经验难以形成统一抽象

### 方案 3：只补 directive 解析与参数透传，暂不统一跨边界逻辑

先增加字段解析和参数透传，只在个别路径做能力开放，其他路径延后补齐。

优点：

- 初期改动最小

缺点：

- 不满足本次统一支持三类签名的目标
- 会制造半完成状态，后续仍需返工

## 选定方案

采用方案 1：抽取共享的“前向签名字节流收集器”，统一三类签名的跨边界收集策略。

该方案是满足当前需求的最小充分方案：

- 共享“能否继续向后收集字节”的边界控制
- 保留各签名类型自己的锚点与 wildcard 规则
- 保持默认收紧，只有显式 `: true` 才开启

## 详细设计

### 1. 新增 directive 与严格解析规则

`_normalize_generate_yaml_desired_fields(...)` 新增三个合法 directive：

- `func_sig_allow_across_function_boundary: true`
- `vfunc_sig_allow_across_function_boundary: true`
- `offset_sig_allow_across_function_boundary: true`

解析规则与 `gv_sig_allow_across_function_boundary` 保持完全一致：

- bare 字段非法，例如 `func_sig_allow_across_function_boundary`
- 重复 directive 非法
- 只有值为 `true` 合法
- `false`、空值、其他字符串都视为非法输入

规范化结果仍然写入 `generation_options`，供后续生成阶段读取。

### 2. 字段白名单与稳定输出顺序

需要扩展现有字段白名单与输出顺序定义。

#### 2.1 `func` / `vfunc`

在 `FUNC_YAML_ORDER` 中增加：

- `func_sig_allow_across_function_boundary`
- `vfunc_sig_allow_across_function_boundary`

建议顺序为：

1. `func_name`
2. `func_va`
3. `func_rva`
4. `func_size`
5. `func_sig`
6. `func_sig_allow_across_function_boundary`
7. `vtable_name`
8. `vfunc_offset`
9. `vfunc_index`
10. `vfunc_sig`
11. `vfunc_sig_max_match`
12. `vfunc_sig_allow_across_function_boundary`

#### 2.2 `struct_member`

在 `STRUCT_MEMBER_YAML_ORDER` 中增加：

- `offset_sig_allow_across_function_boundary`

建议顺序为：

1. `struct_name`
2. `member_name`
3. `offset`
4. `size`
5. `offset_sig`
6. `offset_sig_disp`
7. `offset_sig_allow_across_function_boundary`

只要对应字段未启用，就不写入最终 YAML。

### 3. 共享的前向字节流收集层

抽取一个共享层，只负责：

- 从给定起始指令地址开始
- 按指令边界向前解码并收集字节
- 在需要时遵循统一规则跨越函数尾

该共享层不负责：

- 决定签名起点是什么
- 决定哪些字节应 wildcard
- 决定唯一性判定条件

它只负责提供“可供签名候选器消费的指令流”。

### 4. 跨函数边界的统一收集策略

共享层的跨边界行为与现有 `gv_sig` 保持一致：

- 默认情况下，收集上限为当前函数 `end_ea`
- 当且仅当 `allow_across_function_boundary=True` 时，才允许继续向后
- 继续向后时必须满足：
  - 仍位于同一个可执行 segment
  - 函数尾与下一个代码头之间只能出现显式 padding
  - 允许的 padding 字节仅为 `0xCC` 和 `0x90`
  - 只能在 IDA 标记为 code head 的地址恢复指令解码
- 任一条件不满足时立即停止当前候选的继续扩展

该策略是保守扩展，而不是“忽略函数边界自由扫字节”。

### 5. 三类签名各自保留的语义层

虽然跨边界收集由共享层统一，但三类签名仍保留各自的生成规则。

#### 5.1 `func_sig`

- 锚点仍然是目标函数入口
- volatile operand wildcard 规则保持现状
- 签名唯一性仍要求唯一匹配且匹配地址等于函数入口

只改变一件事：当函数内字节不足时，若显式启用允许跨边界，则可继续向后取更多指令参与候选签名。

#### 5.2 `vfunc_sig`

- 锚点仍然是目标 vcall 指令
- 首条指令中编码 `vfunc_offset` 的关键字节仍必须保持 slot 特异性
- 后续指令的 wildcard 规则保持现状
- 现有 `vfunc_sig_max_match` 语义不变

只改变候选字节流的可扩展范围，不改变 `vfunc_sig` 的判定语义。

#### 5.3 `offset_sig`

- 锚点仍然是结构成员偏移所在指令 `offset_inst_va`
- `offset_sig_disp` 默认仍为 `0`
- 当前 struct-offset 的 wildcard 规则保持现状
- 唯一性仍要求匹配地址等于 `offset_inst_va`

也就是说，本次是让 `offset_sig` 在必要时可以借用函数尾后的额外稳定字节，而不是改变其偏移恢复模型。

### 6. 调度层参数透传

统一调度层需要把 `generation_options` 中的新开关透传到对应生成器。

至少覆盖以下路径：

- `preprocess_common_skill(...)` 中直接生成 `func_sig` 的路径
- `preprocess_common_skill(...)` 中直接生成 `vfunc_sig` 的路径
- `preprocess_common_skill(...)` 中直接生成 `offset_sig` 的路径
- 其他复用 `preprocess_gen_func_sig_via_mcp(...)`、`preprocess_gen_vfunc_sig_via_mcp(...)`、`preprocess_gen_struct_offset_sig_via_mcp(...)` 的直接调用点

要求是：

- 未透传时，生成器默认值必须是 `False`
- 只有当目标 symbol 在 `generate_yaml_desired_fields` 中显式声明 `: true` 时，才把参数置为 `True`

### 7. YAML 回写策略

输出层采用与 `gv_sig` 相同的持久化语义：

- 如果本次目标开启了 `func_sig_allow_across_function_boundary: true`，则最终 `func` / `vfunc` YAML 中写入该字段
- 如果本次目标开启了 `vfunc_sig_allow_across_function_boundary: true`，则最终 `func` / `vfunc` YAML 中写入该字段
- 如果本次目标开启了 `offset_sig_allow_across_function_boundary: true`，则最终 struct-member YAML 中写入该字段
- 未启用时不写字段

这样可以确保：

- 新生成 YAML 能准确表达其签名生成语义
- 未启用目标保持现有 YAML 形态，不引入额外噪音

### 8. 错误处理

错误处理策略统一与 `gv_sig` 看齐：

- 非法 directive 在规范化阶段直接失败
- 生成器若开启跨边界后仍无法形成合法唯一签名，不做宽松降级
- 跨边界过程中如果遇到非 padding、segment 变化、非 code head、解码失败等情况，应立即停止该候选的继续扩展
- 最终若所有候选都无法满足唯一性要求，则整个 symbol 生成失败

这里的关键点是：允许跨边界并不等于放宽签名质量要求。

### 9. 兼容性与行为约束

本次必须保证以下兼容性：

- 旧 YAML 没有新字段时，默认视为关闭
- 未显式声明新 directive 的脚本，输出结果不得因为本次改动而开始跨边界生成签名
- `gv_sig` 现有行为不得退化
- `vfunc_sig_max_match` 与新字段可以共存，二者语义互不覆盖

## 数据流摘要

本次数据流可以概括为三层：

1. 解析层
   - 解析 `generate_yaml_desired_fields`
   - 识别新 directive
   - 写入 `generation_options`
2. 生成层
   - 将 `generation_options` 透传到对应签名生成器
   - 生成器使用共享前向字节流收集层
3. 输出层
   - 仅当显式启用时，把对应 `*_allow_across_function_boundary: true` 注入最终 YAML

## 测试与验证设计

本次建议采用以回归测试为主的 Level 1 验证。

### 1. 规范化解析测试

为 `_normalize_generate_yaml_desired_fields(...)` 增加测试：

- 三个新 directive 的合法 `: true` 场景
- bare 字段非法
- 重复 directive 非法
- `false` / 空字符串 / 非 `true` 文本非法
- 新 directive 与原有 `vfunc_sig_max_match` 共存时仍能正确解析

### 2. `func_sig` 行为测试

- 默认未启用时，不允许越过 `func.end_ea`
- 启用时，允许跨过 `0xCC` / `0x90` padding 并在下一个 code head 继续
- 启用但遇到非法边界内容时，应停止扩展
- 启用时最终 payload 会写入 `func_sig_allow_across_function_boundary: true`

### 3. `vfunc_sig` 行为测试

- 默认未启用时，不允许跨边界
- 启用时可使用跨边界后的附加字节达成匹配
- 首条指令 slot 特异性保持不变
- 启用时最终 payload 会写入 `vfunc_sig_allow_across_function_boundary: true`

### 4. `offset_sig` 行为测试

- 默认未启用时，不允许跨边界
- 启用时可以跨越 padding 后继续收集候选字节
- `offset_sig_disp` 仍保持既有语义
- 启用时最终 payload 会写入 `offset_sig_allow_across_function_boundary: true`

### 5. `gv_sig` 回归测试

- 现有 `gv_sig_allow_across_function_boundary` 测试继续保留
- 确认新共享层或重构不会改变 `gv_sig` 的既有行为

## 风险与权衡

### 风险 1：共享层抽象过度

如果把 wildcard 规则、唯一性判定和前向收集全部揉进一个公共函数，会使共享层承担过多职责。

应对方式：

- 共享层只负责收集指令流与跨边界控制
- wildcard 与唯一性判定继续保留在各签名生成器内部

### 风险 2：`vfunc_sig` 首条指令语义被误泛化

`vfunc_sig` 的首条指令必须保留 slot 相关字节，不能因为共享逻辑而被削弱。

应对方式：

- 共享层只提供原始指令流
- `vfunc_sig` 仍在本地生成逻辑中单独处理首条指令

### 风险 3：`offset_sig` 路径出现重复代码

`offset_sig` 当前实现较直接，最容易在接入跨边界时复制一份新逻辑。

应对方式：

- 强制复用共享前向收集层
- 避免再为 struct-member 单独维护一套边界扫描逻辑

## 实施边界

本次实施范围限定为：

- `ida_analyze_util.py` 中 directive 解析
- `ida_analyze_util.py` 中相关字段顺序/白名单
- `ida_analyze_util.py` 中 `func_sig` / `vfunc_sig` / `offset_sig` 生成路径
- 对应单元测试与回归测试
- 必要时更新相关 Serena memory 或文档说明

不包括：

- 批量修改现有业务 skill 的字段声明
- 重命名已有字段或 YAML 文件结构
- 对所有历史产物做回写迁移

## 结论

本次设计采用“统一边界控制、保留各自签名语义”的方案：

- `func_sig`、`vfunc_sig`、`offset_sig` 新增与 `gv_sig` 对齐的 `*_allow_across_function_boundary: true`
- 默认情况下严格禁止跨函数边界
- 只有显式开启时，才允许按保守规则跨过 padding 并继续收集字节
- 输出 YAML 仅在显式开启时回写对应字段

这样既能补齐三类签名在函数内字节不足时的能力缺口，也能保持仓库整体行为模型的一致性和可维护性。
