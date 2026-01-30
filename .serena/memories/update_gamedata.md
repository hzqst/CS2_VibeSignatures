# update_gamedata

## 概述
从版本化的 YAML 签名数据生成并更新多个插件/框架的 gamedata（JSON/VDF/JSONC 等），实现跨平台签名与偏移统一同步。

## 职责
- 解析命令行参数与读取 `config.yaml`
- 读取指定 `bin_dir/gamever` 下各模块的 YAML 签名文件
- 构建函数名到库名/分类/别名的映射
- 将 YAML 签名转换到各目标格式并写回对应 gamedata 文件
- 输出更新/跳过统计

## 涉及文件 (不要带行号)
- update_gamedata.py
- config.yaml
- bin/<gamever>/<module>/<func>.<platform>.yaml
- CounterStrikeSharp/gamedata/gamedata.json
- cs2fixes/gamedata/cs2fixes.games.txt
- cs2kz/gamedata/cs2kz-core.games.txt
- SwiftlyS2/gamedata/signatures.jsonc
- SwiftlyS2/gamedata/offsets.jsonc
- plugify/gamedata/gamedata.jsonc

## 架构
核心流程为“加载配置 -> 汇总 YAML -> 按格式更新” 的串行管线：
```
parse_args
  -> load_config
  -> build_function_library_map / build_alias_to_name_map
  -> load_all_yaml_data (读取 bin_dir/gamever 下各模块签名 YAML)
  -> update_counterstrikesharp (JSON)
  -> update_cs2fixes (VDF)
  -> update_cs2kz (VDF)
  -> update_swiftlys2 (JSONC: signatures/offsets)
  -> update_plugify (JSONC)
```
格式转换由 `convert_sig_to_css` / `convert_sig_to_cs2fixes` / `convert_sig_to_swiftly` 负责；对含 `::` 的名称通过 `normalize_func_name_colons_to_underscore` 与 `alias_to_name_map` 做映射。VDF 输出会处理反斜杠转义以匹配目标插件格式要求。

## 依赖
- PyYAML（读取 `config.yaml` 与 YAML 签名）
- requests（不使用）
- vdf（解析/生成 VDF）
- JSON/JSONC 读写（自带 json + JSONC 去注释）
- 目录结构：`bin/<gamever>/<module>/` 与各插件 gamedata 目标路径

## 注意事项
- `config.yaml` 中 `catagory` 字段为拼写错误但被沿用，映射时需依赖该字段
- JSONC 写回不保留注释（`save_jsonc` 直接写入纯 JSON）
- YAML 不存在会打印 Warning 并跳过
- `::` 名称与别名映射不完整时会导致跳过
- VDF 输出需替换 `\\x` 为 `\x`，否则 CS2Fixes/CS2KZ 读取不匹配

## 调用方（可选）
- 命令行直接调用：`python update_gamedata.py -gamever=<version> ...`