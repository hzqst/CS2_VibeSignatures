# preprocess_common_skill func_xrefs

## Summary
- `preprocess_common_skill` 只接受统一的 `func_xrefs`；旧的 `func_xref_strings` 已经移除。
- 当前 `func_xrefs` 还能与 `func_vtable_relations` 联动，为同名函数追加 vtable-entry 候选集约束。

## Contract
- `func_xrefs` 条目格式：`(func_name, xref_strings_list, xref_funcs_list, exclude_funcs_list)`
- `xref_strings_list` 与 `xref_funcs_list` 不能同时为空
- 三个列表字段都必须只包含非空字符串
- `exclude_funcs_list` 在正向候选集求交之后、唯一性校验之前做差集过滤

## Dependency resolution
- `xref_funcs_list` 与 `exclude_funcs_list` 只会从 `new_binary_dir` 下的当前版本 YAML 读取地址
- YAML 路径模式：`{func_name}.{platform}.yaml`
- 必需字段：`func_va`
- xref 依赖解析不会读取 `old_yaml_map`
- 当同一函数也出现在 `func_vtable_relations` 中时，`preprocess_common_skill` 会把对应的 `vtable_class` 传给 `preprocess_func_xrefs_via_mcp`，让候选函数额外受 vtable entries 约束

## Operational notes
- `config.yaml` 中的 skill 顺序必须保证依赖 YAML 已在执行 `func_xrefs` 脚本前生成
- `func_xrefs` 当前支持纯字符串、纯函数、字符串+函数联合求交，以及求交后的排除过滤
- 只出现在 `func_xrefs`、不在 `func_names` 里的函数，也会被并入正常的 func 处理流水线并写出标准函数 YAML
- `CNetworkGameClient_ProcessPacketEntities` 仍依赖 `CNetworkGameClient_ProcessPacketEntitiesInternal.{platform}.yaml`
