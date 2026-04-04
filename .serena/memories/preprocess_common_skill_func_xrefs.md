# preprocess_common_skill func_xrefs

## Summary
- `preprocess_common_skill` no longer accepts `func_xref_strings`
- Unified fallback parameter is `func_xrefs`

## Contract
- `func_xrefs` item format: `(func_name, xref_strings_list, xref_funcs_list)`
- `xref_strings_list` and `xref_funcs_list` cannot both be empty

## Dependency resolution
- `xref_funcs_list` resolves dependency addresses only from current-version YAML in `new_binary_dir`
- YAML path pattern: `{func_name}.{platform}.yaml`
- Required field: `func_va`
- Do not read `old_yaml_map`
- Do not trust existing IDA names for dependency resolution

## Operational notes
- Skill ordering in `config.yaml` must ensure dependency YAML exists before a `func_xrefs` script runs
- `func_xrefs` supports string-only, func-only, and mixed string+func intersection
- `CNetworkGameClient_ProcessPacketEntities` now depends on `CNetworkGameClient_ProcessPacketEntitiesInternal.{platform}.yaml`
