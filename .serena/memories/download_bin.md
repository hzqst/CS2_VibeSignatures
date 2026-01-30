# download_bin

## 概述
从 AlliedMods SourceBins 下载 CS2 二进制文件，基于 `config.yaml` 中的模块配置按版本/模块目录保存，可按平台筛选并输出汇总结果。

## 职责
- 解析命令行参数并校验配置文件
- 读取 `config.yaml` 中的模块列表并规范化模块信息
- 为每个模块/平台构建下载 URL、下载文件并落盘
- 统计成功/失败数量并以退出码反映结果

## 涉及文件 (不要带行号)
- download_bin.py
- config.yaml

## 架构
整体为单脚本串行流程：
```
parse_args
  -> parse_config (读取 modules)
    -> for each module
        -> process_module
            -> build_download_url
            -> download_file (GET 并写入 bin_dir/gamever/module/filename)
  -> 汇总成功/失败并决定退出码
```
关键点：`process_module` 负责平台选择、目标路径拼装与跳过已存在文件；`download_file` 先下载到内存再写盘以避免部分下载导致文件损坏。

## 依赖
- PyYAML（`yaml.safe_load`）
- requests（HTTP 下载）
- 文件系统（创建目录/写入文件）
- 外部网络资源：SourceBins 基础地址（默认 `https://sourcebins.alliedmods.net/cs2`）

## 注意事项
- `download_file` 会先把完整内容读入内存，若文件体积较大可能占用较多内存
- 目标文件已存在时直接跳过（计为成功）
- `config.yaml` 不存在会直接退出，模块条目缺少 `name` 会被跳过
- 若存在下载失败则退出码为 1；无模块则退出码为 0

## 调用方（可选）
- 命令行直接调用：`python download_bin.py -gamever=<version> ...`