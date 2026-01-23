---
name: find-GetCSWeaponDataFromKey
description: |
  IDA Pro 字符串分析与函数逆向工作流。通过 ida-pro-mcp 连接 IDA Pro 进行二进制分析，定位GetCSWeaponDataFromKey函数。
  使用场景：
  (1) 在二进制文件中搜索特定字符串
  (2) 查找字符串的交叉引用 (xrefs)
  (3) 反编译引用字符串的函数并查看伪代码
  (4) 在伪代码中定位特定代码片段
  (5) 重命名函数、变量以提高可读性
  (6) 分析函数调用关系和数据流
  触发词：GetCSWeaponDataFromKey
---

# IDA Pro 字符串分析工作流

## 前置条件

- IDA Pro 已打开目标二进制文件
- ida-pro-mcp 服务已连接

## 工作流程

### 1. 搜索字符串

使用 `mcp__ida-pro-mcp__find_regex` 搜索目标字符串：

```
find_regex(pattern="target_string")
```

返回结果包含匹配的字符串及其地址。从结果中选择精确匹配的条目。

### 2. 查找交叉引用

使用 `mcp__ida-pro-mcp__xrefs_to` 查找字符串的所有引用：

```
xrefs_to(addrs="0xADDRESS")
```

返回引用该字符串的所有位置，包括：
- 引用地址
- 引用类型 (data/code)
- 所在函数名和地址

### 3. 反编译函数

使用 `mcp__ida-pro-mcp__decompile` 获取伪代码：

```
decompile(addr="0xFUNC_ADDR")
```

伪代码中每行末尾的注释 `/*0xXXXXXX*/` 标识该行对应的地址。

### 4. 定位代码片段

在伪代码中查找目标代码时：
- 使用地址注释 `/*0xXXXXXX*/` 精确定位
- 关注函数调用的参数类型和值
- 识别关键的条件分支和数据流

### 5. 重命名函数/变量

使用 `mcp__ida-pro-mcp__rename` 进行重命名：

**重命名函数：**
```
rename(batch={"func": {"addr": "0xADDR", "name": "NewFuncName"}})
```

**重命名局部变量：**
```
rename(batch={"local": {"func_addr": "0xFUNC", "old": "v1", "new": "newName"}})
```

**重命名全局变量：**
```
rename(batch={"data": {"old": "dword_XXX", "new": "g_newName"}})
```

## 常用工具速查

| 任务 | 工具 | 关键参数 |
|------|------|----------|
| 搜索字符串 | `find_regex` | pattern |
| 搜索字节 | `find_bytes` | patterns (支持 ?? 通配符) |
| 交叉引用 | `xrefs_to` | addrs |
| 反编译 | `decompile` | addr |
| 反汇编 | `disasm` | addr |
| 列出函数 | `list_funcs` | filter, count, offset |
| 函数调用图 | `callgraph` | roots, max_depth |
| 被调用函数 | `callees` | addrs |
| 重命名 | `rename` | batch |
| 设置类型 | `set_type` | edits |
| 添加注释 | `set_comments` | items |

## 分析技巧

### 识别字符串用途

字符串常见用途：
- 实体类名 (如 `smokegrenade_projectile`)
- 源文件路径 (如 `../../game/shared/xxx.cpp`)
- 调试信息和错误消息
- 配置键名

### 函数参数分析

关注：
- 字符串作为第几个参数传入
- 返回值如何被使用
- 条件分支的判断逻辑

### 偏移量分析

伪代码中的偏移量 (如 `*(v11 + 3584)`) 通常对应结构体字段，可结合 `set_type` 应用结构体定义。
