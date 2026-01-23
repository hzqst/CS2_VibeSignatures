---
name: find-CCSPlayerPawnBase_PostThink
description: |
  IDA Pro 字符串分析与函数逆向工作流。通过 ida-pro-mcp 连接 IDA Pro 进行二进制分析，定位CCSPlayerPawnBase_PostThink函数。
  使用场景：
  (1) 在二进制文件中搜索特定字符串
  (2) 查找字符串的交叉引用 (xrefs)
  (3) 反编译引用字符串的函数并查看伪代码
  (4) 在伪代码中定位特定代码片段
  (5) 重命名函数、变量以提高可读性
  (6) 分析函数调用关系和数据流
  触发词：CCSPlayerPawnBase_PostThink
---

# CCSPlayerPawnBase_PostThink 函数定位工作流

## 概述

此工作流用于在 CS2 服务端二进制文件中定位 `CCSPlayerPawnBase_PostThink` 函数。该函数是玩家Pawn的PostThink处理函数，负责处理购买区域、炸弹区域、救援区域的进入/退出事件。

## 定位步骤

### 1. 搜索特征字符串

使用 `find_regex` 搜索 `enter_buyzone` 字符串：

```
mcp__ida-pro-mcp__find_regex(pattern="enter_buyzone")
```

预期结果：找到字符串地址 `0x7f6cde`

* 如果找到的地址不是0x7f6cde，也是正常的，0x7f6cde是旧版本server.so的地址，新版不一定是这个地址，下同。

### 2. 查找交叉引用

使用 `xrefs_to` 查找引用该字符串的位置：

```
mcp__ida-pro-mcp__xrefs_to(addrs="0x7f6cde")
```

预期结果：找到函数 `sub_9E0280`

### 3. 重命名函数

使用 `rename` 将函数重命名为有意义的名称：

```
mcp__ida-pro-mcp__rename(batch={"func": {"addr": "0x9E0280", "name": "CCSPlayerPawnBase_PostThink"}})
```

### 4. 反编译查看伪代码

使用 `decompile` 查看函数伪代码：

```
mcp__ida-pro-mcp__decompile(addr="0x9E0280")
```

## 函数特征

`CCSPlayerPawnBase_PostThink` 函数包含以下特征字符串：

- `enter_buyzone` / `exit_buyzone` - 购买区域事件
- `enter_bombzone` / `exit_bombzone` - 炸弹区域事件
- `enter_rescue_zone` / `exit_rescue_zone` - 救援区域事件
- `weapon_c4` - C4炸弹检测
- `SpottedLooseBomb` - AFK玩家掉落炸弹提示

## 关键偏移量

| 偏移量 | 用途 |
|--------|------|
| a1 + 4872 | 是否在购买区域标志 |
| a1 + 7612 | 是否在炸弹区域标志 |
| a1 + 7613 | 炸弹区域状态 |
| a1 + 4873 | 是否在救援区域标志 |
| a1 + 4875 | 救援区域状态 |
| a1 + 3824 | 玩家武器容器指针 |

## 相关函数

- `sub_10CA560` - 检测是否在购买区域
- `sub_10CA6A0` - 检测是否可以购买
- `sub_12929F0` - 查找指定武器
- `qword_20E1CC0` - 游戏事件管理器
