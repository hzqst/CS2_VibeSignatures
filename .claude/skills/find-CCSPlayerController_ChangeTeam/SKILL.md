---
name: find-CCSPlayerController_ChangeTeam
description: |
  IDA Pro 字符串分析与函数逆向工作流。通过 ida-pro-mcp 连接 IDA Pro 进行二进制分析，定位CCSPlayerController_ChangeTeam函数。
  使用场景：
  (1) 在二进制文件中搜索特定字符串
  (2) 查找字符串的交叉引用 (xrefs)
  (3) 反编译引用字符串的函数并查看伪代码
  (4) 在伪代码中定位特定代码片段
  (5) 重命名函数、变量以提高可读性
  (6) 分析函数调用关系和数据流
  触发词：CCSPlayerController_ChangeTeam
---

# Find CCSPlayerController_ChangeTeam

通过 IDA Pro MCP 工具定位 CS2 服务器中的 `CCSPlayerController_ChangeTeam` 虚函数。

## 工作流程

### Step 1: 搜索 CCSPlayerController vtable

搜索包含 "CCSPlayerController" 的全局变量：

```
mcp__ida-pro-mcp__list_globals: filter="*CCSPlayerController*"
```

查找 `_ZTV19CCSPlayerController` (vtable for CCSPlayerController)，记录其地址。

### Step 2: 识别 vftable 起始地址

vtable 结构：
- offset 0: `0` (offset to this)
- offset 8: typeinfo 指针 (`_ZTI19CCSPlayerController`)
- **offset 16 (0x10)**: vftable 起始地址 (虚函数表)

如果 `_ZTV19CCSPlayerController` 在 `0x221C510`：
- vftable 起始 = `0x221C510 + 0x10` = `0x221C520`

重命名 vftable 入口：
```
mcp__ida-pro-mcp__rename: batch={"data": [{"old": "off_221C520", "new": "vftable_CCSPlayerController"}]}
```

### Step 3: 搜索 ChangeTeam 特征字符串

搜索函数特征字符串：
```
mcp__ida-pro-mcp__find_regex: pattern="ChangeTeam.*CTMDBG"
```

预期结果：`"%s<%i><%s><%s>" ChangeTeam() CTMDBG , team %d, req team %d willSwitch %d, %.2f \n"`

### Step 4: 通过 xrefs 定位函数

查找字符串的交叉引用：
```
mcp__ida-pro-mcp__xrefs_to: addrs="<string_address>"
```

获取引用该字符串的函数地址。

### Step 5: 确认函数并计算 vtable 偏移

反编译函数确认包含目标字符串：
```
mcp__ida-pro-mcp__decompile: addr="<function_address>"
```

查找函数在 vtable 中的引用：
```
mcp__ida-pro-mcp__xrefs_to: addrs="<function_address>"
```

在 xrefs 结果中找到 `.data.rel.ro` 段的引用地址，计算偏移：
```
offset = (vtable_entry_addr - vftable_base) / 8
```

### Step 6: 重命名函数

```
mcp__ida-pro-mcp__rename: batch={"func": [{"addr": "<function_address>", "name": "CCSPlayerController_ChangeTeam"}]}
```

## 预期结果

| 项目 | 值 |
|------|-----|
| vftable 基址 | `0x221C520` (vftable_CCSPlayerController) |
| ChangeTeam 函数地址 | `0x1378510` |
| vtable 条目地址 | `0x221C848` |
| **offset_CCSPlayerController_ChangeTeam** | **101** |

验证公式：
```
vftable_CCSPlayerController + 101 * 8 = 0x221C520 + 0x328 = 0x221C848
[0x221C848] = 0x1378510 = CCSPlayerController_ChangeTeam
```
