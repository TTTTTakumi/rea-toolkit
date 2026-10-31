# rea-toolkit

> rea（Reverse Engineer Anything）MCP 生态的**补丁执行层**：补齐「分析 → 写回 → 验证」闭环。

[![PyPI - Version](https://img.shields.io/pypi/v/rea-toolkit)](https://pypi.org/project/rea-toolkit/)
[![Python Versions](https://img.shields.io/pypi/pyversions/rea-toolkit)](https://pypi.org/project/rea-toolkit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 为什么做这个

[rea-agents](https://github.com/morluto/rea) 是目前最热门的逆向分析 MCP server（约 1.7 万星），提供 170+ 个**只读**分析工具：反编译、伪代码、字符串、引用、抓包、APK/固件拆解……原始文件字节**永不被修改**。

但逆向工作流最后一步往往是**写回**：改掉某个跳转、改配置、调参数。rea 本身不做这件事——这就是 rea-toolkit 的定位：

| | rea | rea-toolkit |
|---|---|---|
| 定位 | 只读分析（170+ 工具） | 补丁写回（12 工具） |
| 文件改动 | 永不改动原文件 | 保护式写回 + 备份回滚 |
| 使用方式 | MCP / CLI | MCP / CLI，与 rea 互补 |

两层补丁能力，覆盖从 exe 到配置文件的全部写回场景：

- **二进制补丁** `rea_patcher`：PE 认知（VA/偏移换算）、hex 补丁、掩码通配、JSON 批量清单、dry-run 预览、回读校验、失败自动回滚。
- **多语言文本/代码补丁** `rea_text_patcher`：replace / regex / line / json / ini 五种操作原语，编码自适应（UTF-8/GBK/UTF-16），保留结构、注释与缩进，同样带备份回滚。

## 安装

```bash
pip install mcp
pip install rea-toolkit     # 或从源码: pip install .
```

## CLI 快速开始

### 二进制补丁（rea-patcher）

```bash
# 查看 PE 概况（镜像基址 / 段表 / SHA-256）
rea-patcher info game.exe

# dump 文件偏移处字节
rea-patcher dump game.exe 0x434 16

# 打补丁：偏移:旧字节:新字节（可多次 -p；va0x 前缀自动按 image base 换算）
rea-patcher patch game.exe -p 0x434:7508EB02:90909090

# 掩码通配（? 任意字节）+ dry-run 预览
rea-patcher patch game.exe -p "0x100:75??EB??:9090E9??" --dry-run

# JSON 清单批量补丁（可复用、可交接）
rea-patcher patch game.exe --manifest patches.json

# 校验 / 恢复 / 哈希
rea-patcher verify game.exe 0x434 90909090
rea-patcher restore game.exe --force
rea-patcher sha256 game.exe
```

### 文本/代码补丁（rea-text-patcher）

```bash
# 只读查看（自动识别编码）
rea-text-patcher view app.py -s 1 -e 20

# 只读搜索定位
rea-text-patcher search main.py "hp_max" -r

# 打文本补丁（op 为 JSON，可多次 -o）：
rea-text-patcher patch app.py -o '{"op":"replace","old":"a","new":"b"}'
rea-text-patcher patch cfg.json -o '{"op":"json","path":"player.hp","new_value":9999}'
rea-text-patcher patch game.ini -o '{"op":"ini","section":"Graphics","key":"Width","new_value":2560}'

# 校验 / 恢复
rea-text-patcher verify app.py --contains "b"
rea-text-patcher restore app.py --force
```

## 文本补丁 ops 一览

| op | 用途 | 关键参数 |
|----|------|----------|
| replace | 字符串精确替换 | old, new, count / occurrence |
| regex | 正则替换 | pattern, replace, flags |
| line | 行级操作 | action=replace/insert_before/insert_after/delete, line, content, expected |
| json | JSON 键值修改 | path(a.b[0].c), new_value, old_value |
| ini | INI/CFG 键值修改 | section, key, new_value, expected_value |

安全网：所有 ops 顺序执行，任一失败整批拒绝；自动备份 `<file>.reapat_txt_bak`；dry-run 只预览；写回后回读校验，失败自动回滚。

## MCP server（rea_patch_server）

作为 MCP server 接入任意支持 MCP 的 Agent（Claude Code / Codex / Cursor / Marvis 等），注册示例（stdio）：

```
command: python
args:    [<absolute path>\rea_patch_server.py]
```

### 二进制层工具

| 工具 | 说明 |
|------|------|
| rea_patch_pe_info | 只读：PE 概况 |
| rea_patch_dump | 只读：偏移处字节 |
| rea_patch_va_to_offset | VA 转文件偏移 |
| rea_patch_apply | 打补丁（保护式写回） |
| rea_patch_verify | 只读：校验偏移字节 |
| rea_patch_restore | 从备份恢复 |
| rea_patch_sha256 | 只读：文件哈希 |

### 文本/代码层工具

| 工具 | 说明 |
|------|------|
| rea_patch_text_view | 只读：按行查看文本/代码（编码自适应） |
| rea_patch_text_search | 只读：搜索定位关键字/正则，返回命中行号 |
| rea_patch_text_apply | 打文本补丁（replace/regex/line/json/ini，保护式写回） |
| rea_patch_text_verify | 只读：校验包含/不包含 |
| rea_patch_text_restore | 从文本备份恢复 |

所有偏移参数支持 `0x` 前缀十六进制字符串。

## 与同类项目对比

| | rea-toolkit | re-patch (RE-AI 生态) | hex-mcp | pyghidra-lite |
|---|---|---|---|---|
| 二进制补丁 | ✅ hex + 掩码通配 + 批量清单 | ✅ 单偏移写入 | ✅ hex 查看+补丁 | ⚠️ 仅分析，写回受限 |
| PE/VA 换算 | ✅ 内置 | ❌ | ❌ | ✅（Ghidra） |
| 文本/代码补丁 | ✅ 5 种 op 结构感知 | ❌ | ❌ | ❌ |
| 配置文件（JSON/INI） | ✅ 保留格式/注释 | ❌ | ❌ | ❌ |
| 备份/回滚 | ✅ 双引擎 | ✅ manifest | ⚠️ .bak | ⚠️ 部分 |
| 回读校验后回滚 | ✅ | ❌ | ❌ | ❌ |
| dry-run 预览 | ✅ | ❌ | ✅ | ❌ |
| 与 rea(REA) 直接互补 | ✅ | ❌（独立生态） | ❌ | ❌ |

## 测试

```bash
python -m pytest tests/ -v
```

## License

[MIT](LICENSE)
