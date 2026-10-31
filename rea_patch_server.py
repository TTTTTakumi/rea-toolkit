#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rea_patch_server.py — rea 配套补丁能力的 MCP server（stdio 传输）

定位：rea MCP 只提供只读分析；本 server 补齐"写回"闭环：
文件级 hex 补丁（备份 / 预期校验 / 掩码 / dry-run / 回滚 / 恢复）。

所有工具前缀 rea_patch_*，与 rea 只读分析工具互补。

启动方式（Marvis MCP 注册）：
    python <abs path>/rea_patch_server.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rea_patcher as rp
import rea_text_patcher as rtp

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    sys.stderr.write("缺少 mcp 依赖，请先执行: pip install mcp\n")
    sys.exit(1)

mcp = FastMCP(
    "rea-patch",
    instructions=(
        "rea 配套补丁能力：文件级二进制补丁（自动备份、预期字节校验、掩码通配、"
        "dry-run 预览、回读校验、失败自动回滚、备份恢复）。所有写操作默认带保护。"
    ),
)


def _norm_num(v) -> int:
    """兼容 0x 十六进制字符串 / 十进制字符串 / int。"""
    if isinstance(v, str):
        return int(v, 0)
    return int(v)


@mcp.tool()
def rea_patch_pe_info(file_path: str) -> dict:
    """只读查看 PE 文件概况：镜像基址、段表、大小、SHA-256。"""
    return rp.get_pe_info(file_path)


@mcp.tool()
def rea_patch_dump(file_path: str, offset: int, length: int = 16) -> dict:
    """只读查看文件偏移处字节（offset 支持 0x 前缀十六进制）。"""
    off = _norm_num(offset)
    data = rp.read_file_bytes(file_path)
    if off < 0 or off >= len(data):
        raise rp.PatchError(f"偏移 0x{off:X} 超出文件大小 0x{len(data):X}")
    chunk = data[off:off + length]
    return {
        "file": file_path,
        "offset": hex(off),
        "hex": chunk.hex().upper(),
        "size": len(chunk),
    }


@mcp.tool()
def rea_patch_va_to_offset(file_path: str, va: int, image_base: int | None = None) -> dict:
    """把 VA 虚拟地址换算为文件偏移（image_base 不传时自动读 PE 头）。"""
    va_int = _norm_num(va)
    data = rp.read_file_bytes(file_path)
    base = _norm_num(image_base) if image_base not in (None, 0) else None
    off = rp.va_to_file_offset(data, va_int, base)
    return {"va": hex(va_int), "file_offset": hex(off)}


@mcp.tool()
def rea_patch_apply(
    file_path: str,
    patches: list[dict],
    image_base: int | None = None,
    force: bool = False,
    dry_run: bool = False,
) -> dict:
    """打补丁（写回原文件）。

    patches 每项:
      {"offset": "0x434 或 va0x140001234", "old": "AA??BB", "new": "909090"}
    - old 支持 ? 通配（任意字节）
    - 自动创建 <file>.reapat_bak 备份；旧字节不匹配整批拒绝
    - 写回后逐字节回读校验，不匹配自动从备份回滚
    force=true: 已有备份时仍以当前文件为基准（覆盖旧备份）
    dry_run=true: 只校验与预览，不写盘
    """
    data = rp.read_file_bytes(file_path)
    base = _norm_num(image_base) if image_base not in (None, 0) else None
    parsed = []
    for p in patches:
        spec = f"{p['offset']}:{p['old']}:{p['new']}"
        parsed.append(rp.parse_patch_spec(spec, base, data))
    return rp.apply_patches(file_path, parsed, force=force, dry_run=dry_run)


@mcp.tool()
def rea_patch_verify(file_path: str, offset: str, expected: str) -> dict:
    """校验文件偏移处字节是否符合预期（不写文件）。expected 十六进制串，如 90909090。"""
    off = _norm_num(offset)
    expect = bytes.fromhex(expected)
    got = rp.read_range(file_path, off, len(expect))
    return {
        "file": file_path,
        "offset": hex(off),
        "actual": got.hex().upper(),
        "expected": expect.hex().upper(),
        "match": got == expect,
    }


@mcp.tool()
def rea_patch_restore(file_path: str, force: bool = False) -> dict:
    """从 .reapat_bak 备份恢复原文件。force 覆盖当前文件。"""
    bak = rp.restore_file(file_path, force=force)
    return {"file": file_path, "restored_from": bak}


@mcp.tool()
def rea_patch_sha256(file_path: str) -> dict:
    """只读计算文件 SHA-256。"""
    return {"file": file_path, "sha256": rp.sha256(file_path)}


# ================================================================ 文本/代码补丁层
# 多语言代码修改：适用于所有文本文件（Python/C/C++/Java/JS/Lua/SQL/JSON/YAML/INI/XML 等）


@mcp.tool()
def rea_patch_text_view(file_path: str, start_line: int = 1,
                        end_line: int | None = None,
                        encoding: str | None = None) -> dict:
    """只读按行查看文本/代码文件（自动识别 UTF-8/GBK/UTF-16 等编码）。"""
    r = rtp.text_dump(file_path, start_line, end_line, encoding)
    return r


@mcp.tool()
def rea_patch_text_search(file_path: str, pattern: str, regex: bool = False,
                          encoding: str | None = None) -> dict:
    """只读在文本/代码文件中搜索定位关键字/正则，返回命中行号。"""
    return rtp.text_search(file_path, pattern, regex, encoding)


@mcp.tool()
def rea_patch_text_apply(
    file_path: str,
    ops: list[dict],
    encoding: str | None = None,
    force: bool = False,
    dry_run: bool = False,
) -> dict:
    """对文本/代码文件打补丁（多语言通用）。

    ops 按顺序执行，每一项:
      {"op": "replace", "old": "...", "new": "...", "count": n|None, "occurrence": n|None}
        字符串精确替换；count=只替换前 n 次；occurrence=只替换第 n 次出现
      {"op": "regex", "pattern": "...", "replace": "...", "flags": re 数值}
        正则替换（全部命中）
      {"op": "line", "action": "replace|insert_before|insert_after|delete",
       "line": 行号(1-based), "content": "...", "expected": "可选行内容校验"}
        行级操作
      {"op": "json", "path": "a.b[0].c", "new_value": ..., "old_value": 可选预期校验}
        JSON 配置键值修改（保留缩进与编码）
      {"op": "ini", "section": "...", "key": "...", "new_value": "...",
       "expected_value": 可选预期校验}
        INI/CFG 配置键值修改（保留注释与格式）

    安全网：自动备份 <file>.reapat_txt_bak；全部 ops 先内存模拟，任一失败整批拒绝；
    写盘后回读校验，失败自动从备份回滚；dry_run=true 只预览不写盘。
    """
    return rtp.apply_text_patch(file_path, ops, encoding, force, dry_run)


@mcp.tool()
def rea_patch_text_verify(file_path: str, contains: str | None = None,
                          not_contains: str | None = None,
                          regex: bool = False,
                          encoding: str | None = None) -> dict:
    """只读校验文本/代码文件是否包含/不包含某关键字或正则。"""
    return rtp.text_verify(file_path, contains, not_contains, regex, encoding)


@mcp.tool()
def rea_patch_text_restore(file_path: str, force: bool = False) -> dict:
    """从 <file>.reapat_txt_bak 文本备份恢复原文件。force 覆盖当前文件。"""
    return rtp.text_restore(file_path, force)


def main():
    """CLI 入口：启动 stdio MCP server。"""
    mcp.run()


if __name__ == "__main__":
    main()