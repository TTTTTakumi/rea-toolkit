#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rea_patch_server.py — rea 配套补丁能力的 MCP server（stdio 传输）

定位：rea MCP 只提供只读分析；本 server 补齐"写回"闭环：
文件级 hex 补丁（备份 / 预期校验 / 掩码 / dry-run / 回滚 / 恢复）、
补丁清单 v2（目标哈希+偏移范围+旧字节+证据ID 四重校验）、
路径沙箱（受保护系统目录硬拒绝 + allow_roots 白名单）、原子写入。

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
        "dry-run 预览、回读校验、失败自动回滚、备份恢复）、补丁清单 v2 四重校验、"
        "路径沙箱（受保护系统目录硬拒绝；allow_roots 白名单可限定写入范围）。"
        "所有写操作默认带保护；受保护系统目录一律拒绝，需审批的高危路径通过"
        "显式传入 allow_roots 白名单放行。"
    ),
)


def _norm_num(v) -> int:
    """兼容 0x 十六进制字符串 / 十进制字符串 / int。"""
    if isinstance(v, str):
        return int(v, 0)
    return int(v)


def _write_gate(file_path: str, allow_roots: list[str] | None = None,
                require_approval: bool = False) -> tuple[str, bool]:
    """写操作统一安全闸门：受保护系统目录硬拒绝 + 白名单沙箱 + 显式审批。
    返回 (真实路径, approval_granted)；granted=True 表示本次写入已显式审批授权。"""
    if rp.is_protected_path(file_path):
        raise rp.PatchError(
            f"路径 {file_path} 位于受保护系统目录，拒绝修改（高危审批不通过，"
            "不可通过 allow_roots 绕过）")
    real = rp.assert_path_safe(file_path, allow_roots)
    granted = rp.approval_gate(rp._norm_path(real), require_approval, allow_roots)
    return real, granted


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
    allow_roots: list[str] | None = None,
    require_approval: bool = False,
) -> dict:
    """打补丁（写回原文件）。

    patches 每项:
      {"offset": "0x434 或 va0x140001234", "old": "AA??BB", "new": "909090"}
    - old 支持 ? 通配（任意字节）
    - 自动创建 <file>.reapat_bak 备份；旧字节不匹配整批拒绝
    - 原子写入：临时文件 fsync 后 os.replace，崩溃不会留下半写文件
    - 写回后逐字节回读校验，不匹配自动从备份回滚
    force=true: 已有备份时仍以当前文件为基准（覆盖旧备份）
    dry_run=true: 只校验与预览，不写盘
    allow_roots: 可选路径白名单根目录数组，目标必须落在其中（沙箱限定）
    require_approval: 目标位于审批区时，显式传 true 授权写入（审批区由
      REA_PATCH_APPROVAL_ROOTS 配置；审批后返回与审计带 approval=granted）
    """
    _, granted = _write_gate(file_path, allow_roots, require_approval)
    data = rp.read_file_bytes(file_path)
    base = _norm_num(image_base) if image_base not in (None, 0) else None
    parsed = []
    for p in patches:
        spec = f"{p['offset']}:{p['old']}:{p['new']}"
        parsed.append(rp.parse_patch_spec(spec, base, data))
    res = rp.apply_patches(file_path, parsed, force=force, dry_run=dry_run,
                           allow_roots=allow_roots, approval=granted)
    res["approval"] = "granted" if granted else None
    return res


@mcp.tool()
def rea_patch_apply_manifest(
    file_path: str,
    manifest_path: str,
    force: bool = False,
    dry_run: bool = False,
    allow_roots: list[str] | None = None,
    require_approval: bool = False,
) -> dict:
    """按补丁清单 v2 应用补丁（四重校验，推荐入口）。

    清单 JSON:
      {"schema": 2,
       "target": {"file_sha256": "目标文件哈希（必填）", "size": 1234,
                  "evidence_id": "分析证据ID（可空）"},
       "image_base": "0x140000000（可空，PE 自动读）",
       "patches": [{"offset": "0x.. 或 va0x..", "old": "AA??", "new": "9090",
                    "offset_min": 0（可空，最小合法偏移）,
                    "evidence_id": "证据ID（可空）"}]}

    四重校验：
      1. target.file_sha256 == 当前目标文件哈希（防幻觉补丁打错目标）
      2. offset >= offset_min（防越界幻觉）
      3. old 原始字节匹配（坐标过期即拒绝）
      4. evidence_id 审计追溯（写入返回结果）

    受保护系统目录硬拒绝；可通过 allow_roots 白名单限定写入范围。
    require_approval: 目标位于审批区时，显式传 true 授权写入（审批后返回带 approval=granted）。
    """
    _, granted = _write_gate(file_path, allow_roots, require_approval)
    res = rp.apply_manifest(file_path, manifest_path, force=force,
                            dry_run=dry_run, allow_roots=allow_roots,
                            approval=granted)
    res["approval"] = "granted" if granted else None
    return res


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
def rea_patch_restore(file_path: str, force: bool = False,
                      allow_roots: list[str] | None = None,
                      require_approval: bool = False) -> dict:
    """从 .reapat_bak 备份恢复原文件。force 覆盖当前文件。"""
    _, granted = _write_gate(file_path, allow_roots, require_approval)
    bak = rp.restore_file(file_path, force=force, allow_roots=allow_roots,
                          approval=granted)
    return {"file": file_path, "restored_from": bak,
            "approval": "granted" if granted else None}


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
    allow_roots: list[str] | None = None,
    require_approval: bool = False,
) -> dict:
    """对文本/代码文件打补丁（多语言通用）。allow_roots: 可选路径白名单（沙箱限定）。

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
    _, granted = _write_gate(file_path, allow_roots, require_approval)
    try:
        result = rtp.apply_text_patch(file_path, ops, encoding, force, dry_run)
    except Exception as e:  # noqa: BLE001
        rp._audit("text_apply", ok=False, file=file_path, error=str(e),
                  op_count=len(ops),
                  approval="granted" if granted else None)
        raise
    rp._audit("text_apply" if not result.get("dry_run") else "text_apply_dry_run",
              ok=True, file=file_path,
              backup=result.get("backup", ""),
              sha256=result.get("sha256", ""),
              approval="granted" if granted else None,
              op_count=len(ops),
              applied_ops=[{"op": o.get("op"), "line": o.get("line"),
                            "key": o.get("path") or o.get("key"),
                            "occurrence": o.get("occurrence")} for o in ops])
    result["approval"] = "granted" if granted else None
    return result


@mcp.tool()
def rea_patch_text_verify(file_path: str, contains: str | None = None,
                          not_contains: str | None = None,
                          regex: bool = False,
                          encoding: str | None = None) -> dict:
    """只读校验文本/代码文件是否包含/不包含某关键字或正则。"""
    return rtp.text_verify(file_path, contains, not_contains, regex, encoding)


@mcp.tool()
def rea_patch_text_restore(file_path: str, force: bool = False,
                           allow_roots: list[str] | None = None,
                           require_approval: bool = False) -> dict:
    """从 <file>.reapat_txt_bak 文本备份恢复原文件。force 覆盖当前文件。"""
    _, granted = _write_gate(file_path, allow_roots, require_approval)
    try:
        result = rtp.text_restore(file_path, force)
    except Exception as e:  # noqa: BLE001
        rp._audit("text_restore", ok=False, file=file_path, error=str(e),
                  force=force, approval="granted" if granted else None)
        raise
    rp._audit("text_restore", ok=True, file=file_path,
              backup=result.get("backup", ""), sha256=result.get("sha256", ""),
              approval="granted" if granted else None)
    result["approval"] = "granted" if granted else None
    return result


if __name__ == "__main__":
    mcp.run()