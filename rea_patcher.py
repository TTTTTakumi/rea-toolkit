#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rea_patcher.py — rea 配套的二进制补丁执行层（增强版）
========================================================

rea MCP 是只读分析器（原始字节永不变），本模块补齐"分析结论 -> 真正写盘 -> 验证生效"闭环。
既是可独立运行的 CLI，也可作为库被 MCP server（rea_patch_server.py）调用。

增强点（相对初版）：
  * 自动读取 PE 镜像基址（--image-base 变为可选覆盖）
  * 预期字节支持掩码通配 ?? （一跳转指令中含无关字节时用）
  * JSON 补丁清单（manifest），多补丁点可复用、可交接
  * --dry-run 只预览不写盘
  * 回读失败自动回滚（从备份恢复），不留下半补丁状态
  * info / va2off 命令直接给出坐标换算与 PE 概况，配合 rea 工具链

工作流（配合 rea）：
  1. rea 分析：procedure_pseudo_code / read_bytes 定位关键指令 -> 拿到 VA 与原始字节
  2. 本工具换算：va2off / patch 时自动按 PE image base 换算 VA -> 文件偏移
  3. 本工具落补丁：patch <文件> -p <偏移>:<旧字节>:<新字节>（偏移可 va0x... 前缀）
  4. 本工具验证：verify / sha256

常用命令：
  info     只读查看 PE 概况（image base / 段表）        python rea_patcher.py info game.exe
  dump     只读查看文件偏移处字节                       python rea_patcher.py dump game.exe -o 0x4A1F0 -l 32
  patch    打补丁（自动备份+预期校验+写回+回读）        python rea_patcher.py patch game.exe -p 0x4A1F0:7508EB02:90909090
  verify   校验某偏移当前字节                           python rea_patcher.py verify game.exe -o 0x4A1F0 -b 90909090
  backup   手动备份                                     python rea_patcher.py backup game.exe
  restore  从备份恢复                                   python rea_patcher.py restore game.exe
  sha256   全文件 SHA-256                               python rea_patcher.py sha256 game.exe
  va2off   VA -> 文件偏移换算（自动取镜像基址）         python rea_patcher.py va2off game.exe --va 0x140001234

补丁点支持一次多个，-p 可重复；旧字节不匹配时整批拒绝写入（原子性）。
"""
import argparse
import datetime
import hashlib
import json
import os
import shutil
import sys
import threading

# 统一 UTF-8 输出，避免 GBK 管道乱码
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BACKUP_SUFFIX = ".reapat_bak"
TMP_SUFFIX = ".reapat_tmp"

# ---------------------------------------------------------------- 路径安全沙箱（P0）
# 受保护系统目录：硬拒绝，不可绕过（跨 Windows / Linux / macOS）
_PROTECTED_ROOTS: list[str] = []
if os.name == "nt":
    _PROTECTED_ROOTS = [
        r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)",
        r"C:\ProgramData", r"C:\$Recycle.Bin",
    ]
else:
    _PROTECTED_ROOTS = [
        "/etc", "/usr", "/bin", "/sbin", "/boot", "/lib", "/lib64",
        "/System", "/Library", "/var", "/Applications",
    ]


def _norm_path(p: str) -> str:
    """归一化路径：绝对化 + 解析符号链接 + 大小写归一（用于包含比较）。"""
    return os.path.normcase(os.path.realpath(os.path.abspath(str(p))))


def _is_within(path_norm: str, root_norm: str) -> bool:
    if path_norm == root_norm:
        return True
    return path_norm.startswith(root_norm + os.sep)


def is_protected_path(path: str) -> bool:
    """路径是否落在受保护系统目录内（realpath 解析后判定，防符号链接逃逸）。"""
    pn = _norm_path(path)
    return any(_is_within(pn, _norm_path(r)) for r in _PROTECTED_ROOTS)


# ---------------------------------------------------------------- 审批区（P1）
# 审批区与硬拒区区分：受保护系统目录永远拒绝（不可审批）；审批区内路径
# 默认拒绝写入，调用方显式传 require_approval=true 才放行，放行后在
# 返回结果与审计日志中记录 approval=granted 供事后核查。
# 默认不启用（保持既有开放写入行为），可用环境变量 REA_PATCH_APPROVAL_ROOTS
# 配置一批"需审批"根目录（os.pathsep 分隔，如 Windows 上 "C:\Users;D:\敏感区"）。
_APPROVAL_ROOTS_DEFAULT: list[str] = []


def _get_approval_roots() -> list[str]:
    """读取生效审批区（支持运行期环境变量覆盖，便于测试与按需配置）。"""
    ov = os.environ.get("REA_PATCH_APPROVAL_ROOTS")
    if ov:
        return [p.strip() for p in ov.split(os.pathsep) if p.strip()]
    return list(_APPROVAL_ROOTS_DEFAULT)


def is_approval_required(path_norm: str) -> bool:
    """(已归一化)路径是否落在审批区内。"""
    return any(_is_within(path_norm, _norm_path(r))
               for r in _get_approval_roots())


def approval_gate(path_norm: str, require_approval: bool,
                  allow_roots: list[str] | None = None) -> bool:
    """审批闸门（须在 assert_path_safe 之后调用）。
    返回 True = 本次显式授权放行（approval=granted）；False = 无需审批。
    白名单优先：allow_roots 命中即视为已授权，跳过审批判定。
    落在审批区且 require_approval=false -> 抛 PatchError 拒绝。
    """
    if allow_roots:
        allowed_norm = {_norm_path(r) for r in allow_roots}
        if any(_is_within(path_norm, rn) for rn in allowed_norm):
            return False
    if is_approval_required(path_norm):
        if require_approval:
            return True
        raise PatchError(
            f"路径 {path_norm} 位于需审批区域（REA_PATCH_APPROVAL_ROOTS），"
            "拒绝写入；请显式传 require_approval=true 完成授权"
            "（白名单 allow_roots 命中可豁免）")
    return False


def assert_path_safe(path: str, allow_roots: list[str] | None = None) -> str:
    """路径安全闸门（写操作前必须调用）：
    1. 受保护系统目录 -> 硬拒绝（不可通过白名单绕过）
    2. 若传 allow_roots 白名单 -> 目标必须落在其中（防 ../ 与符号链接逃逸）
    返回归一化后的真实路径。
    """
    real = os.path.realpath(os.path.abspath(str(path)))
    norm = os.path.normcase(real)
    for root in _PROTECTED_ROOTS:
        rn = _norm_path(root)
        if _is_within(norm, rn):
            raise PatchError(
                f"路径 {path} 位于受保护系统目录 {root} 内，拒绝修改以保护系统安全")
    if allow_roots:
        allowed_norm = {_norm_path(r) for r in allow_roots}
        if not any(_is_within(norm, rn) for rn in allowed_norm):
            raise PatchError(
                f"路径 {path} 不在允许白名单 {list(allow_roots)} 内，拒绝修改（沙箱拦截）")
    return real


class PatchError(Exception):
    """补丁校验/执行错误，所有失败都抛此异常，由上层转成可读错误。"""


def die(msg: str):
    print(f"[错误] {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------- 基础 IO
def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def read_range(path: str, offset: int, length: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(length)


def do_backup(path: str, allow_roots: list[str] | None = None) -> str:
    if not os.path.exists(path):
        raise PatchError(f"文件不存在: {path}")
    if os.path.isdir(path):
        raise PatchError(f"路径是目录: {path}")
    real = assert_path_safe(path, allow_roots)
    bak = real + BACKUP_SUFFIX
    shutil.copy2(real, bak)
    return bak


# ---------------------------------------------------------------- PE 解析
def pe_image_base(data: bytes) -> int | None:
    """读取 PE 可选头的 ImageBase。非 PE 返回 None。"""
    if len(data) < 0x40 or data[0:2] != b"MZ":
        return None
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    opt_off = e_lfanew + 24
    magic = data[opt_off:opt_off + 2]
    if magic == b"\x0b\x01":  # PE32
        return int.from_bytes(data[opt_off + 28:opt_off + 32], "little")
    if magic == b"\x0b\x02":  # PE32+
        return int.from_bytes(data[opt_off + 24:opt_off + 32], "little")
    return None


def pe_sections(data: bytes) -> list[dict]:
    """提取 PE 段表（VA/RawPtr 等），非 PE 返回 []。"""
    if len(data) < 0x40 or data[0:2] != b"MZ":
        return []
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return []
    num_sections = int.from_bytes(data[e_lfanew + 6:e_lfanew + 8], "little")
    size_opt = int.from_bytes(data[e_lfanew + 20:e_lfanew + 22], "little")
    section_off = e_lfanew + 24 + size_opt
    out = []
    for i in range(num_sections):
        base = section_off + i * 40
        if base + 40 > len(data):
            break
        name = data[base:base + 8].split(b"\x00")[0].decode("latin1")
        out.append({
            "name": name,
            "virt_size": int.from_bytes(data[base + 8:base + 12], "little"),
            "virt_addr": int.from_bytes(data[base + 12:base + 16], "little"),
            "raw_size": int.from_bytes(data[base + 16:base + 20], "little"),
            "raw_ptr": int.from_bytes(data[base + 20:base + 24], "little"),
        })
    return out


def file_format(data: bytes) -> str | None:
    """检测文件格式类型：pe | elf | macho | None。"""
    if len(data) >= 2 and data[0:2] == b"MZ":
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
            return "pe"
    if len(data) >= 4 and data[0:4] == b"\x7fELF":
        return "elf"
    m = int.from_bytes(data[0:4], "big") if len(data) >= 4 else 0
    # Mach-O magic（大小端、32/64）
    if m in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
        return "macho"
    return None


def elf_load_segments(data: bytes) -> list[dict]:
    """提取 ELF PT_LOAD 段（vaddr/offset/filesz），支持 ELF32/64、大小端。"""
    if data[0:4] != b"\x7fELF":
        return []
    elf_class = data[4]      # 1=32 2=64
    elf_data = data[5]       # 1=LE 2=BE
    endian = "little" if elf_data == 1 else "big"
    if elf_class == 1:
        # ELF32 header: e_phoff @28(4), e_phentsize @42(2), e_phnum @44(2)
        phoff = int.from_bytes(data[28:32], endian)
        phentsize = int.from_bytes(data[42:44], endian)
        phnum = int.from_bytes(data[44:46], endian)
        out = []
        for i in range(phnum):
            base = phoff + i * (phentsize or 32)
            if base + 32 > len(data):
                break
            p_type = int.from_bytes(data[base:base + 4], endian)
            if p_type != 1:  # PT_LOAD
                continue
            p_offset = int.from_bytes(data[base + 4:base + 8], endian)
            p_vaddr = int.from_bytes(data[base + 8:base + 12], endian)
            p_filesz = int.from_bytes(data[base + 16:base + 20], endian)
            out.append({"vaddr": p_vaddr, "offset": p_offset,
                        "filesz": p_filesz})
        return out
    if elf_class == 2:
        phoff = int.from_bytes(data[32:40], endian)
        phentsize = int.from_bytes(data[54:56], endian)
        phnum = int.from_bytes(data[56:58], endian)
        out = []
        for i in range(phnum):
            base = phoff + i * (phentsize or 56)
            if base + 56 > len(data):
                break
            p_type = int.from_bytes(data[base:base + 4], endian)
            if p_type != 1:  # PT_LOAD
                continue
            p_offset = int.from_bytes(data[base + 8:base + 16], endian)
            p_vaddr = int.from_bytes(data[base + 16:base + 24], endian)
            p_filesz = int.from_bytes(data[base + 32:base + 40], endian)
            out.append({"vaddr": p_vaddr, "offset": p_offset,
                        "filesz": p_filesz})
        return out
    return []


def macho_segments(data: bytes) -> list[dict]:
    """提取 Mach-O segment（vmaddr/fileoff/filesz），支持 LC_SEGMENT(32)/LC_SEGMENT_64。"""
    if len(data) < 4:
        return []
    m_big = int.from_bytes(data[0:4], "big")
    is64 = m_big in (0xFEEDFACF, 0xCFFAEDFE)
    is32 = m_big in (0xFEEDFACE, 0xCEFAEDFE)
    if not (is64 or is32):
        return []
    # 端序：魔数按 big 读为 CFFAEDFE/CEFAEDFE 表示小端文件；FEED* 为大端文件
    endian = "big" if m_big in (0xFEEDFACE, 0xFEEDFACF) else "little"
    if len(data) < (32 if is64 else 28):
        return []
    ncmds = int.from_bytes(data[16:20], endian)
    base = 32 if is64 else 28  # mach_header 64位32B / 32位28B
    out = []
    cursor = base
    for _ in range(ncmds):
        if cursor + 8 > len(data):
            break
        cmd = int.from_bytes(data[cursor:cursor + 4], endian)
        cmdsize = int.from_bytes(data[cursor + 4:cursor + 8], endian)
        if cmdsize < 8 or cursor + cmdsize > len(data):
            break
        if cmd == 0x19:  # LC_SEGMENT_64: segname@8 vmaddr@24 vmsize@32 fileoff@40 filesize@48
            vmaddr = int.from_bytes(data[cursor + 24:cursor + 32], endian)
            filesz = int.from_bytes(data[cursor + 48:cursor + 56], endian)
            fileoff = int.from_bytes(data[cursor + 40:cursor + 48], endian)
            out.append({"vmaddr": vmaddr, "vm_end": vmaddr + filesz,
                        "fileoff": fileoff, "filesz": filesz})
        elif cmd == 0x01:  # LC_SEGMENT(32): segname@8 vmaddr@24 vmsize@28 fileoff@32 filesize@36
            vmaddr = int.from_bytes(data[cursor + 24:cursor + 28], endian)
            filesz = int.from_bytes(data[cursor + 36:cursor + 40], endian)
            fileoff = int.from_bytes(data[cursor + 32:cursor + 36], endian)
            out.append({"vmaddr": vmaddr, "vm_end": vmaddr + filesz,
                        "fileoff": fileoff, "filesz": filesz})
        cursor += cmdsize
    return out


def va_to_file_offset(data: bytes, va: int, image_base: int | None = None) -> int:
    """将虚拟地址(VA)换算为文件偏移。按文件格式自动分派：
    - PE：走节表（image_base 缺省自动从 PE 头读取）
    - ELF：走 PT_LOAD 段映射（image_base 忽略）
    - Mach-O：走 segment 映射（image_base 忽略）
    """
    fmt = file_format(data)
    if fmt == "pe":
        if image_base is None:
            image_base = pe_image_base(data)
            if image_base is None:
                raise PatchError("无法自动获取 PE 镜像基址，请显式传入 image_base")
        if len(data) < 0x40 or data[0:2] != b"MZ":
            raise PatchError("不是有效的 PE 文件（缺 MZ 头）")
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise PatchError("PE 签名无效")
        num_sections = int.from_bytes(data[e_lfanew + 6:e_lfanew + 8], "little")
        size_opt = int.from_bytes(data[e_lfanew + 20:e_lfanew + 22], "little")
        section_off = e_lfanew + 24 + size_opt
        for i in range(num_sections):
            base = section_off + i * 40
            if base + 40 > len(data):
                break
            virt_addr = int.from_bytes(data[base + 12:base + 16], "little")
            virt_size = int.from_bytes(data[base + 8:base + 12], "little")
            raw_ptr = int.from_bytes(data[base + 20:base + 24], "little")
            raw_size = int.from_bytes(data[base + 16:base + 20], "little")
            seg_start = image_base + virt_addr
            seg_end = image_base + virt_addr + max(virt_size, raw_size)
            if seg_start <= va < seg_end:
                delta = va - seg_start
                if raw_ptr + delta >= len(data):
                    raise PatchError(f"VA 0x{va:X} 在段 {i} 内但超出文件边界")
                return raw_ptr + delta
        raise PatchError(f"VA 0x{va:X} 未落在任何镜像段内（检查 image-base）")
    if fmt == "elf":
        for seg in elf_load_segments(data):
            start = seg["vaddr"]
            end = seg["vaddr"] + seg["filesz"]
            if start <= va < end:
                off = seg["offset"] + (va - start)
                if off >= len(data):
                    raise PatchError(f"VA 0x{va:X} 超出文件边界")
                return off
        raise PatchError(f"VA 0x{va:X} 未落在任何 ELF PT_LOAD 段内")
    if fmt == "macho":
        for s in macho_segments(data):
            if s["vmaddr"] <= va < s["vm_end"]:
                off = s["fileoff"] + (va - s["vmaddr"])
                if off >= len(data):
                    raise PatchError(f"VA 0x{va:X} 超出文件边界")
                return off
        raise PatchError(f"VA 0x{va:X} 未落在任何 Mach-O segment 内")
    raise PatchError("不是可识别的可执行格式（仅支持 PE / ELF / Mach-O）")


# ---------------------------------------------------------------- 补丁规格
def parse_old_pattern(s: str) -> bytes:
    """解析预期字节，支持 ?? 通配（单个字节）。例如 AA??BB 表示第2字节任意。"""
    s = s.strip()
    if len(s) % 2 != 0:
        raise PatchError(f"字节应为十六进制（偶数位），实际: {s}")
    out = bytearray()
    for i in range(0, len(s), 2):
        b = s[i:i + 2]
        if b == "??":
            out.append(0x00)  # 占位，匹配时单独处理
        else:
            out.append(int(b, 16))
    return bytes(out)


def parse_old_mask(s: str) -> bytes:
    """解析预期字节对应的掩码：1=必须匹配，0=任意。"""
    s = s.strip()
    mask = bytearray()
    for i in range(0, len(s), 2):
        b = s[i:i + 2]
        mask.append(0x00 if b == "??" else 0xFF)
    return bytes(mask)


def pattern_matches(actual: bytes, pattern: bytes, mask: bytes) -> bool:
    if len(actual) != len(pattern):
        return False
    for a, p, m in zip(actual, pattern, mask):
        if m and a != p:
            return False
    return True


def parse_patch_spec(spec: str, image_base: int | None, data: bytes) -> dict:
    """解析 '偏移:旧字节:新字节' -> {offset, old, old_mask, new, spec}。
    偏移默认文件偏移；'va0x...' 前缀按 VA 换算。"""
    parts = spec.split(":")
    if len(parts) != 3:
        raise PatchError(f"补丁格式应为 偏移:旧字节:新字节，实际: {spec}")
    off_s, old_s, new_s = parts
    if off_s.lower().startswith("va0x"):
        try:
            off = va_to_file_offset(data, int(off_s[2:], 16), image_base)
        except PatchError as e:
            raise PatchError(f"VA 换算失败: {e}")
    else:
        try:
            off = int(off_s, 0)
        except ValueError:
            raise PatchError(f"偏移无法解析: {off_s}")
    old = parse_old_pattern(old_s)
    old_mask = pattern_mask(old_s)
    try:
        new = bytes.fromhex(new_s)
    except ValueError:
        raise PatchError(f"新字节应为十六进制（偶数位），实际: {new_s}")
    if len(old) != len(new):
        raise PatchError(f"旧字节({len(old)}B)与新字节({len(new)}B)长度不一致，补丁不允许改长度")
    return {"offset": off, "old": old, "old_mask": old_mask, "new": new, "spec": spec}


def pattern_mask(s: str) -> bytes:
    """由模式字符串生成掩码（?? 为 0，其余 0xFF）。"""
    m = bytearray()
    for i in range(0, len(s), 2):
        m.append(0x00 if s[i:i + 2] == "??" else 0xFF)
    return bytes(m)


def patches_from_manifest(path: str, image_base: int | None, data: bytes) -> list[dict]:
    """从 JSON manifest 加载补丁清单。
    格式: {"image_base": 0x140000000(可选), "patches": [{"offset":"0x..|va0x..","old":"AA??","new":"9090","note":"..."}]}
    """
    with open(path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    if image_base is None:
        image_base = manifest.get("image_base")
    patches = []
    for p in manifest.get("patches", []):
        off_s = str(p["offset"])
        old_s = p["old"]
        new_s = p["new"]
        spec = f"{off_s}:{old_s}:{new_s}"
        patches.append(parse_patch_spec(spec, image_base, data))
    if not patches:
        raise PatchError(f"manifest 中无有效补丁点: {path}")
    return patches


def apply_manifest(file: str, manifest_path: str, force: bool = False,
                   dry_run: bool = False,
                   allow_roots: list[str] | None = None,
                   approval: bool = False) -> dict:
    """从 JSON 补丁清单（v2 协议）应用补丁，四重校验：
    1. 目标文件哈希 == manifest.target.file_sha256（防幻觉补丁打错目标）
    2. 偏移 >= manifest.patches[].offset_min（防越界）
    3. 原始字节 match（坐标过期即拒绝）
    4. 每个补丁点可带 evidence_id（引用分析阶段结论，写入审计）

    v2 清单格式:
      {"schema": 2,
       "target": {"file_sha256": "...", "size": 1234, "evidence_id": "rea-xxx"},
       "image_base": 0x140000000(可选),
       "patches": [{"offset": "0x..|va0x..", "old": "AA??", "new": "9090",
                    "offset_min": 0, "evidence_id": "..."}]}
    兼容 v1（无 schema / 无 target）旧清单。
    """
    if not os.path.exists(file):
        raise PatchError(f"文件不存在: {file}")
    if not os.path.exists(manifest_path):
        raise PatchError(f"补丁清单不存在: {manifest_path}")
    real_file = assert_path_safe(file, allow_roots)
    data = read_file_bytes(real_file)
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    schema = manifest.get("schema", 1)
    image_base = manifest.get("image_base")
    if image_base is None:
        image_base = None

    # 四重校验之一：目标哈希
    expect_sha = None
    target = manifest.get("target") or {}
    if isinstance(target, dict):
        expect_sha = target.get("file_sha256")
    if schema >= 2 and expect_sha:
        actual = sha256(real_file)
        if actual.lower() != str(expect_sha).lower():
            raise PatchError(
                "补丁清单目标哈希不匹配（幻觉补丁拦截）："
                f"清单 {expect_sha} vs 实际 {actual}，拒绝应用")

    parsed = []
    p_list = manifest.get("patches", [])
    if not p_list:
        raise PatchError(f"manifest 中无有效补丁点: {manifest_path}")
    for p in p_list:
        spec = f"{p['offset']}:{p['old']}:{p['new']}"
        pp = parse_patch_spec(spec, image_base, data)
        pp["offset_min"] = p.get("offset_min", 0)
        pp["evidence_id"] = p.get("evidence_id")
        parsed.append(pp)

    result = apply_patches(real_file, parsed, force=force, dry_run=dry_run,
                           allow_roots=allow_roots, target_sha256=expect_sha,
                           approval=approval)
    if not result.get("dry_run"):
        _audit("apply_manifest", ok=True, file=real_file,
               manifest=manifest_path, approval="granted" if approval else None,
               evidence_ids=[p["evidence_id"] for p in parsed
                             if p.get("evidence_id")])
    return result


# ---------------------------------------------------------------- 执行
def _apply_patches_inner(file: str, patches: list[dict], force: bool = False,
                         dry_run: bool = False,
                         allow_roots: list[str] | None = None,
                         target_sha256: str | None = None) -> dict:
    """执行补丁。流程：路径安全闸门 -> manifest 目标哈希校验 -> 全部预期校验
    -> 备份 -> 内存构造新内容 -> 临时文件 fsync -> os.replace 原子替换
    -> 回读校验（失败自动回滚）。
    返回结构化结果。"""
    if not os.path.exists(file):
        raise PatchError(f"文件不存在: {file}")
    if os.path.isdir(file):
        raise PatchError(f"路径是目录: {file}")

    # 0. 路径安全闸门（受保护目录硬拒绝 + 可选白名单）
    real_file = assert_path_safe(file, allow_roots)

    data = read_file_bytes(real_file)

    # 0.5 manifest 目标哈希校验（防幻觉补丁：目标文件必须与清单声明一致）
    if target_sha256:
        actual = sha256(real_file)
        if actual.lower() != str(target_sha256).lower():
            raise PatchError(
                "补丁清单目标哈希不匹配（幻觉补丁拦截）："
                f"清单 {target_sha256} vs 实际 {actual[:16]}...，拒绝应用")

    # 1. 全部预期先校验，任一不匹配则整体拒绝（原子性）
    for p in patches:
        off, old, old_mask = p["offset"], p["old"], p["old_mask"]
        if off + len(old) > len(data):
            raise PatchError(
                f"偏移 0x{off:X} 超出文件大小 0x{len(data):X}（补丁 {p['spec']}）")
        # 偏移范围四重校验之一：显式声明最小合法偏移（防越界幻觉）
        off_min = p.get("offset_min", 0)
        if off < off_min:
            raise PatchError(
                f"偏移 0x{off:X} 低于清单声明的合法下限 0x{off_min:X}（补丁 {p['spec']}）")
        actual = data[off:off + len(old)]
        if not pattern_matches(actual, old, old_mask):
            raise PatchError(
                f"预期字节不匹配，拒绝写入。补丁: {p['spec']}\n"
                f"  偏移 0x{off:X} 实际字节: {actual.hex().upper()}（期望 {old.hex().upper()}）\n"
                f"  可能坐标已偏移，请用 dump 复核或重新分析")

    # 2. 备份（已存在且未强制时拒绝）
    bak = real_file + BACKUP_SUFFIX
    if os.path.exists(bak) and not force:
        raise PatchError(
            f"已存在备份 {bak}；若确认当前文件是原始文件请加 force=true")

    if dry_run:
        preview = [{"offset": hex(p["offset"]), "from": p["old"].hex().upper(),
                    "to": p["new"].hex().upper(),
                    "evidence_id": p.get("evidence_id")} for p in patches]
        return {"dry_run": True, "file": real_file, "patches": preview,
                "note": "未写入任何字节"}

    backup_path = do_backup(real_file)

    # 3. 原子写：内存构造新内容 -> 临时文件 fsync -> os.replace
    new_data = bytearray(data)
    for p in patches:
        new_data[p["offset"]:p["offset"] + len(p["new"])] = p["new"]
    tmp = real_file + TMP_SUFFIX
    try:
        # 清理可能残留的旧临时文件（来自上一次崩溃）
        if os.path.exists(tmp):
            os.remove(tmp)
        with open(tmp, "wb") as f:
            f.write(new_data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, real_file)   # 原子替换：崩溃时目标只会是完整旧/新文件
    except Exception as e:  # noqa: BLE001
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        raise PatchError(f"原子写盘失败，已清理临时文件，目标未被修改: {e}")

    # 4. 回读校验，失败自动回滚
    results = []
    ok = True
    for p in patches:
        got = read_range(real_file, p["offset"], len(p["new"]))
        good = got == p["new"]
        ok = ok and good
        results.append({"offset": hex(p["offset"]),
                        "from": p["old"].hex().upper(),
                        "to": p["new"].hex().upper(),
                        "readback": got.hex().upper(),
                        "evidence_id": p.get("evidence_id"),
                        "status": "OK" if good else "FAIL"})
    if not ok:
        shutil.copy2(backup_path, real_file)
        raise PatchError("部分补丁回读不匹配，已自动从备份回滚；" +
                         "\n".join(f"  {r['offset']} {r['to']} 实际 {r['readback']}" for r in results))

    return {
        "file": real_file,
        "backup": backup_path,
        "patches": results,
        "sha256": sha256(real_file),
        "status": "applied",
    }


def _restore_file_inner(file: str, backup: str | None = None, force: bool = False,
                        allow_roots: list[str] | None = None) -> str:
    real_file = assert_path_safe(file, allow_roots)
    bak = backup or (real_file + BACKUP_SUFFIX)
    if not os.path.exists(bak):
        raise PatchError(f"备份不存在: {bak}")
    if os.path.exists(real_file) and not force:
        raise PatchError(f"目标文件 {real_file} 仍存在；传入 force=true 才能用备份覆盖它")
    shutil.copy2(bak, real_file)
    return bak


# ---------------------------------------------------------------- 审计日志（P1）
# 补丁写盘是对二进制的修改动作，逐条落审计日志（JSONL）便于事后核查与交接。
# 默认写到本模块目录下 audit/rea_patch_audit.jsonl；可用环境变量 REA_PATCH_AUDIT_LOG 覆盖。
_AUDIT_LOG = os.environ.get(
    "REA_PATCH_AUDIT_LOG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit", "rea_patch_audit.jsonl"))
_audit_lock = threading.Lock()


def _audit(action: str, *, ok: bool, file: str = "", **fields) -> None:
    """追加一条审计记录。best-effort：审计失败只打 stderr，绝不阻断主流程。
    None 值字段不下发（approval 等可选字段只在有值时落盘）。"""
    try:
        rec = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
               "action": action, "ok": bool(ok), "file": file}
        rec.update({k: v for k, v in fields.items() if v is not None})
        log_dir = os.path.dirname(_AUDIT_LOG)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with _audit_lock:
            with open(_AUDIT_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:  # noqa: BLE001
        print(f"[审计写入失败] {e}", file=sys.stderr)


def apply_patches(file: str, patches: list[dict], force: bool = False,
                  dry_run: bool = False,
                  allow_roots: list[str] | None = None,
                  target_sha256: str | None = None,
                  approval: bool = False) -> dict:
    """审计包装层：统一给 apply 成功/失败打点（成功含备份路径与目标哈希）。
    approval=True 表示本次写入已通过显式审批（服务端在审计中标记 granted）。"""
    try:
        res = _apply_patches_inner(file, patches, force=force, dry_run=dry_run,
                                   allow_roots=allow_roots, target_sha256=target_sha256)
        _audit("apply" if not res.get("dry_run") else "apply_dry_run",
               ok=True, file=res.get("file", file),
               backup=res.get("backup", ""),
               patch_count=len(patches),
               sha256=res.get("sha256", ""),
               approval="granted" if approval else None,
               patch_points=[{"offset": hex(p["offset"]),
                              "from": p["old"].hex().upper(),
                              "to": p["new"].hex().upper(),
                              "evidence_id": p.get("evidence_id")}
                             for p in patches])
        return res
    except Exception as e:  # noqa: BLE001
        _audit("apply", ok=False, file=file, error=str(e), patch_count=len(patches),
               approval="granted" if approval else None)
        raise


def restore_file(file: str, backup: str | None = None, force: bool = False,
                 allow_roots: list[str] | None = None,
                 approval: bool = False) -> str:
    """审计包装层：记录恢复动作（默认从备份覆盖目标）。"""
    try:
        bak = _restore_file_inner(file, backup=backup, force=force,
                                  allow_roots=allow_roots)
        _audit("restore", ok=True, file=file, backup=bak,
               approval="granted" if approval else None)
        return bak
    except Exception as e:  # noqa: BLE001
        _audit("restore", ok=False, file=file, backup=backup or "", error=str(e),
               force=force, approval="granted" if approval else None)
        raise


def get_pe_info(path: str) -> dict:
    data = read_file_bytes(path)
    if len(data) < 2 or data[0:2] != b"MZ":
        raise PatchError("不是 PE 文件（缺 MZ 头）")
    base = pe_image_base(data)
    sections = pe_sections(data)
    return {
        "file": path,
        "size": len(data),
        "image_base": hex(base) if base else None,
        "sections": sections,
        "sha256": sha256(path),
    }


# ---------------------------------------------------------------- CLI
def cmd_info(args):
    info = get_pe_info(args.file)
    print(f"文件: {info['file']}  大小: 0x{info['size']:X}")
    print(f"ImageBase: {info['image_base']}  SHA-256: {info['sha256'][:16]}...")
    if info["sections"]:
        print("段表:")
        for s in info["sections"]:
            print(f"  {s['name']:<12} VA=0x{s['virt_addr']:X}  VSz=0x{s['virt_size']:X}  "
                  f"Ptr=0x{s['raw_ptr']:X}  RSz=0x{s['raw_size']:X}")


def cmd_dump(args):
    data = read_file_bytes(args.file)
    off = args.offset
    if off < 0 or off >= len(data):
        die(f"偏移 0x{off:X} 超出文件大小 0x{len(data):X}")
    chunk = data[off:off + args.length]
    print(f"文件: {args.file}  大小: 0x{len(data):X}  SHA-256: {sha256(args.file)[:16]}...")
    print(f"偏移 0x{off:X} 起 {len(chunk)} 字节:")
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hexs = " ".join(f"{b:02X}" for b in row)
        chars = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        print(f"  0x{off + i:08X}  {hexs:<48}  {chars}")


def cmd_patch(args):
    if not os.path.exists(args.file):
        die(f"文件不存在: {args.file}")
    data = read_file_bytes(args.file)
    if args.image_base == 0:
        args.image_base = None
    patches = []
    for spec in (args.patch or []):
        patches.append(parse_patch_spec(spec, args.image_base, data))
    if getattr(args, "manifest", None):
        patches.extend(patches_from_manifest(args.manifest, args.image_base, data))
    if not patches:
        die("未指定任何补丁点（-p 或 --manifest）")
    try:
        result = apply_patches(args.file, patches, force=args.force, dry_run=args.dry_run,
                               allow_roots=getattr(args, "allow_roots", None))
    except PatchError as e:
        die(str(e))
    if result.get("dry_run"):
        print("dry-run（未写盘）预览:")
        for p in result["patches"]:
            print(f"  {p['offset']}  {p['from']} -> {p['to']}")
        return
    print(f"备份: {result['backup']}")
    for r in result["patches"]:
        print(f"  [{r['status']}] {r['offset']} {r['from']} -> {r['to']}")
    print(f"新文件 SHA-256: {result['sha256']}")
    print("补丁成功")


def cmd_verify(args):
    got = read_range(args.file, args.offset, len(args.bytes) // 2)
    expect = bytes.fromhex(args.bytes)
    print(f"偏移 0x{args.offset:X} 实际: {got.hex().upper()}")
    if got == expect:
        print("结果: 符合预期（生效）")
    else:
        print(f"结果: 不匹配（期望 {expect.hex().upper()}）")


def cmd_restore(args):
    bak = restore_file(args.file, args.backup, force=args.force,
                       allow_roots=getattr(args, "allow_roots", None))
    print(f"已从 {bak} 恢复: {args.file}")


def cmd_sha256(args):
    print(sha256(args.file))


def cmd_va2off(args):
    data = read_file_bytes(args.file)
    try:
        if args.image_base != 0:
            off = va_to_file_offset(data, args.va, args.image_base)
        else:
            off = va_to_file_offset(data, args.va, None)
    except PatchError as e:
        die(str(e))
    print(f"VA 0x{args.va:X} -> 文件偏移 0x{off:X}")


def main():
    p = argparse.ArgumentParser(prog="rea_patcher",
                                description="rea 配套的二进制补丁执行层（备份/补丁/校验/恢复）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("info", help="PE 概况（image base / 段表）")
    d.add_argument("file")
    d.set_defaults(fn=cmd_info)

    d = sub.add_parser("dump", help="只读查看文件偏移处字节")
    d.add_argument("file")
    d.add_argument("-o", "--offset", type=lambda x: int(x, 0), required=True)
    d.add_argument("-l", "--length", type=int, default=16)
    d.set_defaults(fn=cmd_dump)

    pa = sub.add_parser("patch", help="打补丁：自动备份+预期校验+写回+回读")
    pa.add_argument("file")
    pa.add_argument("-p", "--patch", action="append",
                    help="补丁描述 偏移:旧字节:新字节，可多次；偏移用va0x前缀按VA换算")
    pa.add_argument("--manifest",
                    help="JSON 补丁清单（可与 -p 混用）: {\"image_base\":0x...,\"patches\":[{\"offset\":\"0x..|va0x..\",\"old\":\"AA??\",\"new\":\"9090\"}]}")
    pa.add_argument("--image-base", type=lambda x: int(x, 0), default=0,
                    help="镜像基址覆盖（默认自动读 PE 头）")
    pa.add_argument("--force", action="store_true", help="已有备份时仍强制以当前文件为基准")
    pa.add_argument("--dry-run", action="store_true", help="只预览不写盘")
    pa.add_argument("--allow-root", action="append", dest="allow_roots",
                    help="路径白名单根目录（可多次），目标必须落在其中")
    pa.set_defaults(fn=cmd_patch)

    v = sub.add_parser("verify", help="校验某偏移当前字节是否为期望值")
    v.add_argument("file")
    v.add_argument("-o", "--offset", type=lambda x: int(x, 0), required=True)
    v.add_argument("-b", "--bytes", required=True, help="期望字节 hex")
    v.set_defaults(fn=cmd_verify)

    b = sub.add_parser("backup", help="手动备份为 <文件>.reapat_bak")
    b.add_argument("file")
    b.set_defaults(fn=lambda a: print("备份:", do_backup(a.file)))

    r = sub.add_parser("restore", help="从备份恢复")
    r.add_argument("file")
    r.add_argument("--backup", help="备份路径，默认 <文件>.reapat_bak")
    r.add_argument("--force", action="store_true", help="目标存在时仍覆盖")
    r.add_argument("--allow-root", action="append", dest="allow_roots",
                   help="路径白名单根目录（可多次），目标必须落在其中")
    r.set_defaults(fn=cmd_restore)

    s = sub.add_parser("sha256", help="全文件 SHA-256")
    s.add_argument("file")
    s.set_defaults(fn=cmd_sha256)

    v2 = sub.add_parser("va2off", help="VA -> 文件偏移换算")
    v2.add_argument("file")
    v2.add_argument("--va", type=lambda x: int(x, 0), required=True)
    v2.add_argument("--image-base", type=lambda x: int(x, 0), default=0)
    v2.set_defaults(fn=cmd_va2off)

    args = p.parse_args()
    try:
        args.fn(args)
    except PatchError as e:
        die(str(e))
    except Exception as e:  # noqa: BLE001
        die(f"执行失败: {e}")


if __name__ == "__main__":
    main()