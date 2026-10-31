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
import hashlib
import json
import os
import shutil
import sys

# 统一 UTF-8 输出，避免 GBK 管道乱码
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BACKUP_SUFFIX = ".reapat_bak"


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


def do_backup(path: str) -> str:
    if not os.path.exists(path):
        raise PatchError(f"文件不存在: {path}")
    if os.path.isdir(path):
        raise PatchError(f"路径是目录: {path}")
    bak = path + BACKUP_SUFFIX
    shutil.copy2(path, bak)
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


def va_to_file_offset(data: bytes, va: int, image_base: int | None = None) -> int:
    """将虚拟地址(VA)换算为文件偏移。image_base 缺省时自动从 PE 头读取。"""
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


# ---------------------------------------------------------------- 执行
def apply_patches(file: str, patches: list[dict], force: bool = False,
                  dry_run: bool = False) -> dict:
    """执行补丁。流程：校验全部预期 -> 备份 -> 写盘 -> 回读校验（失败自动回滚）。
    返回结构化结果。"""
    if not os.path.exists(file):
        raise PatchError(f"文件不存在: {file}")
    if os.path.isdir(file):
        raise PatchError(f"路径是目录: {file}")
    data = read_file_bytes(file)

    # 1. 全部预期先校验，任一不匹配则整体拒绝（原子性）
    for p in patches:
        off, old, old_mask = p["offset"], p["old"], p["old_mask"]
        if off + len(old) > len(data):
            raise PatchError(
                f"偏移 0x{off:X} 超出文件大小 0x{len(data):X}（补丁 {p['spec']}）")
        actual = data[off:off + len(old)]
        if not pattern_matches(actual, old, old_mask):
            raise PatchError(
                f"预期字节不匹配，拒绝写入。补丁: {p['spec']}\n"
                f"  偏移 0x{off:X} 实际字节: {actual.hex().upper()}（期望 {old.hex().upper()}）\n"
                f"  可能坐标已偏移，请用 dump 复核或重新分析")

    # 2. 备份（已存在且未强制时拒绝）
    bak = file + BACKUP_SUFFIX
    if os.path.exists(bak) and not force:
        raise PatchError(
            f"已存在备份 {bak}；若确认当前文件是原始文件请加 force=true")

    if dry_run:
        preview = [{"offset": hex(p["offset"]), "from": p["old"].hex().upper(),
                    "to": p["new"].hex().upper()} for p in patches]
        return {"dry_run": True, "file": file, "patches": preview,
                "note": "未写入任何字节"}

    backup_path = do_backup(file)

    # 3. 写盘
    with open(file, "r+b") as f:
        for p in patches:
            f.seek(p["offset"])
            f.write(p["new"])

    # 4. 回读校验，失败自动回滚
    results = []
    ok = True
    for p in patches:
        got = read_range(file, p["offset"], len(p["new"]))
        good = got == p["new"]
        ok = ok and good
        results.append({"offset": hex(p["offset"]),
                        "from": p["old"].hex().upper(),
                        "to": p["new"].hex().upper(),
                        "readback": got.hex().upper(),
                        "status": "OK" if good else "FAIL"})
    if not ok:
        shutil.copy2(backup_path, file)
        raise PatchError("部分补丁回读不匹配，已自动从备份回滚；" +
                         "\n".join(f"  {r['offset']} {r['to']} 实际 {r['readback']}" for r in results))

    return {
        "file": file,
        "backup": backup_path,
        "patches": results,
        "sha256": sha256(file),
        "status": "applied",
    }


def restore_file(file: str, backup: str | None = None, force: bool = False) -> str:
    bak = backup or (file + BACKUP_SUFFIX)
    if not os.path.exists(bak):
        raise PatchError(f"备份不存在: {bak}")
    if os.path.exists(file) and not force:
        raise PatchError(f"目标文件 {file} 仍存在；传入 force=true 才能用备份覆盖它")
    shutil.copy2(bak, file)
    return bak


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
        result = apply_patches(args.file, patches, force=args.force, dry_run=args.dry_run)
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
    bak = restore_file(args.file, args.backup, force=args.force)
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