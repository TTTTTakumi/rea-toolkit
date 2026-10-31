#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rea_text_patcher.py — rea_patcher 的多语言文本/代码补丁层
=========================================================

rea 只读分析定位目标后，二进制层用 rea_patcher 落盘；源码/脚本/配置等
**文本层**用本模块落盘。覆盖所有以文本形式存在的代码与配置文件：
Python / C / C++ / Java / JS / TS / Lua / SQL / JSON / YAML / INI / XML / 文本等。

能力（ops 列表，顺序执行）：
  * replace   字符串精确替换（old -> new），可限定次数/指定第几次出现
  * regex     正则替换（re.sub，flags 按 re 模块数值）
  * line      行操作：replace / insert_before / insert_after / delete
  * json      结构化 JSON 键路径修改（a.b[0].c），自动保留缩进与尾随换行
  * ini       结构化 INI / cfg 键值修改（section.key = value，保留注释）

安全网与 rea_patcher 一致：
  * 自动备份 <file>.reapat_txt_bak（与二进制备份 .reapat_bak 互相独立）
  * 写前全部 ops 模拟预览：任一失败则整批拒绝（原子性）
  * dry_run 只预览不写盘（输出变更 diff 与行号）
  * 写后回读校验，失败自动从备份回滚
  * 编码自适应：BOM / UTF-8 / UTF-16 / GBK，可显式指定

CLI:
  text view   只读按行查看       python rea_text_patcher.py view game.cfg -s 1 -e 20
  text search 只读搜索定位       python rea_text_patcher.py search main.py "hp_max" -r
  text patch  打文本补丁         python rea_text_patcher.py patch app.py -o '{"op":"replace","old":"a","new":"b"}'
  text verify 只读校验           python rea_text_patcher.py verify app.py --contains "b"
  text restore 从备份恢复        python rea_text_patcher.py restore app.py --force
"""
import argparse
import json
import os
import re
import shutil
import sys

BACKUP_SUFFIX_TXT = ".reapat_txt_bak"


class TextPatchError(Exception):
    pass


def die(msg: str):
    print(f"[错误] {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------- 编码
def detect_encoding(raw: bytes, hint: str | None = None) -> str:
    """编码检测：显式指定优先；否则 BOM -> UTF-8 严格 -> GBK。"""
    if hint:
        return hint
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return "utf-16"
    for enc in ("utf-8", "gbk"):
        try:
            raw.decode(enc)
            return enc
        except (UnicodeDecodeError, LookupError):
            continue
    return "utf-8"


def read_text(path: str, encoding: str | None = None) -> tuple[str, str]:
    with open(path, "rb") as f:
        raw = f.read()
    enc = detect_encoding(raw, encoding)
    return raw.decode(enc), enc


def _split_lines(text: str) -> list[str]:
    """保留行尾的切分，便于精确计算与回写。"""
    if "\n" not in text and "\r" not in text:
        return [text] if text else []
    lines = text.splitlines(keepends=True)
    if not lines:
        return []
    # 修复 splitlines 对 \r\n 的边界（keepends=True 已保留）
    return lines


def _join_lines(lines: list[str]) -> str:
    return "".join(lines)


# ---------------------------------------------------------------- ops 执行
def _apply_replace(text: str, op: dict) -> tuple[str, int]:
    old, new = op["old"], op.get("new", "")
    if not isinstance(old, str) or old == "":
        raise TextPatchError("replace 需要非空 old")
    count = op.get("count")
    occurrence = op.get("occurrence")
    if count is not None and occurrence is not None:
        raise TextPatchError("count 与 occurrence 不能同时使用")
    if occurrence is not None:
        idx = 0
        pos = -1
        start = 0
        found = -1
        while True:
            pos = text.find(old, start)
            if pos == -1:
                break
            idx += 1
            if idx == occurrence:
                found = pos
                break
            start = pos + len(old)
        if found == -1:
            raise TextPatchError(f"第 {occurrence} 次出现未找到: {old!r}")
        return text[:found] + new + text[found + len(old):], 1
    if count is None:
        n = text.count(old)
        if n == 0:
            raise TextPatchError(f"未找到目标串: {old!r}")
        return text.replace(old, new), n
    n = text.count(old)
    if n < count:
        raise TextPatchError(f"目标串仅出现 {n} 次，少于要求替换 {count} 次: {old!r}")
    return text.replace(old, new, count), count


def _apply_regex(text: str, op: dict) -> tuple[str, int]:
    pattern = op["pattern"]
    repl = op.get("replace", "")
    flags = int(op.get("flags", 0))
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        raise TextPatchError(f"正则编译失败: {e}")
    n_before = len(rx.findall(text))
    if n_before == 0:
        raise TextPatchError(f"正则未命中: {pattern}")
    try:
        new_text, n = rx.subn(repl, text)
    except re.error as e:
        raise TextPatchError(f"正则替换失败: {e}")
    return new_text, n


def _parse_line_num(lines: list[str], line: int, allow_end: bool = False) -> int:
    """1-based 行号校验；allow_end 允许指向末行之后（用于 insert_after 尾部）。"""
    n = len(lines)
    if line < 1 or line > n + (1 if allow_end else 0):
        raise TextPatchError(f"行号 {line} 越界（共 {n} 行）")
    return line


def _apply_line(text: str, op: dict) -> tuple[str, int]:
    lines = _split_lines(text)
    action = op.get("action")
    line = int(op.get("line", 0))
    content = op.get("content", "")
    newline = op.get("newline", "")
    if action == "replace":
        i = _apply_line_num(lines, line) - 1
        old_line_text = lines[i].rstrip("\r\n")
        if "expected" in op and old_line_text != op["expected"]:
            raise TextPatchError(
                f"第 {line} 行内容不是预期值，拒绝替换。\n"
                f"  实际: {old_line_text!r}\n  期望: {op['expected']!r}")
        lines[i] = content + _line_ending(lines[i], newline)
        return _join_lines(lines), 1
    if action == "insert_before":
        _apply_line_num(lines, line, allow_end=True)
        lines.insert(line - 1, content + _line_ending("\n", newline))
        return _join_lines(lines), 1
    if action == "insert_after":
        _apply_line_num(lines, line, allow_end=True)
        i = line  # 插入到第 line 行之后
        insert = content + _line_ending("\n", newline)
        # 若原文件最后一行无换行，先补换行再插入，保证结构
        if i == len(lines) and lines and not lines[-1].endswith("\n"):
            lines[-1] = lines[-1] + "\n"
        lines.insert(i, insert)
        return _join_lines(lines), 1
    if action == "delete":
        _apply_line_num(lines, line)
        del lines[line - 1]
        return _join_lines(lines), 1
    raise TextPatchError(f"未知行操作: {action}")


def _apply_line_num(lines: list[str], line: int, allow_end: bool = False) -> int:
    n = len(lines)
    if line < 1 or line > n + (1 if allow_end else 0):
        raise TextPatchError(f"行号 {line} 越界（共 {n} 行）")
    return line


def _line_ending(line: str, newline: str = "") -> str:
    if newline:
        return "\r\n" if newline in ("crlf", "\\r\\n") else "\n"
    if line.endswith("\r\n"):
        return "\r\n"
    if line.endswith("\n"):
        return "\n"
    return "\n"


def _parse_json_path(path: str) -> list:
    """将 a.b[0].c 解析为访问 token 列表。"""
    tokens = []
    for part in path.replace("[", ".[").replace("]", "").split("."):
        part = part.strip()
        if not part:
            continue
        if part.startswith("["):
            tokens.append(part[1:].strip())
        else:
            tokens.append(part)
    if not tokens:
        raise TextPatchError(f"JSON 路径为空: {path}")
    return tokens


def _get_json(data, tokens):
    cur = data
    for i, t in enumerate(tokens):
        if isinstance(cur, dict):
            if t not in cur:
                raise TextPatchError(f"JSON 键不存在: {'.'.join(tokens[:i + 1])}")
            cur = cur[t]
        elif isinstance(cur, list):
            try:
                idx = int(t)
            except ValueError:
                raise TextPatchError(f"列表下标非法: {t}")
            if idx < 0 or idx >= len(cur):
                raise TextPatchError(f"JSON 下标越界: {t}（长度 {len(cur)}）")
            cur = cur[idx]
        else:
            raise TextPatchError(f"JSON 路径中断于非容器节点: {'.'.join(tokens[:i])}")
    return cur


def _set_json(data, tokens, value):
    cur = data
    for i, t in enumerate(tokens[:-1]):
        nxt = tokens[i + 1]
        if isinstance(cur, dict):
            if t not in cur:
                cur[t] = [] if str(nxt).isdigit() else {}
            cur = cur[t]
        elif isinstance(cur, list):
            idx = int(t)
            while len(cur) <= idx:
                cur.append(None)
            if cur[idx] is None:
                cur[idx] = [] if str(nxt).isdigit() else {}
            cur = cur[idx]
        else:
            raise TextPatchError(f"JSON 路径中断于非容器节点: {t}")
    last = tokens[-1]
    if isinstance(cur, dict):
        cur[last] = value
    elif isinstance(cur, list):
        idx = int(last)
        while len(cur) <= idx:
            cur.append(None)
        cur[idx] = value
    else:
        raise TextPatchError(f"JSON 路径中断于非容器节点: {last}")


def _apply_json(text: str, op: dict) -> tuple[str, int]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise TextPatchError(f"JSON 解析失败: {e}")
    path = op["path"]
    tokens = _parse_json_path(path)
    value = op.get("value")
    new_val = op.get("new_value", value)  # value / new_value 二选一
    old_val = _get_json(data, tokens)
    if "old_value" in op and op["old_value"] is not None:
        if old_val != op["old_value"]:
            raise TextPatchError(
                f"JSON 键 {path} 当前值 {old_val!r} 与 expected_value {op['old_value']!r} 不符")
    _set_json(data, tokens, new_val)
    indent = _detect_json_indent(text)
    new_text = json.dumps(data, ensure_ascii=False, indent=indent)
    # 保留原有尾随换行与首尾空白
    head = text[:len(text) - len(text.lstrip("\ufeff \t\r\n"))]
    tail = text[len(text.rstrip("\r\n \t")):]
    if text.startswith("\ufeff"):
        new_text = "\ufeff" + new_text
    new_text = head + new_text.lstrip("\ufeff \t\r\n") + tail
    return new_text, 1


def _detect_json_indent(text: str) -> int | None:
    """探测原 JSON 缩进；紧凑版返回 None（保持紧凑）。"""
    for line in text.splitlines():
        s = line
        if not s.startswith(" "):
            continue
        cnt = len(s) - len(s.lstrip(" "))
        if cnt > 0:
            return cnt
    return None


def _apply_ini(text: str, op: dict) -> tuple[str, int]:
    import configparser
    cfg = configparser.ConfigParser(allow_no_value=True, strict=False)
    try:
        cfg.read_string(text)
    except configparser.Error as e:
        raise TextPatchError(f"INI 解析失败: {e}")
    section = op.get("section")
    key = op.get("key")
    value = op.get("value") or op.get("new_value")
    if section is None or key is None:
        raise TextPatchError("INI 操作需要 section 与 key")
    if not cfg.has_section(section):
        cfg.add_section(section)
    old = cfg.get(section, key, fallback=None)
    if "expected_value" in op and op["expected_value"] is not None and old != op["expected_value"]:
        raise TextPatchError(
            f"INI {section}.{key} 当前值 {old!r} 与预期 {op['expected_value']!r} 不符")
    cfg.set(section, key, str(value))
    # 保留注释与格式：基于原文本做行替换而非重新序列化
    new_text, changed = _ini_rewrite(text, section, key, str(value))
    if not changed:
        raise TextPatchError(f"INI 未找到 {section}.{key} 行（新增节/键不在文本补丁范围内）")
    return new_text, 1


def _ini_rewrite(text: str, section: str, key: str, value: str) -> tuple[str, bool]:
    """以行级替换方式修改 INI 值，保留注释；找不到返回未修改。"""
    lines = _split_lines(text)
    cur_section = None
    changed = False
    out = []
    for ln in lines:
        s = ln.rstrip("\r\n")
        stripped = s.strip()
        out.append(ln)
        if not stripped or (stripped.startswith(";") or stripped.startswith("#")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            cur_section = stripped[1:-1].strip()
            continue
        if cur_section != section:
            continue
        if "=" in s or ":" in s:
            k, _v = re.split(r"[=:]", s, 1)
            if k.strip() == key:
                indent = s[:len(s) - len(s.lstrip())]
                # 只替换 key 之后的原始分隔符部分，保留原格式/空格/分隔符
                key_pos = s.find(k.strip())
                tail = s[key_pos + len(k.strip()):]
                # tail 形如 "=1920" 或 " = 1920"，仅替换其值部分
                m = re.match(r"^(\s*[=:]\s*)(.*)$", tail)
                if m:
                    out[-1] = indent + k.strip() + m.group(1) + value + _line_ending(ln)
                else:
                    out[-1] = indent + k.strip() + tail + value + _line_ending(ln)
                changed = True
                continue
    return _join_lines(out), changed


TXT_OPERATIONS = {
    "replace": _apply_replace,
    "regex": _apply_regex,
    "line": _apply_line,
    "json": _apply_json,
    "ini": _apply_ini,
}


def apply_text_patch(file: str, ops: list[dict], encoding: str | None = None,
                     force: bool = False, dry_run: bool = False) -> dict:
    """执行文本补丁。流程：读文本 -> 内存中顺序模拟全部 ops（任一失败整批拒绝）
    -> 备份 -> 写盘 -> 回读 SHA-256 校验（失败自动回滚）。"""
    if not os.path.exists(file):
        raise TextPatchError(f"文件不存在: {file}")
    if os.path.isdir(file):
        raise TextPatchError(f"路径是目录: {file}")
    if not ops:
        raise TextPatchError("ops 列表为空")

    text, enc = read_text(file, encoding)

    # 1. 模拟执行全部 ops（原子性）
    results = []
    current = text
    for i, op in enumerate(ops):
        kind = op.get("op")
        fn = TXT_OPERATIONS.get(kind)
        if fn is None:
            raise TextPatchError(f"第 {i + 1} 个操作未知类型: {kind!r}")
        try:
            new_text, n = fn(current, op)
        except TextPatchError as e:
            raise TextPatchError(f"ops[{i}]({kind}) 失败: {e}")
        changed = new_text != current
        results.append({"op": kind, "changed": changed, "count": n})
        current = new_text
    if current == text:
        raise TextPatchError("所有 ops 均无实际变更（可能补丁已生效过）")

    # 2. 备份保护
    bak = file + BACKUP_SUFFIX_TXT
    if os.path.exists(bak) and not force:
        raise TextPatchError(
            f"已存在文本备份 {bak}；若确认当前文件是补丁前原文件，请传 force=true")

    if dry_run:
        return {
            "dry_run": True, "file": file, "encoding": enc, "ops": results,
            "note": "未写入任何内容", "preview": _diff_summary(text, current),
        }

    backup_path = _do_backup(file, bak)

    # 3. 写盘 + 4. 回读校验
    try:
        with open(file, "w", encoding=enc, newline="") as f:
            f.write(current)
        with open(file, "rb") as f:
            got = f.read()
        expected = current.encode(enc)
        if got != expected:
            raise TextPatchError("回读内容不匹配，补丁未生效")
    except Exception as e:
        shutil.copy2(backup_path, file)
        raise TextPatchError(f"写回/回读失败，已从备份回滚: {e}")

    # 再次回读最终确认 + 计算摘要
    with open(file, "rb") as f:
        new_raw = f.read()
    new_text2 = new_raw.decode(enc)

    return {
        "file": file, "encoding": enc, "backup": backup_path,
        "ops": results, "status": "applied",
        "sha256": _sha256(file),
        "preview": _diff_summary(text, new_text2, max_ctx=3),
    }


def _do_backup(file: str, bak: str) -> str:
    shutil.copy2(file, bak)
    return bak


def _sha256(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for ch in iter(lambda: f.read(1 << 20), b""):
            h.update(ch)
    return h.hexdigest()


def _diff_summary(old: str, new: str, max_ctx: int = 3) -> list[dict]:
    """极简 diff：按行找增删差异，返回变更块（行号、旧/新、上下文）。"""
    import difflib
    old_l = old.splitlines()
    new_l = new.splitlines()
    sm = difflib.SequenceMatcher(a=old_l, b=new_l)
    out = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        block = {
            "tag": tag,
            "old_lines": [f"{i1 + k}:{old_l[x]}" for k, x in enumerate(range(i1, i2))],
            "new_lines": [f"{j1 + k}:{new_l[x]}" for k, x in enumerate(range(j1, j2))],
        }
        out.append(block)
    return out[:8]


def text_dump(path: str, start: int = 1, end: int | None = None,
              encoding: str | None = None) -> dict:
    text, enc = read_text(path, encoding)
    lines = _split_lines(text)
    total = len(lines)
    end = total if end is None else min(end, total)
    if start < 1:
        raise TextPatchError(f"起始行号不能小于 1: {start}")
    if start > end:
        raise TextPatchError(f"start({start}) > end({end})")
    shown = [f"{i + 1:6d} | {lines[i].rstrip(chr(10)).rstrip(chr(13))}"
             for i in range(start - 1, end)]
    return {"file": path, "encoding": enc, "total_lines": total,
            "lines": shown}


def text_search(path: str, pattern: str, regex: bool = False,
                encoding: str | None = None) -> dict:
    text, enc = read_text(path, encoding)
    lines = _split_lines(text)
    hits = []
    for i, ln in enumerate(lines, 1):
        body = ln.rstrip("\r\n")
        if regex:
            try:
                if re.search(pattern, body):
                    hits.append(i)
            except re.error:
                raise TextPatchError(f"正则无效: {pattern}")
        else:
            if pattern in body:
                hits.append(i)
    return {"file": path, "encoding": enc, "total_lines": len(lines),
            "hits": hits, "count": len(hits)}


def text_verify(path: str, contains: str | None = None,
                not_contains: str | None = None,
                regex: bool = False, encoding: str | None = None) -> dict:
    text, enc = read_text(path, encoding)
    results = {}
    ok = True
    if contains is not None:
        if regex:
            m = bool(re.search(contains, text))
        else:
            m = contains in text
        results["contains"] = m
        ok = ok and m
    if not_contains is not None:
        if regex:
            m = bool(re.search(not_contains, text))
        else:
            m = not_contains in text
        # 期望"不含" -> 不存在才为真
        results["not_contains"] = not m
        ok = ok and (not m)
    return {"file": path, "encoding": enc, "checks": results, "match": ok}


def text_restore(file: str, force: bool = False) -> dict:
    bak = file + BACKUP_SUFFIX_TXT
    if not os.path.exists(bak):
        raise TextPatchError(f"文本备份不存在: {bak}")
    if os.path.exists(file) and not force:
        raise TextPatchError(f"目标文件 {file} 仍存在；传入 force=true 才能用备份覆盖它")
    shutil.copy2(bak, file)
    return {"file": file, "restored_from": bak}


# ---------------------------------------------------------------- CLI
def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(prog="rea-text-patcher",
                                 description="rea 配套的多语言文本/代码补丁层")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_view = sub.add_parser("view", help="只读按行查看")
    p_view.add_argument("file")
    p_view.add_argument("-s", "--start", type=int, default=1)
    p_view.add_argument("-e", "--end", type=int, default=None)
    p_view.add_argument("--encoding")

    p_search = sub.add_parser("search", help="只读全文搜索")
    p_search.add_argument("file")
    p_search.add_argument("pattern")
    p_search.add_argument("-r", "--regex", action="store_true")
    p_search.add_argument("--encoding")

    p_patch = sub.add_parser("patch", help="打文本补丁")
    p_patch.add_argument("file")
    p_patch.add_argument("-o", "--op", action="append", required=True,
                         help="单个 op 的 JSON 字符串，可多次")
    p_patch.add_argument("--encoding")
    p_patch.add_argument("--dry-run", action="store_true")

    p_verify = sub.add_parser("verify", help="只读校验")
    p_verify.add_argument("file")
    p_verify.add_argument("--contains", default=None)
    p_verify.add_argument("--not-contains", default=None)
    p_verify.add_argument("-r", "--regex", action="store_true")
    p_verify.add_argument("--encoding")

    p_restore = sub.add_parser("restore", help="从文本备份恢复")
    p_restore.add_argument("file")
    p_restore.add_argument("--force", action="store_true")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "view":
            r = text_dump(args.file, args.start, args.end, args.encoding)
            print(f"[{r['file']}] encoding={r['encoding']} total={r['total_lines']}")
            print("\n".join(r["start"]) or "(空文件)")
        elif args.cmd == "search":
            r = text_search(args.file, args.pattern, args.regex, args.encoding)
            print(f"[{r['file']}] encoding={r['encoding']} 命中 {r['count']} 行: {r['hits']}")
        elif args.cmd == "patch":
            ops = [json.loads(o) for o in args.op]
            r = apply_text_patch(args.file, ops, args.encoding,
                                 dry_run=args.dry_run)
            print(json.dumps(r, ensure_ascii=False, indent=2))
        elif args.cmd == "verify":
            r = text_verify(args.file, args.contains, getattr(args, "not_contains"),
                            args.regex, args.encoding)
            print(json.dumps(r, ensure_ascii=False, indent=2))
        elif args.cmd == "restore":
            r = text_restore(args.file, args.force)
            print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0
    except TextPatchError as e:
        die(str(e))
    except FileNotFoundError as e:
        die(str(e))
    except json.JSONDecodeError as e:
        die(f"JSON 解析失败: {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main())