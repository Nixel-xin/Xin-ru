"""源码预处理：美化压缩 JS、丰富文件清单类型

xinru 要求：minified 也要扫，但先 beautify 再逐行，避免一行 5 万字符导致上下文爆炸。
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any


SOURCE_EXTS = {
    ".js", ".mjs", ".cjs", ".jsx",
    ".ts", ".tsx",
    ".vue", ".svelte",
    ".map",
    ".json", ".html", ".htm",
    ".css",  # 也扫：可能藏 sourcemap / 内联
}

_MINIFIED_HINTS = re.compile(r"[\w$]{1,3}=[\w$]{1,3}\([\w$,]{0,40}\)[,;]")


def is_source_path(path: str) -> bool:
    ext = Path(path).suffix.lower()
    if ext in SOURCE_EXTS:
        return True
    name = Path(path).name.lower()
    return name in ("webpack.js", "chunk.js") or name.endswith(".js.map")


def looks_minified(content: str, path: str = "") -> bool:
    if not content:
        return False
    name = (path or "").lower()
    if ".min." in name or name.endswith(".min.js"):
        return True
    lines = content.splitlines()
    if not lines:
        return False
    # 单行巨长 / 平均行长极高
    if len(lines) <= 5 and max(len(x) for x in lines) > 500:
        return True
    avg = sum(len(x) for x in lines) / max(len(lines), 1)
    if avg > 300 and len(lines) < 80:
        return True
    sample = "\n".join(lines[:3])
    if len(sample) > 400 and _MINIFIED_HINTS.search(sample):
        return True
    return False


def simple_beautify_js(content: str) -> str:
    """轻量美化：不依赖 jsbeautifier。优先结构可读，不求完美 AST。"""
    if not content:
        return content
    s = content.replace("\r\n", "\n").replace("\r", "\n")
    # 已有较多换行则不动
    if s.count("\n") >= max(20, len(s) // 200):
        return s

    out: list[str] = []
    i = 0
    n = len(s)
    indent = 0
    in_str = False
    str_ch = ""
    escape = False
    in_line_comment = False
    in_block_comment = False

    def nl():
        nonlocal out
        out.append("\n" + ("  " * max(indent, 0)))

    while i < n:
        ch = s[i]
        nxt = s[i + 1] if i + 1 < n else ""

        if in_line_comment:
            out.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            out.append(ch)
            if ch == "*" and nxt == "/":
                out.append("/")
                i += 2
                in_block_comment = False
                continue
            i += 1
            continue
        if in_str:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == str_ch:
                in_str = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            out.append("//")
            i += 2
            in_line_comment = True
            continue
        if ch == "/" and nxt == "*":
            out.append("/*")
            i += 2
            in_block_comment = True
            continue
        if ch in ('"', "'", "`"):
            in_str = True
            str_ch = ch
            out.append(ch)
            i += 1
            continue

        if ch in "{[":
            out.append(ch)
            indent += 1
            nl()
            i += 1
            continue
        if ch in "}]":
            indent = max(indent - 1, 0)
            nl()
            out.append(ch)
            if nxt and nxt not in ",;)]}\n":
                nl()
            i += 1
            continue
        if ch == ";":
            out.append(ch)
            if nxt not in "\n":
                nl()
            i += 1
            continue
        if ch == ",":
            out.append(ch)
            if nxt not in "\n ":
                out.append(" ")
            i += 1
            continue
        out.append(ch)
        i += 1

    text = "".join(out)
    # 压缩多余空行
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip() + "\n"


def preprocess_file(path: str, *, write_sidecar: bool = True) -> dict[str, Any]:
    """读取并在需要时美化。返回 {path, content, beautified, original_lines, lines}"""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {
            "path": path,
            "content": "",
            "beautified": False,
            "error": str(e),
            "original_lines": 0,
            "lines": 0,
        }

    original_lines = raw.count("\n") + (1 if raw and not raw.endswith("\n") else 0)
    beautified = False
    content = raw
    if looks_minified(raw, path) and Path(path).suffix.lower() in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}:
        content = simple_beautify_js(raw)
        beautified = content != raw
        if beautified and write_sidecar:
            side = p.with_suffix(p.suffix + ".beautified")
            try:
                side.write_text(content, encoding="utf-8")
            except Exception:
                pass

    lines = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
    return {
        "path": path,
        "content": content,
        "beautified": beautified,
        "original_lines": original_lines,
        "lines": lines,
        "sha1": hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:12],
    }


def expand_inventory(paths: list[str]) -> list[str]:
    """扩展文件清单：同目录 map/ts/vue 等，不丢弃任何源文件。"""
    seen: set[str] = set()
    out: list[str] = []
    for p in paths or []:
        try:
            ap = str(Path(p).resolve())
        except Exception:
            ap = os.path.abspath(p)
        if ap in seen:
            continue
        if os.path.isfile(ap):
            seen.add(ap)
            out.append(ap)
        parent = Path(ap).parent
        if not parent.is_dir():
            continue
        try:
            for child in parent.iterdir():
                if not child.is_file():
                    continue
                if not is_source_path(str(child)):
                    continue
                cp = str(child.resolve())
                if cp not in seen:
                    seen.add(cp)
                    out.append(cp)
        except Exception:
            continue
    return out


def inventory_stats(paths: list[str]) -> dict[str, Any]:
    by_ext: dict[str, int] = {}
    total_lines = 0
    large = 0
    for p in paths:
        ext = Path(p).suffix.lower() or "(none)"
        by_ext[ext] = by_ext.get(ext, 0) + 1
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                n = sum(1 for _ in f)
            total_lines += n
            if n > 2000:
                large += 1
        except Exception:
            pass
    return {
        "files": len(paths),
        "total_lines_est": total_lines,
        "large_files": large,
        "by_ext": by_ext,
    }
