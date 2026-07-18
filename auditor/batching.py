"""xinru 模式 B 文件分批

策略:
- 同模块/同目录尽量同批
- utils/shared 单独成批
- 小文件 10/批, 中 5/批, 大 1/批
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


_UTILS_HINT = re.compile(r"(?i)(^|/)(utils?|shared|common|lib|helpers?|vendor|node_modules)(/|$)")


def _line_count(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def _module_key(path: str) -> str:
    p = Path(path)
    parts = list(p.parts)
    # 取倒数第二/三层作为模块键
    if len(parts) >= 3:
        return str(Path(*parts[-3:-1]))
    if len(parts) >= 2:
        return str(Path(*parts[-2:-1]))
    return p.parent.name or "root"


def is_utils_path(path: str) -> bool:
    return bool(_UTILS_HINT.search(path.replace("\\", "/")))


def size_bucket(lines: int) -> str:
    if lines > 2000:
        return "large"
    if lines >= 500:
        return "medium"
    return "small"


def batch_capacity(bucket: str) -> int:
    if bucket == "large":
        return 1
    if bucket == "medium":
        return 5
    return 10


def build_batches(file_paths: list[str]) -> list[dict[str, Any]]:
    """返回 [{batch_id, files, kind, module}]"""
    utils: list[tuple[str, int]] = []
    groups: dict[str, list[tuple[str, int]]] = {}

    for fp in file_paths:
        if not fp:
            continue
        n = _line_count(fp)
        if is_utils_path(fp):
            utils.append((fp, n))
            continue
        key = _module_key(fp)
        groups.setdefault(key, []).append((fp, n))

    batches: list[dict[str, Any]] = []
    bid = 1

    # utils 单独批次，按大小再切
    if utils:
        for chunk in _chunk_by_size(utils):
            batches.append({
                "batch_id": f"B{bid}",
                "kind": "utils",
                "module": "utils/shared",
                "files": [p for p, _ in chunk],
                "line_counts": {p: n for p, n in chunk},
            })
            bid += 1

    # 普通模块：先大文件优先
    modules = sorted(groups.items(), key=lambda kv: -max((n for _, n in kv[1]), default=0))
    for mod, items in modules:
        # 模块内也按行数降序
        items = sorted(items, key=lambda x: -x[1])
        for chunk in _chunk_by_size(items):
            batches.append({
                "batch_id": f"B{bid}",
                "kind": "module",
                "module": mod,
                "files": [p for p, _ in chunk],
                "line_counts": {p: n for p, n in chunk},
            })
            bid += 1

    return batches


def _chunk_by_size(items: list[tuple[str, int]]) -> list[list[tuple[str, int]]]:
    """按 xinru 容量切分，大文件独享。"""
    chunks: list[list[tuple[str, int]]] = []
    cur: list[tuple[str, int]] = []
    cur_bucket = None
    for item in items:
        b = size_bucket(item[1])
        cap = batch_capacity(b)
        if b == "large":
            if cur:
                chunks.append(cur)
                cur = []
                cur_bucket = None
            chunks.append([item])
            continue
        if not cur:
            cur = [item]
            cur_bucket = b
            continue
        # 不同 bucket 或超容量 → 新开
        if cur_bucket != b or len(cur) >= batch_capacity(cur_bucket or "small"):
            chunks.append(cur)
            cur = [item]
            cur_bucket = b
        else:
            cur.append(item)
    if cur:
        chunks.append(cur)
    return chunks


def cross_batch_context(
    all_files: list[str],
    needed_name: str,
    *,
    around: str = "",
    window: int = 50,
) -> dict[str, Any]:
    """主 Agent 处理跨批文件请求：按文件名/函数名提取上下文。"""
    candidates = [p for p in all_files if needed_name in p or os.path.basename(p) == needed_name]
    if not candidates and around:
        # 函数名搜索
        for p in all_files:
            try:
                text = Path(p).read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if re.search(rf"\b{re.escape(around)}\b", text):
                candidates.append(p)
                break
    if not candidates:
        return {"ok": False, "error": f"file not found: {needed_name}", "context": ""}

    path = candidates[0]
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        return {"ok": False, "error": str(e), "context": ""}

    if around:
        hit = None
        for i, ln in enumerate(lines):
            if around in ln:
                hit = i
                break
        if hit is None:
            start, end = 0, min(len(lines), window * 2)
        else:
            start = max(0, hit - window)
            end = min(len(lines), hit + window)
    else:
        start, end = 0, min(len(lines), window * 2)

    snippet = "\n".join(f"{i+1}:{lines[i]}" for i in range(start, end))
    return {
        "ok": True,
        "path": path,
        "start_line": start + 1,
        "end_line": end,
        "context": snippet,
    }
