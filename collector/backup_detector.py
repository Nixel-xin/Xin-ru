"""备份/临时文件扫描引擎

针对已知 JS 文件 URL 探测常见备份/编辑器临时文件:
- xxx.js.bak / xxx.js~ / xxx.js.old / xxx.js.orig
- .xxx.js.swp / .xxx.js.swo / .xxx.js.swn
- xxx.js.swp / xxx.js.swo
- xxx.js.bk / xxx.js.backup
- xxx-dev.js / xxx.min.js / xxx.prod.js
"""

import os
import httpx
from urllib.parse import urljoin

from .orchestrator import _save_file, _is_duplicate, _count_lines

# 备份后缀列表
BACKUP_SUFFIXES = [
    ".bak", ".backup", ".old", ".orig", ".bk",
    "~",  # emacs/vim 备份
]

# editor 临时文件模式
SWAP_PATTERNS = [
    ".{name}.swp", ".{name}.swo", ".{name}.swn",  # vim
    "{name}.swp", "{name}.swo",                   # 某些配置
    "#{name}#",                                    # emacs autosave
    "{name}.save",                                 # 编辑器保存
]

# 变体
VARIANT_SUFFIXES = [".dev", ".prod", ".staging", ".test", ".min"]


async def backup_collect(
    targets: list[str],
    work_dir: str,
    collected_files: list[dict],
) -> list[dict]:
    """扫描备份和临时文件"""
    results: list[dict] = []

    # 从已收集文件中提取 JS URL 列表
    js_urls = list(set(
        f["url"] for f in collected_files
        if f.get("source_type") in (
            "js_bundle", "spider", "sourcemap_restored",
            "llm_js", "path_brute",
        )
        and str(f.get("url") or "").split("?")[0].endswith((".js", ".mjs", ".ts", ".jsx", ".tsx"))
    ))

    # 同时直接对 target 域名构造常见路径
    base_urls = js_urls.copy()
    for target in targets:
        base_urls.append(target.rstrip("/") + "/")

    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        seen_urls = set(js_urls)  # 已经有的不重复探测

        for url in base_urls:
            # 去除 query string
            base_url = url.split("?")[0]

            # ---- 备份文件探测 ----
            for suffix in BACKUP_SUFFIXES:
                test_url = base_url + suffix
                if test_url in seen_urls:
                    continue
                seen_urls.add(test_url)

                try:
                    resp = await client.get(test_url)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        target_dir = os.path.join(work_dir, "backup")
                        filename = os.path.basename(base_url) + suffix
                        filepath = _save_file(resp.text, target_dir, filename)
                        if _is_duplicate(filepath):
                            continue
                        results.append({
                            "source_type": "backup",
                            "url": test_url,
                            "local_path": filepath,
                            "file_name": filename,
                            "file_size": len(resp.text.encode()),
                            "line_count": _count_lines(filepath),
                        })
                except Exception:
                    continue

            # ---- 编辑器临时文件 ----
            name = os.path.basename(base_url)
            for pattern in SWAP_PATTERNS:
                test_name = pattern.format(name=name)
                test_url = urljoin(
                    base_url.rsplit("/", 1)[0] + "/",
                    test_name,
                )
                if test_url in seen_urls:
                    continue
                seen_urls.add(test_url)

                try:
                    resp = await client.get(test_url)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        target_dir = os.path.join(work_dir, "backup")
                        filepath = _save_file(resp.text, target_dir, test_name)
                        if _is_duplicate(filepath):
                            continue
                        results.append({
                            "source_type": "backup",
                            "url": test_url,
                            "local_path": filepath,
                            "file_name": test_name,
                            "file_size": len(resp.text.encode()),
                            "line_count": _count_lines(filepath),
                        })
                except Exception:
                    continue

            # ---- 变体探测 (xxx.min.js → xxx.dev.js) ----
            if name.endswith((".js", ".mjs")):
                stem = name.rsplit(".", 1)[0]
                for variant in VARIANT_SUFFIXES:
                    test_name = f"{stem}{variant}.js"
                    test_url = urljoin(
                        base_url.rsplit("/", 1)[0] + "/",
                        test_name,
                    )
                    if test_url in seen_urls:
                        continue
                    seen_urls.add(test_url)

                    try:
                        resp = await client.get(test_url)
                        if resp.status_code == 200 and len(resp.text) > 10:
                            target_dir = os.path.join(work_dir, "backup")
                            filepath = _save_file(resp.text, target_dir, test_name)
                            if _is_duplicate(filepath):
                                continue
                            results.append({
                                "source_type": "backup",
                                "url": test_url,
                                "local_path": filepath,
                                "file_name": test_name,
                                "file_size": len(resp.text.encode()),
                                "line_count": _count_lines(filepath),
                            })
                    except Exception:
                        continue

    print(f"[backup] 收集完成: {len(results)} 个备份/变体文件")
    return results
