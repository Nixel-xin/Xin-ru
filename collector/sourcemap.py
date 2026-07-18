"""sourcemap 发现 + 还原引擎

策略:
1. 从已收集的 JS 文件末尾寻找 sourceMappingURL
2. 下载 .map 文件
3. 用 python-sourcemap 还原原始源码（sourcesContent）
4. 将还原的源码写入独立文件
"""

import os
import re
from urllib.parse import urljoin

import httpx

from .orchestrator import _save_file, _is_duplicate, _count_lines


# 匹配 sourcemap 引用
# //# sourceMappingURL=bundle.js.map
SOURCEMAP_PATTERN = re.compile(
    r"//#\s*sourceMappingURL\s*=\s*(.+?)(?:\s*\n|\s*$)",
    re.IGNORECASE,
)


async def sourcemap_collect(
    targets: list[str],
    work_dir: str,
    collected_files: list[dict],
) -> list[dict]:
    """从已收集的 JS 文件中发现 .map 文件并还原源码"""
    results: list[dict] = []
    target_domain = targets[0] if targets else ""

    # 找出所有 JS 文件的 URL 和本地路径
    js_files = [
        (f["url"], f["local_path"])
        for f in collected_files
        if f.get("source_type") in (
            "js_bundle", "spider", "path_brute",
            "llm_js", "llm_inline", "llm_entry",
        )
        and str(f.get("local_path") or "").endswith((".js", ".mjs", ".ts", ".jsx", ".tsx", ".txt", ".html"))
    ]

    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        for js_url, js_path in js_files:
            # 尝试方法 1: 从文件末尾找 sourceMappingURL
            map_url = None
            try:
                with open(js_path, "r", encoding="utf-8", errors="replace") as f:
                    # 只读末尾 500 字符（sourcemap 引用在最后）
                    f.seek(0, 2)
                    size = f.tell()
                    f.seek(max(0, size - 500))
                    tail = f.read()
                    match = SOURCEMAP_PATTERN.search(tail)
                    if match:
                        map_ref = match.group(1).strip()
                        map_ref = map_ref.rstrip(".,;")
                        map_url = urljoin(js_url, map_ref)
            except Exception:
                pass

            # 尝试方法 2: 直接加 .map 后缀
            if not map_url:
                map_url = js_url + ".map"

            if not map_url:
                continue

            # 下载 .map 文件
            try:
                resp = await client.get(map_url)
                if resp.status_code != 200:
                    continue

                map_content = resp.text
                if not map_content.startswith("{") or '"version"' not in map_content[:100]:
                    continue  # 不是有效的 sourcemap

                # ---- 还原源码 ----
                restored = _restore_sourcemap(map_content)
                if not restored:
                    continue

                # 保存还原的源文件
                target_dir = os.path.join(work_dir, "sourcemap")
                for src_path, src_content in restored.items():
                    # 防止文件名冲突
                    safe_name = src_path.replace("/", "_").replace("\\", "_").lstrip("._")
                    if not safe_name.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs")):
                        safe_name += ".js"

                    filepath = _save_file(src_content, target_dir, safe_name)
                    if _is_duplicate(filepath):
                        continue

                    results.append({
                        "source_type": "sourcemap_restored",
                        "url": f"{map_url}#{src_path}",
                        "local_path": filepath,
                        "file_name": safe_name,
                        "file_size": len(src_content.encode()),
                        "line_count": _count_lines(filepath),
                    })

                print(f"[sourcemap] ✅ {map_url} → 还原 {len(restored)} 个源文件")

            except Exception as e:
                print(f"[sourcemap] ❌ {map_url}: {e}")

    print(f"[sourcemap] 收集完成: {len(results)} 个还原文件")
    return results


def _restore_sourcemap(map_content: str) -> dict[str, str]:
    """解析 sourcemap JSON 并还原源码

    优先使用 sourcesContent 字段（内嵌在 .map 中的原始源码）。
    如果不存在，返回空 dict（需要实际源码文件）。
    """
    import json
    try:
        data = json.loads(map_content)
    except json.JSONDecodeError:
        return {}

    sources: list[str] = data.get("sources", [])
    contents: list[str] | None = data.get("sourcesContent")

    result: dict[str, str] = {}
    if contents:
        for src, content in zip(sources, contents):
            if content and len(content.strip()) > 10:
                result[src] = content
    else:
        # 没有 sourcesContent → 尝试用 python-sourcemap 库解析映射
        try:
            from sourcemap import SourceMap
            import io
            sm = SourceMap.loads(map_content)
            # 即使没有 sourcesContent，我们也记录了 sources 列表
            # 实际还原需要爬取对应路径的源文件
            for src in sources:
                result[src] = f"// [sourcemap reference] {src}\n// sourcesContent not embedded - source file not available"
        except ImportError:
            pass

    return result
