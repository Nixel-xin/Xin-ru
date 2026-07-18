"""路径爆破引擎

对目标发起常见目录/文件路径探测，发现新的 JS 文件、API 端点、配置文件等。

策略:
1. 对每个 target 探测常见路径
2. 发现 JS 文件 → 下载
3. 发现 JSON/配置文件 → 下载
4. 记录所有发现的路径（即使没 JS 也作为上下文信息）
"""

import os
import httpx
from urllib.parse import urljoin, urlparse

from .orchestrator import _save_file, _is_duplicate, _count_lines

# 常见 JS/前端路径字典
JS_PATHS = [
    # 配置文件
    "config.js", "config.json", "setting.js", "settings.json",
    "app.config.js", "appConfig.js", "basisConfig.js",
    "env.js", "env.json",
    "manifest.json",

    # 路由文件
    "app.js", "main.js", "index.js", "bundle.js",
    "vendor.js", "common.js", "chunk-vendors.js",
    "runtime.js", "polyfills.js",

    # API 描述
    "swagger.json", "openapi.json", "api-docs.json",
    "api/swagger.json", "v2/api-docs",

    # 源码目录
    "js/app.js", "js/main.js", "js/config.js",
    "static/js/app.js", "static/js/main.js",
    "assets/js/app.js", "assets/js/main.js",
    "dist/js/app.js", "dist/js/main.js",
    "build/js/app.js", "build/js/main.js",

    # Webpack
    "webpack.config.js", "vite.config.js",

    # 其他
    "robots.txt", "sitemap.xml", "security.txt",
    "crossdomain.xml", "clientaccesspolicy.xml",

    # 常见小程序/移动端
    "app.json", "app-service.js", "webview.js",
    "common.app.js", "page-frame.js",

    # 调试信息
    "debug.js", "debug.json", "log.json",

    # sourcemap（名字里带 map 的）
    "app.js.map", "bundle.js.map", "vendor.js.map",
]

# 常见目录（索引可能暴露文件列表）
COMMON_DIRS = [
    "static/", "assets/", "js/", "css/", "dist/",
    "build/", "public/", "resources/", "source/",
    "api/", "v1/", "v2/", "v3/",
    "admin/", "manage/", "console/",
    "upload/", "uploads/", "files/",
    "logs/", "log/",
    "backup/", "bak/", "old/",
    "test/", "tests/", "testing/",
    "tmp/", "temp/", "cache/",
    "config/", "conf/", "inc/", "include/",
    "vendor/", "node_modules/",
    ".git/", ".svn/", ".hg/",
    ".vscode/", ".idea/",
]


async def path_brute_collect(
    targets: list[str],
    work_dir: str,
    collected_files: list[dict],
) -> list[dict]:
    """对每个 target 进行路径爆破"""
    results: list[dict] = []
    already_found_urls = {f["url"] for f in collected_files}

    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        for target in targets:
            base = target.rstrip("/")
            domain = urlparse(base).netloc
            target_dir = os.path.join(work_dir, "path_brute", domain.replace(":", "_"))

            # ---- 探测 JS 文件路径 ----
            for path in JS_PATHS:
                url = urljoin(base + "/", path)
                if url in already_found_urls:
                    continue
                already_found_urls.add(url)

                try:
                    resp = await client.get(url)
                except Exception:
                    continue

                if resp.status_code != 200:
                    continue

                body = resp.text
                if len(body) < 10:
                    continue

                is_js = body.strip().startswith(("(", "!", "[", "var ", "const ", "let ", "import ", "export ", "function", "class ", "window.", "document.", "define(", "require(")) \
                    or "\"use strict\"" in body[:50] \
                    or "webpackBootstrap" in body[:200]

                is_json = body.strip().startswith("[") or body.strip().startswith("{")

                if is_js or is_json or path.endswith((".js", ".json", ".map")):
                    filename = path.replace("/", "_")
                    filepath = _save_file(body, target_dir, filename)
                    if _is_duplicate(filepath):
                        continue
                    results.append({
                        "source_type": "path_brute",
                        "url": url,
                        "local_path": filepath,
                        "file_name": filename,
                        "file_size": len(body.encode()),
                        "line_count": _count_lines(filepath),
                    })

            # ---- 探测目录 ----
            for dir_path in COMMON_DIRS:
                url = urljoin(base + "/", dir_path)
                if url in already_found_urls:
                    continue
                already_found_urls.add(url)

                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        body = resp.text
                        # 如果是目录索引，提取页面中的 JS 文件链接
                        js_links = _extract_links(body, url)
                        for link_url in js_links:
                            if link_url in already_found_urls:
                                continue
                            already_found_urls.add(link_url)
                            try:
                                lr = await client.get(link_url)
                                if lr.status_code == 200 and len(lr.text) > 10:
                                    fname = os.path.basename(urlparse(link_url).path) or f"dir_{dir_path.replace('/', '_')}_file"
                                    fp = _save_file(lr.text, target_dir, fname)
                                    if _is_duplicate(fp):
                                        continue
                                    results.append({
                                        "source_type": "path_brute",
                                        "url": link_url,
                                        "local_path": fp,
                                        "file_name": fname,
                                        "file_size": len(lr.text.encode()),
                                        "line_count": _count_lines(fp),
                                    })
                            except Exception:
                                pass
                except Exception:
                    continue

    print(f"[path_brute] 收集完成: {len(results)} 个文件")
    return results


def _extract_links(html: str, base_url: str) -> list[str]:
    """从 HTML 页面中提取 JS/CSS/JSON 链接"""
    import re
    urls = set()
    # <script src="...">
    for match in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE):
        urls.add(urljoin(base_url, match.group(1)))
    # <link href="..."> (CSS/JSON)
    for match in re.finditer(r'href=["\']([^"\']+\.(?:css|json|map)[^"\']*)["\']', html, re.IGNORECASE):
        urls.add(urljoin(base_url, match.group(1)))
    return list(urls)
