"""LLM 主导源码收集

策略:
1. HTTP 直接抓目标首页/常见入口（不依赖 Playwright）
2. 正则粗提 script/link/api
3. 调用 Grok/LLM 从 HTML/JS 片段中提取应下载的源码与接口资产
4. 并发下载 JS/JSON/map 等文本资产并落盘
5. 可选：从已下载文件中再提取下一轮 URL（浅层扩展）
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from typing import Any
from urllib.parse import urljoin, urlparse, urldefrag

import httpx

from .orchestrator import _save_file, _is_duplicate, _count_lines


_SCRIPT_SRC_RE = re.compile(
    r"""(?is)<script[^>]+src=["']([^"']+)["']|href=["']([^"']+\.js(?:\?[^"']*)?)["']"""
)
_ABS_URL_RE = re.compile(r"""(?i)\bhttps?://[^\s"'<>\\]+""")
_REL_JS_RE = re.compile(r"""["'](/[^"']+\.js(?:\?[^"']*)?)["']""")
_INLINE_SCRIPT_RE = re.compile(r"(?is)<script(?![^>]+src=)[^>]*>(.*?)</script>")
_API_HINT_RE = re.compile(r"(?i)(api|countly|graphql|swagger|openapi|v\d+/|/i/|/o/)")


def _safe_name(url: str, fallback: str) -> str:
    path = urlparse(url).path
    name = os.path.basename(path) or fallback
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    if len(name) > 120:
        digest = hashlib.md5(url.encode()).hexdigest()[:8]
        root, ext = os.path.splitext(name)
        name = f"{root[:80]}_{digest}{ext or '.js'}"
    if not os.path.splitext(name)[1]:
        name += ".js"
    return name


def _normalize_asset_url(base: str, raw: str) -> str | None:
    raw = (raw or "").strip()
    if not raw or raw.startswith(("data:", "javascript:", "mailto:")):
        return None
    raw, _ = urldefrag(raw)
    full = urljoin(base, raw)
    parsed = urlparse(full)
    if parsed.scheme not in {"http", "https"}:
        return None
    return full


def _looks_like_api_target(target: str, content: str = "", ctype: str = "") -> bool:
    host_path = f"{urlparse(target).netloc}{urlparse(target).path}".lower()
    if any(k in host_path for k in ("api.", "/api", "countly", "graphql", "swagger")):
        return True
    low_ctype = (ctype or "").lower()
    if any(k in low_ctype for k in ("json", "javascript", "text/plain")) and not content.lstrip().startswith("<"):
        # 非 HTML 入口更像 API/配置
        if content.lstrip()[:1] in "{[":
            return True
    if content and not content.lstrip().startswith("<") and _API_HINT_RE.search(target):
        return True
    return False


def _extract_regex_assets(base_url: str, html: str) -> dict[str, list[str]]:
    scripts, maps, apis, inlines = [], [], [], []
    for m in _SCRIPT_SRC_RE.finditer(html or ""):
        raw = m.group(1) or m.group(2)
        u = _normalize_asset_url(base_url, raw)
        if u:
            scripts.append(u)
    for m in _REL_JS_RE.finditer(html or ""):
        u = _normalize_asset_url(base_url, m.group(1))
        if u:
            scripts.append(u)
    for m in _ABS_URL_RE.finditer(html or ""):
        raw = m.group(0).rstrip(").,;]}>'\"")
        u = _normalize_asset_url(base_url, raw)
        if not u:
            continue
        low = u.lower()
        if low.endswith(".js") or ".js?" in low or low.endswith(".mjs"):
            scripts.append(u)
        elif low.endswith(".map") or "sourcemap" in low:
            maps.append(u)
        elif any(k in low for k in ("/api", "graphql", "countly", "v1/", "v2/", "swagger", "openapi")):
            apis.append(u)
    for i, m in enumerate(_INLINE_SCRIPT_RE.finditer(html or "")):
        body = (m.group(1) or "").strip()
        if len(body) > 20:
            inlines.append(body)
    # dedupe preserve order
    def uniq(items: list[str]) -> list[str]:
        seen, out = set(), []
        for x in items:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out
    return {
        "scripts": uniq(scripts),
        "sourcemaps": uniq(maps),
        "apis": uniq(apis),
        "inlines": inlines[:50],
    }


async def _fetch_text(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> tuple[int, str, str]:
    r = await client.get(url, headers=headers or {}, timeout=timeout)
    ctype = r.headers.get("content-type", "")
    try:
        text = r.text
    except Exception:
        text = r.content.decode("utf-8", errors="replace")
    return r.status_code, ctype, text


def _llm_extract_assets(
    target: str,
    body_excerpt: str,
    regex_assets: dict[str, list[str]],
    *,
    is_api: bool = False,
) -> dict[str, Any]:
    """同步调用 LLM，返回结构化资产。"""
    from orchestrator.llm import call_llm_json, JSON_SYSTEM_PROMPT

    mode = "API/接口目标" if is_api else "Web/前端目标"
    prompt = f"""任务：从前端/接口入口提取应下载资产。
目标: {target}
模式: {mode}

入口内容片段（可能截断）:
```
{body_excerpt[:6000]}
```

正则已粗提取:
scripts={json.dumps((regex_assets.get('scripts') or [])[:80], ensure_ascii=False)}
apis={json.dumps((regex_assets.get('apis') or [])[:80], ensure_ascii=False)}
sourcemaps={json.dumps((regex_assets.get('sourcemaps') or [])[:40], ensure_ascii=False)}

只返回 JSON 对象，字段固定如下:
{{
  "page_summary": "一句话说明站点/接口类型",
  "js_urls": ["完整URL"],
  "sourcemap_urls": ["完整URL"],
  "config_urls": ["完整URL"],
  "api_endpoints": ["METHOD https://host/path 或 https://host/path"],
  "interesting_paths": ["/path"],
  "notes": "简短备注"
}}

硬性要求:
1. 只输出 JSON，不要解释，不要 markdown
2. 不要编造不存在的 URL；可把相对路径补成绝对 URL
3. 优先同站/业务相关资源
4. js_urls 不超过 120 个
5. 若是 API 目标，可重点填 api_endpoints/config_urls，js_urls 可为空数组
"""
    try:
        print("[llm_source] LLM request start", flush=True)
        data = call_llm_json(
            JSON_SYSTEM_PROMPT,
            prompt,
            temperature=0.0,
            max_tokens=1200,
            retries=0,
        )
        print("[llm_source] LLM request done", flush=True)
        if isinstance(data, dict):
            # 规范化字段
            for key in ("js_urls", "sourcemap_urls", "config_urls", "api_endpoints", "interesting_paths"):
                val = data.get(key)
                if val is None:
                    data[key] = []
                elif isinstance(val, str):
                    data[key] = [val]
                elif not isinstance(val, list):
                    data[key] = []
            return data
        return {"error": f"unexpected json type {type(data)}", "js_urls": [], "api_endpoints": []}
    except Exception as e:
        print(f"[llm_source] LLM request exception: {e}", flush=True)
        return {"error": str(e), "js_urls": [], "api_endpoints": []}


async def llm_source_collect(
    targets: list[str],
    work_dir: str,
    cookies: dict[str, str] | None = None,
    options: dict | None = None,
) -> list[dict]:
    cookies = cookies or {}
    options = options or {}
    results: list[dict] = []
    max_downloads = int(options.get("max_downloads", 120))
    per_request_timeout = float(options.get("download_timeout", 12))

    headers_base = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    timeout = httpx.Timeout(per_request_timeout, connect=8.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        for target in targets:
            print(f"[llm_source] target {target}", flush=True)
            host = urlparse(target).netloc or "target"
            target_dir = os.path.join(work_dir, "llm_source", host)
            os.makedirs(target_dir, exist_ok=True)

            hdrs = dict(headers_base)
            if cookies.get(target):
                hdrs["Cookie"] = cookies[target]

            # 1) fetch homepage + a few common entries
            entry_urls = [target]
            parsed = urlparse(target)
            origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else target
            if not target.rstrip("/").endswith((".js", ".json", ".map")):
                entry_urls += [
                    origin + "/",
                    origin + "/index.html",
                    origin + "/zh/index.html",
                    origin + "/cn/index.html",
                    origin + "/swagger-ui/index.html",
                    origin + "/swagger.json",
                    origin + "/openapi.json",
                    origin + "/v1/",
                    origin + "/api/",
                ]

            homepage_html = ""
            homepage_url = target
            homepage_ctype = ""
            for eu in list(dict.fromkeys(entry_urls)):
                try:
                    status, ctype, text = await _fetch_text(client, eu, hdrs, timeout=per_request_timeout)
                    print(f"[llm_source] fetch {eu} -> {status} {ctype[:40]}", flush=True)
                    # save raw entry
                    fname = _safe_name(eu, "entry.html")
                    if "html" not in (ctype or "") and not text.lstrip().startswith("<"):
                        fname = _safe_name(eu, "entry.txt")
                    path = _save_file(text, target_dir, fname)
                    if not _is_duplicate(path):
                        results.append({
                            "source_type": "llm_entry",
                            "url": eu,
                            "local_path": path,
                            "file_name": os.path.basename(path),
                            "file_size": os.path.getsize(path),
                            "line_count": _count_lines(path),
                        })
                    if not homepage_html and status < 500 and text:
                        homepage_html = text
                        homepage_url = str(eu)
                        homepage_ctype = ctype or ""
                        if "html" in (ctype or "") or text.lstrip().startswith("<"):
                            break
                except Exception as e:
                    print(f"[llm_source] entry fail {eu}: {e}", flush=True)

            if not homepage_html:
                print(f"[llm_source] no homepage for {target}", flush=True)
                continue

            is_api = _looks_like_api_target(target, homepage_html, homepage_ctype)
            if is_api:
                print(f"[llm_source] treat as API target: {target}", flush=True)

            regex_assets = _extract_regex_assets(homepage_url, homepage_html)

            # save inline scripts first
            for i, body in enumerate(regex_assets.get("inlines") or []):
                path = _save_file(body, target_dir, f"inline_{i}.js")
                if _is_duplicate(path):
                    continue
                results.append({
                    "source_type": "llm_inline",
                    "url": f"{homepage_url}#inline-{i}",
                    "local_path": path,
                    "file_name": os.path.basename(path),
                    "file_size": os.path.getsize(path),
                    "line_count": _count_lines(path),
                })

            # 2) LLM extract（可选增强；默认短超时，失败/跳过都不影响正则资产）
            llm_assets = {"js_urls": [], "api_endpoints": [], "config_urls": [], "sourcemap_urls": []}
            skip_llm = bool(options.get("skip_llm_extract")) or str(os.environ.get("XINRU_SKIP_LLM_SOURCE", "")).lower() in {"1","true","yes"}
            # 若正则已拿到足够脚本，默认跳过 LLM，避免网关长阻塞拖死收集
            regex_script_n = len(regex_assets.get("scripts") or [])
            if not skip_llm and regex_script_n >= int(options.get("llm_min_scripts_to_skip", 8)):
                # 仍调用，但更短；若 options force
                if not bool(options.get("force_llm_extract")):
                    skip_llm = True
                    print(f"[llm_source] skip LLM extract (regex scripts={regex_script_n} enough)", flush=True)
            if skip_llm and not bool(options.get("force_llm_extract")):
                print(f"[llm_source] LLM extract skipped; use regex assets scripts={regex_script_n}", flush=True)
            else:
                print(f"[llm_source] calling LLM for asset list: {target}", flush=True)
                try:
                    # 用 wait_for 限时；线程内同步 HTTP 可能残留，但不阻塞主流程
                    llm_assets = await asyncio.wait_for(
                        asyncio.to_thread(
                            _llm_extract_assets,
                            target,
                            homepage_html[:5000],
                            regex_assets,
                            is_api=is_api,
                        ),
                        timeout=float(options.get("llm_call_timeout", 25)),
                    )
                except asyncio.TimeoutError:
                    print(
                        f"[llm_source] LLM timeout for {target}, fallback regex only scripts={regex_script_n}",
                        flush=True,
                    )
                    llm_assets = {"error": "llm timeout", "js_urls": [], "api_endpoints": [], "config_urls": [], "sourcemap_urls": []}
                except Exception as e:
                    print(f"[llm_source] LLM error for {target}: {e}; fallback regex", flush=True)
                    llm_assets = {"error": str(e), "js_urls": [], "api_endpoints": [], "config_urls": [], "sourcemap_urls": []}
                if llm_assets.get("error"):
                    print(f"[llm_source] LLM error: {llm_assets['error']}", flush=True)
                else:
                    print(
                        f"[llm_source] LLM ok js={len(llm_assets.get('js_urls') or [])} "
                        f"api={len(llm_assets.get('api_endpoints') or [])} "
                        f"cfg={len(llm_assets.get('config_urls') or [])}",
                        flush=True,
                    )

            print(f"[llm_source] merge assets regex_scripts={len(regex_assets.get('scripts') or [])} llm_js={len(llm_assets.get('js_urls') or [])}", flush=True)
            # merge urls
            js_urls = []
            for u in (
                (regex_assets.get("scripts") or [])
                + (llm_assets.get("js_urls") or [])
                + (llm_assets.get("config_urls") or [])
                + (regex_assets.get("sourcemaps") or [])
                + (llm_assets.get("sourcemap_urls") or [])
            ):
                nu = _normalize_asset_url(homepage_url, u)
                if nu:
                    js_urls.append(nu)

            # API endpoints may be pure paths; store as text artifacts too
            api_lines = []
            for ep in (regex_assets.get("apis") or []) + (llm_assets.get("api_endpoints") or []):
                if not ep:
                    continue
                api_lines.append(str(ep).strip())
                # also try download if looks like URL
                maybe = str(ep).strip().split()[-1]
                nu = _normalize_asset_url(homepage_url, maybe)
                if nu and any(nu.lower().endswith(ext) for ext in (".js", ".json", ".map", ".txt", ".yml", ".yaml")):
                    js_urls.append(nu)

            if api_lines:
                api_path = _save_file(
                    "\n".join(dict.fromkeys(api_lines)),
                    target_dir,
                    "api_endpoints.txt",
                )
                if not _is_duplicate(api_path):
                    results.append({
                        "source_type": "llm_api_list",
                        "url": homepage_url,
                        "local_path": api_path,
                        "file_name": "api_endpoints.txt",
                        "file_size": os.path.getsize(api_path),
                        "line_count": _count_lines(api_path),
                    })

            # unique
            seen = set()
            merged = []
            for u in js_urls:
                if u not in seen:
                    seen.add(u)
                    merged.append(u)
            merged = merged[:max_downloads]
            print(f"[llm_source] download candidates={len(merged)}", flush=True)

            # also persist LLM plan
            plan_path = _save_file(
                json.dumps({
                    "target": target,
                    "homepage_url": homepage_url,
                    "is_api": is_api,
                    "regex_count": {k: len(v) if isinstance(v, list) else 0 for k, v in regex_assets.items()},
                    "llm": llm_assets,
                    "download_list": merged,
                }, ensure_ascii=False, indent=2),
                target_dir,
                "llm_asset_plan.json",
            )
            results.append({
                "source_type": "llm_plan",
                "url": homepage_url,
                "local_path": plan_path,
                "file_name": "llm_asset_plan.json",
                "file_size": os.path.getsize(plan_path),
                "line_count": _count_lines(plan_path),
            })

            # 3) download assets
            sem = asyncio.Semaphore(8)

            async def download_one(url: str):
                async with sem:
                    try:
                        status, ctype, text = await _fetch_text(
                            client, url, hdrs, timeout=per_request_timeout
                        )
                        if status >= 400 or not text:
                            return None
                        # only keep text-ish
                        if len(text) > 5_000_000:
                            text = text[:5_000_000]
                        fname = _safe_name(url, "asset.js")
                        path = _save_file(text, target_dir, fname)
                        if _is_duplicate(path):
                            return None
                        return {
                            "source_type": "llm_js",
                            "url": url,
                            "local_path": path,
                            "file_name": os.path.basename(path),
                            "file_size": os.path.getsize(path),
                            "line_count": _count_lines(path),
                        }
                    except Exception as e:
                        print(f"[llm_source] download fail {url}: {e}", flush=True)
                        return None

            downloaded = await asyncio.gather(*[download_one(u) for u in merged])
            ok = [x for x in downloaded if x]
            results.extend(ok)
            print(f"[llm_source] downloaded {len(ok)} assets for {target}", flush=True)

            # 4) shallow second-pass: extract more js urls from first N downloaded files
            # 限制数量与超时，避免外链/大文件拖死整个任务
            extra_urls = []
            try:
                for item in ok[:10]:
                    try:
                        with open(item["local_path"], "r", encoding="utf-8", errors="replace") as f:
                            content = f.read(80000)
                        for m in _REL_JS_RE.finditer(content):
                            u = _normalize_asset_url(item["url"], m.group(1))
                            if u and u not in seen:
                                extra_urls.append(u)
                                seen.add(u)
                        for m in _ABS_URL_RE.finditer(content):
                            raw = m.group(0).rstrip(").,;]}>'\"")
                            u = _normalize_asset_url(item["url"], raw)
                            if not u or u in seen:
                                continue
                            # 只收同站 js/json，避免 github/adobe 外链拖死
                            host = (urlparse(u).hostname or "").lower()
                            base_host = (urlparse(homepage_url).hostname or "").lower()
                            if host and base_host and not (host == base_host or host.endswith("." + base_host) or base_host.endswith("." + host)):
                                continue
                            if u.endswith(".js") or ".js?" in u or u.endswith(".json") or u.endswith(".map"):
                                extra_urls.append(u)
                                seen.add(u)
                    except Exception:
                        pass
                extra_urls = extra_urls[:12]
                if extra_urls:
                    print(f"[llm_source] second-pass extras={len(extra_urls)}", flush=True)
                    try:
                        more = await asyncio.wait_for(
                            asyncio.gather(*[download_one(u) for u in extra_urls], return_exceptions=False),
                            timeout=float(options.get("second_pass_timeout", 45)),
                        )
                        more_ok = [x for x in more if x]
                        results.extend(more_ok)
                        print(f"[llm_source] second-pass downloaded={len(more_ok)}", flush=True)
                    except asyncio.TimeoutError:
                        print("[llm_source] second-pass timeout, keep first-pass assets", flush=True)
                    except Exception as e:
                        print(f"[llm_source] second-pass error: {e}", flush=True)
            except Exception as e:
                print(f"[llm_source] second-pass outer error: {e}", flush=True)

    print(f"[llm_source] total files={len(results)}", flush=True)
    return results
