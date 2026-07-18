"""Playwright 浏览器爬虫 — 拦截 JS bundle/chunk + 内联脚本（带硬超时，避免卡死）"""

from __future__ import annotations

import asyncio
import os
from urllib.parse import urljoin, urlparse

from .orchestrator import _save_file, _is_duplicate, _count_lines


async def spider_collect(
    targets: list[str],
    work_dir: str,
    cookies: dict[str, str],
) -> list[dict]:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("[spider] playwright 未安装，跳过", flush=True)
        return []

    results: list[dict] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
        )
        try:
            for target in targets:
                print(f"[spider] target {target}", flush=True)
                # API/纯接口域名不做浏览器爬，避免卡死
                low = (target or "").lower()
                if any(x in low for x in ("countly", "/api.", "v-api.", "api.")):
                    # 仍尝试直接拉首页 body 作为线索文本
                    try:
                        import httpx
                        async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
                            r = await client.get(target)
                            body = r.text[:200000]
                        if body:
                            host = urlparse(target).netloc or "api"
                            target_dir = os.path.join(work_dir, "spider", host)
                            filepath = _save_file(body, target_dir, "index_response.txt")
                            if not _is_duplicate(filepath):
                                results.append({
                                    "source_type": "js_bundle",
                                    "url": target,
                                    "local_path": filepath,
                                    "file_name": "index_response.txt",
                                    "file_size": len(body.encode()),
                                    "line_count": _count_lines(filepath),
                                })
                        print(f"[spider] api-target fast path {target}", flush=True)
                    except Exception as e:
                        print(f"[spider] api-target skip {target}: {e}", flush=True)
                    continue
                try:
                    part = await asyncio.wait_for(
                        _spider_one(browser, target, work_dir, cookies.get(target, "")),
                        timeout=30,
                    )
                    results.extend(part or [])
                    print(f"[spider] target done {target} +{len(part or [])}", flush=True)
                except asyncio.TimeoutError:
                    print(f"[spider] target timeout {target}", flush=True)
                except Exception as e:
                    print(f"[spider] target error {target}: {e}", flush=True)
        finally:
            try:
                await asyncio.wait_for(browser.close(), timeout=5)
            except Exception:
                pass

    print(f"[spider] 收集完成: {len(results)} 个 JS 文件", flush=True)
    return results


async def _spider_one(browser, target: str, work_dir: str, cookie_header: str) -> list[dict]:
    results: list[dict] = []
    context = await browser.new_context(
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        viewport={"width": 1440, "height": 900},
        locale="zh-CN",
    )
    try:
        if cookie_header:
            domain = urlparse(target).netloc
            for cookie_str in cookie_header.split(";"):
                cookie_str = cookie_str.strip()
                if "=" in cookie_str:
                    name, _, value = cookie_str.partition("=")
                    await context.add_cookies([{
                        "name": name.strip(),
                        "value": value.strip(),
                        "domain": domain,
                        "path": "/",
                    }])

        page = await context.new_page()
        js_responses: list[dict] = []

        async def handle_response(response):
            content_type = response.headers.get("content-type", "")
            url = response.url
            if "javascript" in content_type or url.endswith(".js") or url.endswith(".mjs"):
                try:
                    body = await response.body()
                    js_responses.append({"url": url, "body": body, "size": len(body)})
                except Exception:
                    pass

        page.on("response", handle_response)

        await page.goto(target, wait_until="domcontentloaded", timeout=15000)
        await asyncio.sleep(2)
        try:
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(1)
        except Exception:
            pass

        inline_scripts = []
        try:
            inline_scripts = await page.evaluate(
                """() => Array.from(document.querySelectorAll('script:not([src])'))
                    .map(s => s.textContent)
                    .filter(t => t && t.length > 10)"""
            ) or []
        except Exception:
            pass

        target_dir = os.path.join(work_dir, "spider", urlparse(target).netloc)
        file_index = 0
        for resp in js_responses:
            url = resp["url"]
            body = resp["body"]
            filename = os.path.basename(urlparse(url).path) or f"bundle_{file_index}.js"
            if not filename.endswith(".js"):
                filename += ".js"
            filepath = _save_file(body, target_dir, filename)
            if _is_duplicate(filepath):
                continue
            results.append({
                "source_type": "js_bundle",
                "url": url,
                "local_path": filepath,
                "file_name": filename,
                "file_size": resp["size"],
                "line_count": _count_lines(filepath),
            })
            file_index += 1

        for i, script in enumerate(inline_scripts or []):
            filename = f"inline_{i}.js"
            filepath = _save_file(script, target_dir, filename)
            if _is_duplicate(filepath):
                continue
            results.append({
                "source_type": "js_bundle",
                "url": f"{target}#inline-{i}",
                "local_path": filepath,
                "file_name": filename,
                "file_size": len(script.encode()),
                "line_count": _count_lines(filepath),
            })
    finally:
        try:
            await asyncio.wait_for(context.close(), timeout=3)
        except Exception:
            pass
    return results
