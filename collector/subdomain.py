"""子域名枚举引擎

使用 crt.sh 证书透明度日志 + 内置字典爆破 枚举子域名。

后续可扩展: DNS 解析、SecurityTrails API、AlienVault OTX 等。
"""

import os
import re
import json
import httpx
from urllib.parse import urlparse

from .orchestrator import _save_file, _is_duplicate, _count_lines

# crt.sh API
CRTSH_URL = "https://crt.sh/?q={domain}&output=json"

# 常见子域名字典
COMMON_SUBDOMAINS = [
    "api", "admin", "app", "m", "mobile", "web", "www",
    "dev", "test", "staging", "uat", "qa",
    "cdn", "static", "assets", "img", "images",
    "mail", "smtp", "imap", "pop3",
    "ftp", "sftp", "ssh",
    "vpn", "remote", "portal",
    "jenkins", "gitlab", "github", "bitbucket",
    "jira", "confluence", "wiki",
    "kibana", "grafana", "prometheus", "alertmanager",
    "api-dev", "api-test", "api-staging",
    "ws", "websocket", "socket",
    "oauth", "auth", "login", "sso", "idp",
    "pay", "payment", "order", "shop",
    "dashboard", "monitor", "status",
    "docs", "doc", "help", "support",
    "blog", "news", "forum",
    "ns1", "ns2", "dns1", "dns2",
    "v1", "v2", "api-v1", "api-v2",
    "preprod", "pre-prod", "stg", "pp",
    "int", "internal", "corp", "corporate",
    "data", "db", "redis", "es", "elastic",
]


async def subdomain_collect(
    targets: list[str],
    work_dir: str,
) -> list[dict]:
    """枚举子域名并把结果保存为 JSON 文件"""
    results: list[dict] = []

    for target in targets:
        domain = _extract_domain(target)
        if not domain:
            continue

        subdomains: set[str] = set()

        # ---- 方法 1: crt.sh 证书透明度 ----
        crt_subdomains = await _crt_sh_lookup(domain)
        subdomains.update(crt_subdomains)
        print(f"[subdomain] crt.sh: {len(crt_subdomains)} 个")

        # ---- 方法 2: 字典爆破 (只做常见子域名，不做大字典) ----
        dict_subdomains = await _dictionary_lookup(domain, COMMON_SUBDOMAINS)
        subdomains.update(dict_subdomains)
        print(f"[subdomain] 字典: {len(dict_subdomains)} 个")

        # 保存结果
        if subdomains:
            target_dir = os.path.join(work_dir, "subdomains")
            result_path = _save_file(
                json.dumps(sorted(list(subdomains)), indent=2, ensure_ascii=False),
                target_dir,
                f"{domain}_subdomains.json",
            )
            if not _is_duplicate(result_path):
                results.append({
                    "source_type": "subdomain_list",
                    "url": f"subdomain://{domain}",
                    "local_path": result_path,
                    "file_name": f"{domain}_subdomains.json",
                    "file_size": os.path.getsize(result_path),
                    "line_count": len(subdomains),
                })

    print(f"[subdomain] 收集完成: {len(results)} 个子域名列表文件")
    return results


async def _crt_sh_lookup(domain: str) -> list[str]:
    """通过 crt.sh 查询证书透明度日志"""
    subdomains: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(CRTSH_URL.format(domain=domain))
            if resp.status_code != 200:
                return []

            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "") or entry.get("common_name", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line and line != domain:
                        # 过滤通配符
                        line = line.replace("*.", "")
                        if "." in line:
                            subdomains.add(line)
    except Exception as e:
        print(f"[subdomain] crt.sh 查询 {domain} 失败: {e}")

    return list(subdomains)


async def _dictionary_lookup(domain: str, wordlist: list[str]) -> list[str]:
    """字典爆破子域名（HTTP 请求验证，并发）"""
    import asyncio
    found: list[str] = []
    async with httpx.AsyncClient(timeout=10) as client:
        async def _check_one(sub: str):
            hostname = f"{sub}.{domain}"
            for scheme in ["https", "http"]:
                try:
                    resp = await client.get(f"{scheme}://{hostname}")
                    if resp.status_code < 500:  # 404/403/200 都说明子域名存在
                        return hostname
                except Exception:
                    continue
            return None

        sem = asyncio.Semaphore(20)  # 最多 20 个并发
        async def _bounded(sub: str):
            async with sem:
                return await _check_one(sub)

        tasks = [_bounded(sub) for sub in wordlist]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                found.append(r)

    return found


def _extract_domain(target: str) -> str:
    """从 URL 提取裸域名，如 https://app.example.com/path → example.com"""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    hostname = parsed.netloc or parsed.path
    # 去掉端口
    hostname = hostname.split(":")[0]
    # 提取主域名 (example.com) — 简单实现：取最后两段
    parts = hostname.split(".")
    if len(parts) >= 2:
        # 处理二级 TLD (co.uk, com.cn 等)
        if parts[-2] in ("co", "com", "org", "net", "gov", "ac"):
            return ".".join(parts[-3:]) if len(parts) >= 3 else hostname
        return ".".join(parts[-2:])
    return hostname
