"""WAF 授权策略 — xinru 0.1

WAF_AUTHORIZED=true  → 可直接发包，正常节奏
WAF_AUTHORIZED=false → 限流 + 变形 header，降低触发
"""

from __future__ import annotations

import asyncio
import os
import random
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


@dataclass
class WafPolicy:
    authorized: bool = False
    min_interval_sec: float = 0.0
    jitter_sec: float = 0.0
    max_rps: float = 0.0
    mutate_headers: bool = False
    notes: str = ""


_LAST_SEND: dict[str, float] = {}


def resolve_waf_authorized(config: dict[str, Any] | None = None) -> bool | None:
    config = config or {}
    if config.get("waf_authorized") is not None:
        return bool(config.get("waf_authorized"))
    env = os.environ.get("WAF_AUTHORIZED")
    if env is None or env == "":
        return None
    return str(env).strip().lower() in {"1", "true", "yes", "y", "on"}


def build_policy(config: dict[str, Any] | None = None) -> WafPolicy:
    auth = resolve_waf_authorized(config)
    if auth is True:
        return WafPolicy(
            authorized=True,
            min_interval_sec=float(config.get("waf_min_interval") or 0.05),
            jitter_sec=0.05,
            max_rps=float(config.get("waf_max_rps") or 20),
            mutate_headers=False,
            notes="authorized: direct send",
        )
    # 未授权 / 不确定 → 隐蔽
    return WafPolicy(
        authorized=False,
        min_interval_sec=float(config.get("waf_min_interval") or 0.8),
        jitter_sec=float(config.get("waf_jitter") or 0.6),
        max_rps=float(config.get("waf_max_rps") or 1.2),
        mutate_headers=True,
        notes="unauthorized/unknown: throttle+mutate",
    )


def mutate_request_headers(headers: dict[str, str] | None, policy: WafPolicy) -> dict[str, str]:
    h = dict(headers or {})
    if not policy.mutate_headers:
        return h
    # 常见浏览器伪装 + 去掉过于“扫描器”的痕迹
    h.setdefault(
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    )
    h.setdefault("Accept", "application/json, text/plain, */*")
    h.setdefault("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
    # 随机化大小写不碰，只加噪声 header
    h.setdefault("X-Requested-With", "XMLHttpRequest")
    if random.random() < 0.4:
        h.setdefault("Cache-Control", "no-cache")
    # 去掉明显扫描器头
    for k in list(h.keys()):
        if k.lower() in {"x-scanner", "x-bug-bounty", "x-pentest"}:
            h.pop(k, None)
    return h


async def pace(url: str, policy: WafPolicy) -> None:
    """按 host 限速。"""
    try:
        host = (urlsplit(url).hostname or "default").lower()
    except Exception:
        host = "default"
    now = time.monotonic()
    last = _LAST_SEND.get(host, 0.0)
    wait = policy.min_interval_sec + random.random() * max(policy.jitter_sec, 0.0)
    if policy.max_rps > 0:
        wait = max(wait, 1.0 / policy.max_rps)
    delta = now - last
    if delta < wait:
        await asyncio.sleep(wait - delta)
    _LAST_SEND[host] = time.monotonic()


def apply_to_request(
    *,
    url: str,
    headers: dict[str, str] | None,
    policy: WafPolicy | None,
    config: dict[str, Any] | None = None,
) -> dict[str, str]:
    pol = policy or build_policy(config)
    return mutate_request_headers(headers, pol)
