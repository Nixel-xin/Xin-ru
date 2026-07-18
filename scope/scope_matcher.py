"""BBASRC scope matcher — 线索/域名是否在测试范围内。"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from urllib.parse import urlsplit


@lru_cache(maxsize=1)
def load_scope(path: str | None = None) -> dict:
    path = path or os.path.join(os.path.dirname(__file__), "bbasrc_scope.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _host(url_or_host: str) -> str:
    value = (url_or_host or "").strip().lower()
    if not value:
        return ""
    if "://" not in value:
        # bare host or host/path
        value = value.split("/")[0]
        return value.split(":")[0]
    try:
        return (urlsplit(value).hostname or "").lower()
    except Exception:
        return ""


def is_out_of_scope(url_or_host: str, text: str = "", scope: dict | None = None) -> tuple[bool, str]:
    scope = scope or load_scope()
    host = _host(url_or_host)
    blob = f"{url_or_host} {text}".lower()

    for exact in scope.get("out_of_scope", {}).get("exact_urls", []):
        if exact.lower().rstrip("/") in (url_or_host or "").lower().rstrip("/"):
            return True, f"exact_url:{exact}"
    for suffix in scope.get("out_of_scope", {}).get("host_suffixes", []):
        s = suffix.lower().lstrip(".")
        if host == s or host.endswith("." + s):
            return True, f"host_suffix:{suffix}"
    for kw in scope.get("out_of_scope", {}).get("keyword_exclusions", []):
        if kw.lower() in blob:
            return True, f"keyword:{kw}"
    return False, ""


def is_in_scope(url_or_host: str, scope: dict | None = None) -> tuple[bool, str]:
    scope = scope or load_scope()
    host = _host(url_or_host)
    if not host:
        return False, "empty_host"

    excluded, reason = is_out_of_scope(url_or_host, scope=scope)
    if excluded:
        return False, f"out_of_scope:{reason}"

    for exact in scope.get("in_scope", {}).get("exact_hosts", []):
        if host == exact.lower():
            return True, f"exact_host:{exact}"

    for root in scope.get("in_scope", {}).get("wildcard_roots", []):
        root = root.lower().lstrip(".")
        if host == root or host.endswith("." + root):
            return True, f"wildcard:*.{root}"

    return False, "not_in_scope"


def filter_urls(urls: list[str], scope: dict | None = None) -> list[str]:
    out = []
    for u in urls or []:
        ok, _ = is_in_scope(u, scope=scope)
        if ok:
            out.append(u)
    return out
