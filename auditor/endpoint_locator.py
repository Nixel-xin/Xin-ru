"""API 接口精确定位 — 从调用链/源码上下文抽出可发包 endpoint"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse


_ABS_URL_RE = re.compile(r"""(?i)\bhttps?://[^\s'"`\\]+""")
_PATH_RE = re.compile(r"""(?x)['"`](/(?:api|v\d+|gateway|open|inner|admin|user|order|member)[^'"`]*)['"`]|['"`](/[A-Za-z0-9_./\-{}:?&=%]+)['"`]""")
_BASE_URL_RE = re.compile(
    r"""(?ix)
    (?:baseURL|baseUrl|BASE_URL|apiUrl|API_URL|host|domain|serverUrl)\s*[:=]\s*['"]([^'"]+)['"]
    """
)
_METHOD_RE = re.compile(r"""(?i)\bmethod\s*[:=]\s*['"](GET|POST|PUT|DELETE|PATCH)['"]|\.(get|post|put|delete|patch)\s*\(""")


def _clean_url(url: str) -> str:
    return (url or "").strip().rstrip(").,;]}>'\"")


def _origin_from_target(target: str) -> str:
    if not target:
        return ""
    if "://" not in target:
        target = "https://" + target
    p = urlparse(target)
    if not p.scheme or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"


def extract_base_urls(content: str) -> list[str]:
    found = []
    for m in _BASE_URL_RE.finditer(content or ""):
        val = _clean_url(m.group(1))
        if val:
            found.append(val)
    for m in _ABS_URL_RE.finditer(content or ""):
        found.append(_clean_url(m.group(0)))
    # 去重保序
    out = []
    seen = set()
    for item in found:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out[:20]


def normalize_endpoint(
    *,
    method: str = "GET",
    domain: str = "",
    path: str = "",
    full_url: str = "",
    params: dict | None = None,
    headers: dict | None = None,
    default_targets: list[str] | None = None,
) -> dict[str, Any]:
    """把各种残缺字段规范成可发包结构。"""
    method = (method or "GET").upper()
    params = params or {}
    headers = headers or {}
    full_url = _clean_url(full_url)
    domain = (domain or "").strip()
    path = (path or "").strip()

    if full_url and full_url.startswith("http"):
        p = urlparse(full_url)
        domain = domain if domain and domain != "待定位" else p.netloc
        path = path if path and path != "待定位" else (p.path or "/")
        if p.query and not params:
            from urllib.parse import parse_qs
            q = parse_qs(p.query)
            params = {k: (v[0] if isinstance(v, list) and v else v) for k, v in q.items()}
    else:
        # domain 可能是 origin
        if domain.startswith("http"):
            p = urlparse(domain)
            origin = f"{p.scheme}://{p.netloc}"
            if not path or path == "待定位":
                path = p.path or "/"
            domain = p.netloc
            full_url = origin.rstrip("/") + (path if path.startswith("/") else f"/{path}" if path and path != "待定位" else "")
        elif path.startswith("http"):
            full_url = path
            p = urlparse(path)
            domain = p.netloc
            path = p.path or "/"
        else:
            origin = ""
            if domain and domain != "待定位":
                origin = domain if domain.startswith("http") else f"https://{domain}"
            elif default_targets:
                origin = _origin_from_target(default_targets[0])
                domain = urlparse(origin).netloc if origin else domain
            if origin and path and path != "待定位":
                full_url = origin.rstrip("/") + (path if path.startswith("/") else "/" + path)

    if not full_url and default_targets and path and path != "待定位":
        full_url = urljoin(_origin_from_target(default_targets[0]) + "/", path.lstrip("/"))

    if (not domain or domain == "待定位") and full_url:
        domain = urlparse(full_url).netloc or domain

    if not path or path == "待定位":
        if full_url:
            path = urlparse(full_url).path or "/"
        else:
            path = "待定位"

    return {
        "method": method or "GET",
        "domain": domain or "待定位",
        "path": path or "待定位",
        "params": params,
        "headers": headers,
        "full_url": full_url or "",
        "locatable": bool(full_url and full_url.startswith("http")),
    }


def locate_from_trace(
    trace: dict[str, Any] | None,
    *,
    content: str = "",
    line_no: int = 0,
    default_targets: list[str] | None = None,
) -> dict[str, Any]:
    """从追溯结果 + 本地上下文精确定位 endpoint。"""
    trace = trace or {}
    api = trace.get("api_endpoint") if isinstance(trace.get("api_endpoint"), dict) else {}

    # 1) 追溯结果优先
    endpoint = normalize_endpoint(
        method=api.get("method", "GET"),
        domain=api.get("domain", ""),
        path=api.get("path", ""),
        full_url=api.get("full_url", ""),
        params=api.get("params") if isinstance(api.get("params"), dict) else {},
        headers=api.get("headers") if isinstance(api.get("headers"), dict) else {},
        default_targets=default_targets,
    )
    if endpoint["locatable"]:
        endpoint["source"] = "trace"
        return endpoint

    # 2) 当前文件上下文补全
    lines = (content or "").split("\n")
    lo = max(0, line_no - 30)
    hi = min(len(lines), line_no + 30)
    chunk = "\n".join(lines[lo:hi])
    bases = extract_base_urls(content) + extract_base_urls(chunk)

    method = endpoint.get("method") or "GET"
    m = _METHOD_RE.search(chunk)
    if m:
        method = (m.group(1) or m.group(2) or method).upper()

    path = endpoint.get("path") if endpoint.get("path") != "待定位" else ""
    full_url = endpoint.get("full_url") or ""

    abs_urls = [_clean_url(m.group(0)) for m in _ABS_URL_RE.finditer(chunk)]
    if abs_urls:
        abs_urls = sorted(
            abs_urls,
            key=lambda u: (
                0 if re.search(r"/api/|/v\d+/", u, re.I) else 1,
                -len(urlparse(u).path or ""),
            ),
        )
        full_url = abs_urls[0]
    if not path:
        for m in _PATH_RE.finditer(chunk):
            path = m.group(1) or m.group(2) or ""
            if path:
                break
    if (not path or path == "待定位") and not full_url:
        m = re.search(r'[\'"`](/(?:api|v\d+)[^\'"`]*)[\'"`]', chunk)
        if m:
            path = m.group(1)

    domain = endpoint.get("domain") if endpoint.get("domain") != "待定位" else ""
    if not domain:
        for b in bases:
            if b.startswith("http"):
                domain = urlparse(b).netloc
                if not full_url and path:
                    full_url = urljoin(b if b.endswith("/") else b + "/", path.lstrip("/"))
                break
            if b.startswith("/") and not path:
                path = b

    endpoint = normalize_endpoint(
        method=method,
        domain=domain,
        path=path,
        full_url=full_url,
        params=endpoint.get("params") or {},
        headers=endpoint.get("headers") or {},
        default_targets=default_targets,
    )
    endpoint["source"] = "context" if endpoint["locatable"] else "unresolved"
    endpoint["base_candidates"] = bases[:5]
    return endpoint


def endpoint_to_request_args(endpoint: dict[str, Any]) -> dict[str, Any]:
    """转换成 verifier 可直接使用的参数。"""
    method = (endpoint.get("method") or "GET").upper()
    url = endpoint.get("full_url") or ""
    headers = dict(endpoint.get("headers") or {})
    params = dict(endpoint.get("params") or {})
    body = None
    if method in {"POST", "PUT", "PATCH", "DELETE"} and params:
        import json
        body = json.dumps(params, ensure_ascii=False)
        headers.setdefault("Content-Type", "application/json")
    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "params": params if method == "GET" else None,
    }
