"""调用链追溯引擎 — 本地 grep 上下游 + LLM 拼合 5 问结果"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterable


_IDENT_RE = re.compile(r"\b([A-Za-z_$][\w$]{2,})\b")
_FUNC_DEF_RE = re.compile(
    r"""(?x)
    (?:function\s+([A-Za-z_$][\w$]*)\s*\()|
    (?:(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>))|
    (?:([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?function\b)|
    (?:(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*))
    """
)
_REQUEST_RE = re.compile(
    r"""(?ix)
    (?:wx\.request|uni\.request|axios(?:\.[a-z]+)?|fetch|request|http\.(?:get|post|put|delete|patch)|
       \.(?:get|post|put|delete|patch)\s*\()
    """
)
_URL_RE = re.compile(r"""(?ix)https?://[^\s'"`\\]+|['"`](/[A-Za-z0-9_./?&=%\-{}:]+)['"`]""")
_METHOD_RE = re.compile(r"""(?i)\bmethod\s*[:=]\s*['"](GET|POST|PUT|DELETE|PATCH)['"]|\.(get|post|put|delete|patch)\s*\(""")
_re_path = re.compile(r"""[\'"`](/(?:api|v\d+|gateway|open|inner|admin|user|order|member)?[^\'"`]*)[\'"`]""")
_STOP_WORDS = {
    "const", "let", "var", "function", "return", "import", "export", "from", "default",
    "true", "false", "null", "undefined", "this", "window", "document", "console",
    "async", "await", "new", "class", "extends", "typeof", "string", "number", "object",
    "length", "push", "data", "params", "headers", "config", "options", "value", "result",
    "response", "error", "then", "catch", "json", "parse", "stringify",
}


def extract_keywords(line_text: str, context: str = "") -> dict[str, list[str]]:
    """从可疑行提取函数/变量关键词，供跨文件搜索。"""
    text = f"{line_text}\n{context}"
    idents = []
    for m in _IDENT_RE.finditer(text):
        name = m.group(1)
        if name.lower() in _STOP_WORDS:
            continue
        if len(name) < 3:
            continue
        idents.append(name)

    # 去重保序
    seen = set()
    ordered = []
    for name in idents:
        if name in seen:
            continue
        seen.add(name)
        ordered.append(name)

    funcs = [n for n in ordered if re.search(rf"\b{re.escape(n)}\s*\(", text)]
    vars_ = [n for n in ordered if n not in funcs]
    return {
        "functions": funcs[:12],
        "variables": vars_[:12],
        "all": ordered[:20],
    }


def _iter_source_files(file_paths: Iterable[str]) -> list[str]:
    out = []
    for p in file_paths:
        if not p or not os.path.isfile(p):
            continue
        lower = p.lower()
        if any(x in lower for x in ("node_modules", ".min.js", "vendor/")):
            continue
        if not any(lower.endswith(ext) for ext in (".js", ".ts", ".tsx", ".vue", ".jsx", ".mjs", ".cjs", ".json", ".html")):
            continue
        out.append(p)
    return out


def grep_symbol(
    symbol: str,
    file_paths: list[str],
    *,
    max_hits: int = 20,
    exclude_file: str | None = None,
) -> list[dict[str, Any]]:
    """朴素跨文件 grep。"""
    if not symbol or len(symbol) < 3:
        return []
    pattern = re.compile(rf"\b{re.escape(symbol)}\b")
    hits: list[dict[str, Any]] = []
    for path in _iter_source_files(file_paths):
        if exclude_file and os.path.abspath(path) == os.path.abspath(exclude_file):
            # 本文件也要搜，但后面会标注
            pass
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f):
                    if pattern.search(line):
                        hits.append(
                            {
                                "file": path,
                                "line": i,
                                "text": line.strip()[:220],
                                "symbol": symbol,
                            }
                        )
                        if len(hits) >= max_hits:
                            return hits
        except Exception:
            continue
    return hits


def find_enclosing_function(content: str, line_no: int) -> dict[str, Any]:
    lines = content.split("\n")
    name = ""
    start = max(0, line_no - 80)
    for i in range(line_no, start - 1, -1):
        if i < 0 or i >= len(lines):
            continue
        m = _FUNC_DEF_RE.search(lines[i])
        if m:
            name = next((g for g in m.groups() if g), "")
            return {"function": name or "<anonymous>", "line": i, "text": lines[i].strip()[:200]}
    return {"function": "<module>", "line": max(0, line_no), "text": ""}


def extract_local_request_clues(content: str, line_no: int, window: int = 25) -> dict[str, Any]:
    lines = content.split("\n")
    lo = max(0, line_no - window)
    hi = min(len(lines), line_no + window + 1)
    chunk = "\n".join(lines[lo:hi])

    urls = [m.group(0).strip("'\"`") for m in _URL_RE.finditer(chunk)]
    # 捕获字符串路径: "/v1/users/" "/api/pay"
    for m in _re_path.finditer(chunk):
        candidate = m.group(1)
        if candidate and candidate not in urls:
            urls.append(candidate)
    method = "GET"
    m = _METHOD_RE.search(chunk)
    if m:
        method = (m.group(1) or m.group(2) or "GET").upper()

    has_request = bool(_REQUEST_RE.search(chunk)) or bool(re.search(r"(?i)\bfetch\s*\(", chunk))
    headers = {}
    if re.search(r"(?i)authorization", chunk):
        headers["Authorization"] = "Bearer <token>"
    if re.search(r"(?i)\btoken\b\s*:", chunk):
        headers["token"] = "<token>"

    params = {}
    for key in ("userId", "orderId", "id", "page", "pageSize", "keyword", "amount", "price"):
        if re.search(rf"(?i)\b{key}\b", chunk):
            params[key] = f"<{key}>"

    return {
        "has_request": has_request,
        "method": method,
        "urls": urls[:8],
        "headers": headers,
        "params": params,
        "chunk": chunk[:2000],
    }


def build_search_hits(
    keywords: dict[str, list[str]],
    file_paths: list[str],
    current_file: str,
    max_per_symbol: int = 8,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    symbols = (keywords.get("functions") or []) + (keywords.get("variables") or [])
    seen = set()
    for symbol in symbols[:10]:
        for hit in grep_symbol(symbol, file_paths, max_hits=max_per_symbol):
            key = (hit["file"], hit["line"], hit["symbol"])
            if key in seen:
                continue
            seen.add(key)
            hit["is_current_file"] = os.path.abspath(hit["file"]) == os.path.abspath(current_file or "")
            hits.append(hit)
            if len(hits) >= 40:
                return hits
    return hits


def heuristic_trace(
    *,
    file_path: str,
    content: str,
    line_no: int,
    threat: dict[str, Any],
    search_hits: list[dict[str, Any]],
    default_domain: str = "",
) -> dict[str, Any]:
    """LLM 失败时的兜底追溯。"""
    enclosing = find_enclosing_function(content, line_no)
    clues = extract_local_request_clues(content, line_no)
    callers = []
    for hit in search_hits:
        if hit.get("symbol") and hit["symbol"] == enclosing.get("function"):
            callers.append(
                {
                    "file": hit["file"],
                    "function": hit["symbol"],
                    "line": hit["line"],
                }
            )
        if len(callers) >= 5:
            break
    if not callers:
        callers = [{"file": file_path, "function": enclosing.get("function", "<module>"), "line": enclosing.get("line", line_no)}]

    url = ""
    path = ""
    domain = default_domain
    if clues["urls"]:
        ranked = sorted(
            clues["urls"],
            key=lambda u: (
                0 if re.search(r"/v\d+/|/api/|/user|/order|/member|/pay", u, re.I) else 1,
                0 if u.startswith("/") else 1,
                0 if u.startswith("http") else 1,
                -len(u),
            ),
        )
        raw = ranked[0]
        if raw.startswith("http"):
            url = raw
            try:
                from urllib.parse import urlparse
                p = urlparse(raw)
                domain = p.netloc or domain
                path = p.path or "/"
            except Exception:
                path = raw
        else:
            path = raw
            for cand in ranked[1:]:
                if cand.startswith("http"):
                    from urllib.parse import urlparse
                    domain = urlparse(cand).netloc or domain
                    break

    if not path:
        # 从当前行再抠一次
        m = re.search(r"""['"`](/[^'"`]+)['"`]""", content.split("\n")[line_no] if line_no < len(content.split("\n")) else "")
        if m:
            path = m.group(1)

    api = {
        "method": clues.get("method") or "GET",
        "domain": domain or "待定位",
        "path": path or "待定位",
        "params": clues.get("params") or {},
        "headers": clues.get("headers") or {},
        "full_url": url or "",
    }
    if not api["full_url"] and domain and path and path != "待定位":
        origin = domain if str(domain).startswith("http") else f"https://{domain}"
        api["full_url"] = origin.rstrip("/") + (path if path.startswith("/") else "/" + path)

    return {
        "callers": callers,
        "param_source": threat.get("description", "未确定"),
        "data_flow": f"{file_path}:{line_no} → {enclosing.get('function')} → request/sink",
        "api_endpoint": api,
        "defenses": [],
        "attacker_controllable": True,
        "notes": "heuristic_trace fallback",
        "local_request": clues.get("has_request", False),
        "search_hit_count": len(search_hits),
    }


async def trace_call_chain(
    *,
    file_path: str,
    content: str,
    line_no: int,
    threat: dict[str, Any],
    file_paths: list[str],
    default_domain: str = "",
    call_llm_json=None,
    system_prompt: str = "",
    call_chain_prompt_template: str = "",
) -> dict[str, Any]:
    """完整追溯：关键词 → grep → LLM 5问 → 启发式兜底。"""
    import asyncio

    lines = content.split("\n")
    current_line = lines[line_no] if 0 <= line_no < len(lines) else ""
    ctx_lo = max(0, line_no - 6)
    ctx_hi = min(len(lines), line_no + 7)
    context = "\n".join(f"  {i}: {lines[i]}" for i in range(ctx_lo, ctx_hi))

    keywords = extract_keywords(current_line, context)
    search_hits = build_search_hits(keywords, file_paths, file_path)

    # 先给启发式结果，保证无人值守时不空
    fallback = heuristic_trace(
        file_path=file_path,
        content=content,
        line_no=line_no,
        threat=threat,
        search_hits=search_hits,
        default_domain=default_domain,
    )

    if not call_llm_json:
        return fallback

    try:
        from auditor.threat_patterns import CALL_CHAIN_PROMPT
        template = call_chain_prompt_template or CALL_CHAIN_PROMPT
        prompt = template.format(
            file_path=file_path,
            line_number=line_no,
            pattern_name=threat.get("pattern_name", ""),
            current_line=current_line,
            context=context,
            search_hits="\n".join(
                f"- {h['file']}:{h['line']} [{h['symbol']}] {h['text']}" for h in search_hits[:25]
            ) or "(no hits)",
        )
        result = await asyncio.wait_for(
            asyncio.to_thread(call_llm_json, system_prompt, prompt),
            timeout=90,
        )
        if not isinstance(result, dict):
            return fallback

        # 合并：LLM 结果优先，缺字段用 fallback 补齐
        api = result.get("api_endpoint") or {}
        if not isinstance(api, dict):
            api = {}
        fb_api = fallback.get("api_endpoint") or {}
        merged_api = {
            "method": api.get("method") or fb_api.get("method") or "GET",
            "domain": api.get("domain") or fb_api.get("domain") or "待定位",
            "path": api.get("path") or fb_api.get("path") or "待定位",
            "params": api.get("params") or fb_api.get("params") or {},
            "headers": api.get("headers") or fb_api.get("headers") or {},
            "full_url": api.get("full_url") or fb_api.get("full_url") or "",
        }
        result["api_endpoint"] = merged_api
        result.setdefault("callers", fallback.get("callers"))
        result.setdefault("param_source", fallback.get("param_source"))
        result.setdefault("data_flow", fallback.get("data_flow"))
        result.setdefault("defenses", fallback.get("defenses"))
        result["search_hit_count"] = len(search_hits)
        result["keywords"] = keywords
        return result
    except Exception as e:
        fallback["notes"] = f"llm_trace_failed: {e}"
        return fallback
