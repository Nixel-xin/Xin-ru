"""Yakit 兼容验证引擎 — HTTP 发包 + 原始请求包格式证据

不依赖 Yakit MCP（可独立运行），但产出格式与 Yakit HTTP Fuzzer 兼容。
证据格式是完整的原始 HTTP 请求包文本（可直接粘贴到 Yakit 重放）。

7步验证策略 (来自 xinru SKILL.md 第四步):
1. 无认证请求
2. 空参数请求
3. 假参数请求
4. 错误签名 / 无签名 / 真签名
5. 越权请求
6. 写操作请求
7. 注入测试

增强:
- WAF 授权限速/变形
- 签名三态
- 非状态码语义判定（静态资源/登录页/JSON 业务差异）
- 凭证失效探测回调
"""

from __future__ import annotations

import json
import re
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from auditor.waf_policy import WafPolicy, build_policy, apply_to_request, pace


AuthFailureHook = Callable[..., Awaitable[dict[str, Any]] | dict[str, Any]]


def build_raw_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
    http_version: str = "HTTP/1.1",
) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    lines = [f"{method} {path} {http_version}"]
    hdrs = dict(headers or {})
    if "Host" not in hdrs and "host" not in [k.lower() for k in hdrs]:
        hdrs["Host"] = parsed.netloc
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        if isinstance(body, bytes):
            lines.append(body.decode("utf-8", errors="replace"))
        else:
            lines.append(body)
    return "\n".join(lines)


def _format_response(response) -> str:
    lines = [f"HTTP/1.1 {response.status_code} {response.reason_phrase or ''}"]
    for k, v in response.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    try:
        text = response.text or ""
        lines.append(text[:2000])
        if len(text) > 2000:
            lines.append(f"\n... (截断，共 {len(text)} 字节)")
    except Exception:
        lines.append("(无法读取响应体)")
    return "\n".join(lines)


def _mutate_params(body: str | None, params: dict | None) -> str:
    if not body or not params:
        return body or "{}"
    mutated = body
    for k, v in (params or {}).items():
        if isinstance(v, str):
            if v.isdigit():
                mutated = mutated.replace(v, "99999")
            elif len(v) > 5:
                mutated = mutated.replace(v, "AAAA" + v[4:])
            else:
                mutated = mutated.replace(v, "test_fake")
    return mutated


_STATIC_EXT_RE = re.compile(r"\.(?:js|css|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot)(?:\?|$)", re.I)
_HTML_RE = re.compile(r"(?is)<!doctype html|<html[\s>]")
_LOGIN_RE = re.compile(r"(?i)login|signin|请先登录|未登录|unauthorized|not\s*authenticated")
_JSON_ERR_RE = re.compile(r'(?i)"(?:success)"\s*:\s*false|"(?:errCode|errorCode)"\s*:\s*(?:[1-9]\d*|401|403|10001|10002|-1)|"(?:code|status)"\s*:\s*(?:401|403|10001|10002|-1)(?!\d)')
_JSON_OK_RE = re.compile(r'(?i)"(?:success)"\s*:\s*true|"(?:code|status|errCode|errorCode)"\s*:\s*0\b')


def classify_response(status: int, body: str = "", url: str = "", content_type: str = "") -> dict[str, Any]:
    """非纯状态码判定。"""
    body = body or ""
    ctype = (content_type or "").lower()
    is_static = bool(_STATIC_EXT_RE.search(url or "")) or any(x in ctype for x in ("javascript", "css", "image/", "font/"))
    is_html = "text/html" in ctype or bool(_HTML_RE.search(body[:500]))
    is_json = "json" in ctype or body.lstrip().startswith(("{", "["))
    loginish = bool(_LOGIN_RE.search(body[:1500]))
    json_err = bool(_JSON_ERR_RE.search(body[:1500])) if is_json else False
    json_ok = bool(_JSON_OK_RE.search(body[:1500])) if is_json else False

    meaningful_200 = False
    if status == 200 and not is_static:
        if is_json and len(body) > 2 and (json_ok or not json_err):
            # 有明确 success/code=0，或非错误 JSON
            if json_err and not json_ok:
                meaningful_200 = False
            else:
                meaningful_200 = True
        elif is_html and not loginish and len(body) > 200:
            # HTML 200 且不像登录页 —— 仍谨慎
            meaningful_200 = False
        elif not is_html and not is_json and len(body) > 40:
            meaningful_200 = True

    return {
        "is_static": is_static,
        "is_html": is_html,
        "is_json": is_json,
        "loginish": loginish,
        "json_err": json_err,
        "meaningful_200": meaningful_200,
        "business_open": bool(meaningful_200 and not loginish and not json_err),
    }


def _finding_from_response(step: str, status: int, body: str, url: str, ctype: str = "") -> str:
    cls = classify_response(status, body, url, ctype)
    if cls["is_static"] and status == 200:
        return f"{step} → {status}（静态资源，不作为高危）"
    if cls["business_open"]:
        return f"{step} → {status}（⚠️ 业务数据可达）"
    if cls["loginish"] or cls["json_err"]:
        return f"{step} → {status}（鉴权/错误响应）"
    if status == 200:
        return f"{step} → {status}（需结合 body 语义，未直接确认）"
    return f"{step} → {status}"


def _with_query(url: str, params: dict[str, Any] | None) -> str:
    if not params:
        return url
    parsed = urlparse(url)
    q = dict(parse_qs(parsed.query, keep_blank_values=True))
    flat = {k: (v[-1] if isinstance(v, list) and v else v) for k, v in q.items()}
    for k, v in params.items():
        flat[k] = v
    return urlunparse(parsed._replace(query=urlencode(flat, doseq=False)))


async def yakit_verify_7steps(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    params: dict | None = None,
    cookies: str | None = None,
    token_header: str | None = None,
    token_value: str | None = None,
    sign_header: str | None = None,
    sign_value: str | None = None,
    session_a: dict | None = None,
    session_b: dict | None = None,
    *,
    task_id: int | None = None,
    waf_policy: WafPolicy | None = None,
    signature_profile: Any | None = None,
    on_auth_failure: AuthFailureHook | None = None,
    config: dict | None = None,
) -> list[dict]:
    evidence: list[dict] = []
    policy = waf_policy or build_policy(config)
    hdrs = apply_to_request(url=url, headers=headers, policy=policy, config=config)

    if token_header and token_value:
        hdrs[token_header] = token_value
    if cookies:
        hdrs["Cookie"] = cookies
    if sign_header and sign_value:
        hdrs[sign_header] = sign_value

    auth_failed_once = False

    async def _maybe_auth_fail(status: int, resp_body: str, role: str = "A"):
        nonlocal auth_failed_once
        if auth_failed_once or not on_auth_failure:
            return
        if status not in (401, 403):
            # body 语义
            if not re.search(r"(?i)unauthorized|token\s*expired|请先登录|登录失效", resp_body or ""):
                return
        auth_failed_once = True
        try:
            res = on_auth_failure(url=url, role=role, status=status, body=resp_body)
            if hasattr(res, "__await__"):
                await res
        except Exception:
            pass

    async def _send(client: httpx.AsyncClient, m: str, u: str, h: dict[str, str], b: str | None):
        await pace(u, policy)
        return await client.request(m, u, headers=h, content=b)

    async with httpx.AsyncClient(timeout=15, follow_redirects=False, verify=False) as client:
        # ---- 1 无认证 ----
        no_auth_headers = {
            k: v for k, v in hdrs.items()
            if k.lower() not in ("authorization", "cookie", "x-sign", "sign", "token", "x-token", "x-signature")
        }
        no_auth_headers = apply_to_request(url=url, headers=no_auth_headers, policy=policy)
        req1 = build_raw_request(method, url, no_auth_headers, body)
        try:
            r1 = await _send(client, method, url, no_auth_headers, body)
            resp1 = _format_response(r1)
            evidence.append({
                "step": "1-无认证",
                "request": req1,
                "response": resp1,
                "finding": _finding_from_response("无认证", r1.status_code, r1.text or "", url, r1.headers.get("content-type", "")),
                "status_code": r1.status_code,
                "class": classify_response(r1.status_code, r1.text or "", url, r1.headers.get("content-type", "")),
            })
        except Exception as e:
            evidence.append({"step": "1-无认证", "request": req1, "response": f"请求失败: {e}", "finding": "请求失败"})

        # ---- 2 空参数 ----
        req2 = build_raw_request(method, url, hdrs, "")
        try:
            r2 = await _send(client, method, url, hdrs, "")
            evidence.append({
                "step": "2-空参数",
                "request": req2,
                "response": _format_response(r2),
                "finding": _finding_from_response("空参数", r2.status_code, r2.text or "", url, r2.headers.get("content-type", "")),
                "status_code": r2.status_code,
                "class": classify_response(r2.status_code, r2.text or "", url, r2.headers.get("content-type", "")),
            })
            await _maybe_auth_fail(r2.status_code, r2.text or "")
        except Exception as e:
            evidence.append({"step": "2-空参数", "request": req2, "response": f"请求失败: {e}", "finding": "请求失败"})

        # ---- 3 假参数 ----
        fake_body = _mutate_params(body, params)
        req3 = build_raw_request(method, url, hdrs, fake_body)
        try:
            r3 = await _send(client, method, url, hdrs, fake_body)
            evidence.append({
                "step": "3-假参数",
                "request": req3,
                "response": _format_response(r3),
                "finding": _finding_from_response("假参数", r3.status_code, r3.text or "", url, r3.headers.get("content-type", "")),
                "status_code": r3.status_code,
                "class": classify_response(r3.status_code, r3.text or "", url, r3.headers.get("content-type", "")),
            })
        except Exception as e:
            evidence.append({"step": "3-假参数", "request": req3, "response": f"请求失败: {e}", "finding": "请求失败"})

        # ---- 4 签名三态 ----
        from auditor.signature import apply_signature

        if signature_profile is not None:
            for mode, label in (("none", "4a-无签名"), ("fake", "4b-假签名"), ("true", "4c-真签名")):
                signed = apply_signature(
                    signature_profile,
                    method=method,
                    url=url,
                    headers=hdrs,
                    body=body,
                    params=params if isinstance(params, dict) else None,
                    mode=mode,
                )
                s_headers = apply_to_request(url=url, headers=signed["headers"], policy=policy)
                s_url = _with_query(url, signed.get("params")) if method.upper() == "GET" else url
                s_body = signed.get("body")
                req = build_raw_request(method, s_url, s_headers, s_body)
                try:
                    rr = await _send(client, method, s_url, s_headers, s_body)
                    evidence.append({
                        "step": label,
                        "request": req,
                        "response": _format_response(rr),
                        "finding": _finding_from_response(label, rr.status_code, rr.text or "", s_url, rr.headers.get("content-type", "")),
                        "status_code": rr.status_code,
                        "class": classify_response(rr.status_code, rr.text or "", s_url, rr.headers.get("content-type", "")),
                        "sign_mode": mode,
                    })
                except Exception as e:
                    evidence.append({"step": label, "request": req, "response": f"请求失败: {e}", "finding": "请求失败"})
        elif sign_header:
            wrong = dict(hdrs)
            wrong[sign_header] = "wrong_sign_for_test"
            req4 = build_raw_request(method, url, wrong, body)
            try:
                r4 = await _send(client, method, url, wrong, body)
                evidence.append({
                    "step": "4-错误签名",
                    "request": req4,
                    "response": _format_response(r4),
                    "finding": _finding_from_response("错误签名", r4.status_code, r4.text or "", url, r4.headers.get("content-type", "")),
                    "status_code": r4.status_code,
                })
            except Exception as e:
                evidence.append({"step": "4-错误签名", "request": req4, "response": f"请求失败: {e}", "finding": "请求失败"})
        else:
            evidence.append({
                "step": "4-签名",
                "request": "（无签名 profile/header，跳过）",
                "response": "",
                "finding": "",
            })

        # ---- 5 越权 ----
        async def _request_with_session(sess: dict | None, req_url: str, req_body: str | None, tag: str):
            s_headers = dict(hdrs)
            for k in list(s_headers.keys()):
                if k.lower() in ("authorization", "cookie", "token", "x-token", "access-token"):
                    s_headers.pop(k, None)
            if sess:
                if sess.get("cookies"):
                    s_headers["Cookie"] = sess["cookies"]
                th = sess.get("token_header") or "Authorization"
                tv = sess.get("token") or ""
                if tv:
                    if th.lower() == "authorization" and not str(tv).lower().startswith("bearer "):
                        s_headers[th] = f"Bearer {tv}"
                    else:
                        s_headers[th] = tv
                for k, v in (sess.get("headers") or {}).items():
                    s_headers[k] = v
            s_headers = apply_to_request(url=req_url, headers=s_headers, policy=policy)
            raw_req = build_raw_request(method, req_url, s_headers, req_body)
            try:
                resp = await _send(client, method, req_url, s_headers, req_body)
                cls = classify_response(resp.status_code, resp.text or "", req_url, resp.headers.get("content-type", ""))
                return {
                    "step": tag,
                    "request": raw_req,
                    "response": _format_response(resp),
                    "finding": _finding_from_response(tag, resp.status_code, resp.text or "", req_url, resp.headers.get("content-type", "")),
                    "status_code": resp.status_code,
                    "body": (resp.text or "")[:2000],
                    "class": cls,
                }
            except Exception as e:
                return {
                    "step": tag,
                    "request": raw_req,
                    "response": f"请求失败: {e}",
                    "finding": "请求失败",
                    "status_code": 0,
                    "body": "",
                    "class": {},
                }

        dual = bool(
            (session_a and (session_a.get("cookies") or session_a.get("token")))
            and (session_b and (session_b.get("cookies") or session_b.get("token")))
        )

        if dual:
            ev_a = await _request_with_session(session_a, url, body, "5a-账号A访问")
            evidence.append({k: ev_a[k] for k in ("step", "request", "response", "finding") if k in ev_a})
            ev_b = await _request_with_session(session_b, url, body, "5b-账号B交叉访问")
            finding_b = ev_b["finding"]
            if ev_a.get("status_code") == 200 and ev_b.get("status_code") == 200:
                body_a = ev_a.get("body") or ""
                body_b = ev_b.get("body") or ""
                cls_a = ev_a.get("class") or {}
                cls_b = ev_b.get("class") or {}
                similar = abs(len(body_a) - len(body_b)) < max(40, int(0.2 * max(len(body_a), 1)))
                both_business = bool(cls_a.get("business_open") and cls_b.get("business_open"))
                if both_business and similar and not (cls_a.get("is_static") or cls_b.get("is_static")):
                    finding_b += "（⚠️ 双账号交叉均返回业务数据，疑似水平越权）"
                elif both_business:
                    finding_b += "（⚠️ 双账号均可访问，需比对对象归属）"
            evidence.append({
                "step": ev_b["step"],
                "request": ev_b["request"],
                "response": ev_b["response"],
                "finding": finding_b,
                "status_code": ev_b.get("status_code"),
                "class": ev_b.get("class"),
            })
            await _maybe_auth_fail(int(ev_a.get("status_code") or 0), ev_a.get("body") or "", role="A")
            await _maybe_auth_fail(int(ev_b.get("status_code") or 0), ev_b.get("body") or "", role="B")
        elif params or (body and any(k in (body or "") for k in ("id", "user", "uid", "order"))):
            overreach_url = url
            overreach_body = body
            for old_val, new_val in (("1", "2"), ("01", "02")):
                if old_val in (url or ""):
                    overreach_url = overreach_url.replace(old_val, new_val)
            if body:
                overreach_body = _mutate_params(body, params or {"id": "1"})
            req5 = build_raw_request(method, overreach_url, hdrs, overreach_body)
            try:
                r5 = await _send(client, method, overreach_url, hdrs, overreach_body)
                evidence.append({
                    "step": "5-越权(单账号ID篡改)",
                    "request": req5,
                    "response": _format_response(r5),
                    "finding": _finding_from_response("越权", r5.status_code, r5.text or "", overreach_url, r5.headers.get("content-type", "")),
                    "status_code": r5.status_code,
                    "class": classify_response(r5.status_code, r5.text or "", overreach_url, r5.headers.get("content-type", "")),
                })
            except Exception as e:
                evidence.append({"step": "5-越权(单账号ID篡改)", "request": req5, "response": f"请求失败: {e}", "finding": "请求失败"})
        else:
            evidence.append({
                "step": "5-越权",
                "request": "（无双账号会话且无参数，跳过）",
                "response": "",
                "finding": "缺少双账号或对象参数，无法做可靠越权验证",
            })

        # ---- 6 写操作 ----
        if method.upper() == "GET":
            req6 = build_raw_request("POST", url, hdrs, body or "{}")
            try:
                r6 = await _send(client, "POST", url, hdrs, body or "{}")
                evidence.append({
                    "step": "6-写操作",
                    "request": req6,
                    "response": _format_response(r6),
                    "finding": _finding_from_response("GET→POST", r6.status_code, r6.text or "", url, r6.headers.get("content-type", "")),
                    "status_code": r6.status_code,
                })
            except Exception as e:
                evidence.append({"step": "6-写操作", "request": req6, "response": f"请求失败: {e}", "finding": "请求失败"})
        else:
            evidence.append({
                "step": "6-写操作",
                "request": f"（已是 {method} 方法，跳过 GET 转 POST 测试）",
                "response": "",
                "finding": "",
            })

        # ---- 7 注入 ----
        injection_payloads = [
            ("SQL注入", "' OR '1'='1"),
            ("XSS", "<script>alert(1)</script>"),
            ("路径穿越", "../../etc/passwd"),
        ]
        for inj_name, inj_payload in injection_payloads:
            if not params:
                continue
            first_key = list(params.keys())[0]
            inj_params = dict(params)
            inj_params[first_key] = inj_payload
            inj_body = json.dumps(inj_params) if body and body.strip().startswith("{") else None
            if not inj_body:
                inj_body = "&".join(f"{k}={v}" for k, v in inj_params.items())
            req7 = build_raw_request(method, url, hdrs, inj_body)
            try:
                r7 = await _send(client, method, url, hdrs, inj_body)
                body7 = r7.text or ""
                finding = _finding_from_response(inj_name, r7.status_code, body7, url, r7.headers.get("content-type", ""))
                # 反射/报错增强
                if inj_payload in body7:
                    finding += "（⚠️ payload 反射）"
                if re.search(r"(?i)sql syntax|odbc|jdbc|sqlite|mysql|oracle|stack trace|exception", body7):
                    finding += "（⚠️ 疑似报错回显）"
                if "root:x:" in body7 or "/etc/passwd" in body7:
                    finding += "（⚠️ 路径穿越读文件迹象）"
                evidence.append({
                    "step": f"7-注入({inj_name})",
                    "request": req7,
                    "response": _format_response(r7),
                    "finding": finding,
                    "status_code": r7.status_code,
                    "class": classify_response(r7.status_code, body7, url, r7.headers.get("content-type", "")),
                })
            except Exception as e:
                evidence.append({
                    "step": f"7-注入({inj_name})",
                    "request": req7,
                    "response": f"请求失败: {e}",
                    "finding": "请求失败",
                })

    return evidence
