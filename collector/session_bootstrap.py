"""无人值守会话引导 — Cookie + 账号双给，失效自动回落

策略（对 A/B 每个身份独立执行）:
1. 有 Cookie/Token → 先用轻量请求探活
2. 探活失败且有账号密码 → Playwright 自动登录补会话
3. 仍失败且 allow_register → 尝试自动注册后再登录
4. 登录成功后尽量提取 user_id / token
5. 全程不弹窗、不等待人工
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from collector.accounts import extract_user_id_hints, session_from_preconfig


_AUTH_FAIL_MARKERS = (
    "unauthorized",
    "unauth",
    "not login",
    "not logged",
    "please login",
    "login required",
    "token expired",
    "token invalid",
    "session expired",
    "重新登录",
    "请登录",
    "未登录",
    "登录失效",
    "登录过期",
    "没有权限",
    "无权限",
    "invalid token",
    "jwt expired",
)


def _origin(target: str) -> str:
    if not target:
        return ""
    if "://" not in target:
        target = "https://" + target
    p = urlsplit(target)
    if not p.scheme or not p.netloc:
        return target.rstrip("/")
    return f"{p.scheme}://{p.netloc}"


def _candidate_probe_urls(target: str) -> list[str]:
    origin = _origin(target)
    base = target if target.startswith("http") else f"https://{target}"
    paths = [
        "",
        "/",
        "/api/user/info",
        "/api/users/me",
        "/api/v1/user/info",
        "/api/v1/users/me",
        "/api/member/info",
        "/api/account/info",
        "/api/auth/user",
        "/api/auth/me",
        "/user/info",
        "/users/me",
        "/me",
        "/profile",
        "/api/profile",
    ]
    urls = []
    for path in paths:
        if not path:
            urls.append(base)
            continue
        urls.append(urljoin(origin + "/", path.lstrip("/")))
    # 去重保序
    out, seen = [], set()
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _looks_auth_failed(status: int, body: str) -> bool:
    if status in (401, 403):
        return True
    text = (body or "").lower()
    if any(m in text for m in _AUTH_FAIL_MARKERS):
        return True
    # 常见业务码
    if re.search(r'"(?:code|status|errCode|errorCode)"\s*:\s*(?:401|403|10001|10002|20001)', body or ""):
        return True
    return False


async def probe_session(
    target: str,
    *,
    cookies: str = "",
    token: str = "",
    token_header: str = "Authorization",
    headers: dict | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """探活会话，返回是否有效 + 可能的 user_id/token 线索。"""
    hdrs = dict(headers or {})
    if cookies:
        hdrs["Cookie"] = cookies
    if token:
        th = token_header or "Authorization"
        if th.lower() == "authorization" and not str(token).lower().startswith("bearer "):
            hdrs[th] = f"Bearer {token}"
        else:
            hdrs[th] = token

    evidence = []
    extracted_uid = ""
    extracted_token = ""
    any_ok = False

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        for url in _candidate_probe_urls(target)[:10]:
            try:
                resp = await client.get(url, headers=hdrs)
            except Exception as e:
                evidence.append({"url": url, "error": str(e)})
                continue
            body = ""
            try:
                body = resp.text[:3000]
            except Exception:
                body = ""
            failed = _looks_auth_failed(resp.status_code, body)
            evidence.append({
                "url": url,
                "status": resp.status_code,
                "failed": failed,
                "len": len(body),
            })
            if not failed and resp.status_code < 500:
                any_ok = True
                if not extracted_uid:
                    extracted_uid = extract_user_id_hints(body)
                if not extracted_token:
                    m = re.search(r'"(?:token|accessToken|access_token)"\s*:\s*"([^"]{8,})"', body)
                    if m:
                        extracted_token = m.group(1)
                # 有明确 me/info 成功就够了
                if extracted_uid or any(x in url for x in ("/me", "user", "member", "profile", "account")):
                    break

    return {
        "valid": any_ok,
        "user_id": extracted_uid,
        "token": extracted_token,
        "evidence": evidence,
    }


async def bootstrap_account_session(
    *,
    target: str,
    account: dict[str, Any],
    work_dir: str,
    allow_register: bool = False,
) -> dict[str, Any]:
    """对单个身份执行: 预置会话探活 → 登录回落 → 可选注册。"""
    from collector.auth import acquire_auth, try_register_and_login

    role = account.get("role") or "A"
    pre = session_from_preconfig(account)
    username = account.get("username") or ""
    password = account.get("password") or ""
    cookies = pre.get("cookies") or account.get("cookies") or ""
    token = pre.get("token") or account.get("token") or ""
    token_header = pre.get("token_header") or account.get("token_header") or "Authorization"
    headers = dict(pre.get("headers") or account.get("headers") or {})
    user_id = account.get("user_id") or pre.get("user_id") or ""

    # 1) 预置 cookie/token 探活
    if cookies or token:
        probe = await probe_session(
            target,
            cookies=cookies,
            token=token,
            token_header=token_header,
            headers=headers,
        )
        if probe.get("valid"):
            return {
                "role": role,
                "label": account.get("label") or f"account_{role}",
                "username": username,
                "cookies": cookies,
                "token": token or probe.get("token") or "",
                "token_header": token_header,
                "headers": headers,
                "user_id": user_id or probe.get("user_id") or "",
                "source": "preconfig_valid",
                "success": True,
                "reason": "预置 Cookie/Token 探活通过",
                "probe": probe.get("evidence", [])[:5],
            }
        # 失效，准备回落
        stale_reason = "预置 Cookie/Token 探活失败，尝试账号密码回落"
    else:
        stale_reason = "无预置 Cookie/Token"

    # 2) 账号密码登录回落
    if username and password:
        cred = f"{username}:{password}"
        try:
            auth_result = await acquire_auth(
                target=target,
                work_dir=os.path.join(work_dir, role),
                credentials=cred,
                on_captcha=None,
                on_need_credentials=None,
                on_need_cookie=None,
            )
        except Exception as e:
            auth_result = {
                "success": False,
                "cookies": None,
                "method": "failed",
                "reason": f"登录异常: {e}",
            }

        if auth_result.get("success") and auth_result.get("cookies"):
            new_cookies = auth_result.get("cookies") or ""
            probe = await probe_session(target, cookies=new_cookies, token=token, token_header=token_header, headers=headers)
            return {
                "role": role,
                "label": account.get("label") or f"account_{role}",
                "username": username,
                "cookies": new_cookies,
                "token": token or probe.get("token") or "",
                "token_header": token_header,
                "headers": headers,
                "user_id": user_id or probe.get("user_id") or extract_user_id_hints(new_cookies) or "",
                "source": auth_result.get("method") or "login",
                "success": True,
                "reason": f"{stale_reason} → 登录成功",
                "probe": probe.get("evidence", [])[:5],
            }

        login_fail_reason = auth_result.get("reason") or "登录失败"
    else:
        login_fail_reason = "无账号密码可回落"

    # 3) 自动注册（通常给 B 用）
    if allow_register:
        try:
            reg = await try_register_and_login(
                target=target,
                work_dir=os.path.join(work_dir, f"{role}_register"),
                preferred_username=username or None,
                preferred_password=password or None,
            )
        except Exception as e:
            reg = {"success": False, "reason": f"注册异常: {e}"}

        if reg.get("success") and reg.get("cookies"):
            new_cookies = reg.get("cookies") or ""
            probe = await probe_session(target, cookies=new_cookies)
            return {
                "role": role,
                "label": account.get("label") or f"account_{role}",
                "username": reg.get("username") or username,
                "cookies": new_cookies,
                "token": reg.get("token") or token or probe.get("token") or "",
                "token_header": token_header,
                "headers": headers,
                "user_id": reg.get("user_id") or probe.get("user_id") or "",
                "source": "register_login",
                "success": True,
                "reason": f"{stale_reason} → {login_fail_reason} → 自动注册并登录成功",
                "probe": probe.get("evidence", [])[:5],
            }
        reg_reason = reg.get("reason") or "自动注册失败"
    else:
        reg_reason = "未开启 allow_register"

    return {
        "role": role,
        "label": account.get("label") or f"account_{role}",
        "username": username,
        "cookies": cookies,
        "token": token,
        "token_header": token_header,
        "headers": headers,
        "user_id": user_id,
        "source": "failed",
        "success": False,
        "reason": f"{stale_reason}；{login_fail_reason}；{reg_reason}",
    }
