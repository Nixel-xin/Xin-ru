"""双账号会话管理 — 无人值守越权测试的前提

设计原则:
1. 执行期零人工干预：账号必须在启动前给齐，或允许自动注册时自建
2. 最少两套身份 A/B；只有一套时降级为“单账号 + 对象ID篡改”
3. 会话统一结构，供 verifier 交叉访问

会话结构:
{
  "role": "A",
  "label": "account_a",
  "username": "...",
  "cookies": "k=v; ...",
  "token": "Bearer xxx" | "xxx" | "",
  "token_header": "Authorization" | "token" | "",
  "headers": {...},
  "user_id": "可选，登录响应/cookie 中提取",
  "source": "pre_cookie|login|register|config"
}
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit


def _split_cred(raw: str) -> tuple[str, str]:
    raw = (raw or "").strip()
    if not raw:
        return "", ""
    if ":" not in raw:
        return raw, ""
    user, _, pwd = raw.partition(":")
    return user.strip(), pwd.strip()


def parse_account_configs(config: dict[str, Any] | None) -> list[dict[str, Any]]:
    """从 task.config 解析账号列表，兼容旧字段。

    支持:
    - accounts: [{username,password,cookies,token,role}]
    - credentials + credentials_b
    - cookies + cookies_b
    - credentials_a / cookie_a 等别名
    """
    config = config or {}
    accounts: list[dict[str, Any]] = []

    raw_accounts = config.get("accounts")
    if isinstance(raw_accounts, str):
        try:
            raw_accounts = json.loads(raw_accounts)
        except Exception:
            raw_accounts = None
    if isinstance(raw_accounts, list):
        for i, item in enumerate(raw_accounts):
            if not isinstance(item, dict):
                continue
            role = str(item.get("role") or ("A" if i == 0 else "B" if i == 1 else f"U{i+1}"))
            username = str(item.get("username") or item.get("user") or "")
            password = str(item.get("password") or item.get("pass") or "")
            if not username and item.get("credentials"):
                username, password = _split_cred(str(item.get("credentials")))
            accounts.append({
                "role": role,
                "label": str(item.get("label") or f"account_{role}"),
                "username": username,
                "password": password,
                "cookies": str(item.get("cookies") or item.get("cookie") or ""),
                "token": str(item.get("token") or ""),
                "token_header": str(item.get("token_header") or ""),
                "headers": item.get("headers") if isinstance(item.get("headers"), dict) else {},
                "user_id": str(item.get("user_id") or item.get("uid") or ""),
            })

    # 兼容扁平字段
    flat_specs = [
        (
            "A",
            config.get("credentials") or config.get("credentials_a") or config.get("account_a"),
            config.get("cookies") or config.get("cookies_a") or config.get("cookie_a"),
            config.get("token") or config.get("token_a"),
            config.get("user_id") or config.get("user_id_a") or "",
        ),
        (
            "B",
            config.get("credentials_b") or config.get("account_b"),
            config.get("cookies_b") or config.get("cookie_b"),
            config.get("token_b"),
            config.get("user_id_b") or "",
        ),
    ]
    existing_roles = {a["role"] for a in accounts}
    for role, cred, cookies, token, user_id in flat_specs:
        user_id = str(user_id or "")
        if role in existing_roles:
            # 补齐缺失 cookie/token
            for acc in accounts:
                if acc["role"] == role:
                    if cookies and not acc.get("cookies"):
                        acc["cookies"] = str(cookies)
                    if token and not acc.get("token"):
                        acc["token"] = str(token)
                    if user_id and not acc.get("user_id"):
                        acc["user_id"] = user_id
                    if cred and not acc.get("username"):
                        u, p = _split_cred(str(cred))
                        acc["username"], acc["password"] = u, p
            continue
        u, p = _split_cred(str(cred or ""))
        ck = str(cookies or "")
        tk = str(token or "")
        if not (u or ck or tk):
            continue
        accounts.append({
            "role": role,
            "label": f"account_{role}",
            "username": u,
            "password": p,
            "cookies": ck,
            "token": tk,
            "token_header": "",
            "headers": {},
            "user_id": user_id,
        })

    # 去空
    cleaned = []
    for acc in accounts:
        if acc.get("username") or acc.get("cookies") or acc.get("token"):
            cleaned.append(acc)
    return cleaned


def session_from_preconfig(acc: dict[str, Any]) -> dict[str, Any]:
    token = (acc.get("token") or "").strip()
    token_header = (acc.get("token_header") or "").strip()
    headers = dict(acc.get("headers") or {})
    if token and not token_header:
        token_header = "Authorization"
        if not token.lower().startswith("bearer "):
            # 保留原值，verifier 可直接用
            pass
        headers.setdefault(token_header, token if token.lower().startswith("bearer ") else f"Bearer {token}")
    elif token and token_header:
        headers.setdefault(token_header, token)

    return {
        "role": acc.get("role") or "A",
        "label": acc.get("label") or "account",
        "username": acc.get("username") or "",
        "cookies": acc.get("cookies") or "",
        "token": token,
        "token_header": token_header,
        "headers": headers,
        "user_id": acc.get("user_id") or "",
        "source": "preconfig",
        "success": bool(acc.get("cookies") or token),
        "reason": "preconfigured" if (acc.get("cookies") or token) else "need_login",
    }


def extract_user_id_hints(text: str) -> str:
    if not text:
        return ""
    patterns = [
        r'"(?:userId|user_id|uid|memberId|member_id|accountId)"\s*:\s*"?([A-Za-z0-9_\-]+)"?',
        r'(?:userId|uid)=([A-Za-z0-9_\-]+)',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if m:
            return m.group(1)
    return ""


def pick_cookie_for_url(sessions_by_target: dict[str, dict[str, dict]], url: str, role: str = "A") -> str:
    """从 target→role→session 中挑 cookie。"""
    try:
        host = (urlsplit(url).hostname or "").lower()
    except Exception:
        host = ""
    # exact / suffix match target host
    for target, role_map in (sessions_by_target or {}).items():
        try:
            th = (urlsplit(target if "://" in target else "https://" + target).hostname or "").lower()
        except Exception:
            th = ""
        if host and th and not (host == th or host.endswith("." + th) or th.endswith("." + host)):
            continue
        sess = (role_map or {}).get(role) or {}
        if sess.get("cookies"):
            return sess.get("cookies") or ""
    # fallback any
    for role_map in (sessions_by_target or {}).values():
        sess = (role_map or {}).get(role) or {}
        if sess.get("cookies"):
            return sess.get("cookies") or ""
    return ""


def pick_session(sessions_by_target: dict[str, dict[str, dict]], url: str = "", role: str = "A") -> dict[str, Any]:
    try:
        host = (urlsplit(url).hostname or "").lower() if url else ""
    except Exception:
        host = ""
    for target, role_map in (sessions_by_target or {}).items():
        try:
            th = (urlsplit(target if "://" in target else "https://" + target).hostname or "").lower()
        except Exception:
            th = ""
        if host and th and not (host == th or host.endswith("." + th) or th.endswith("." + host)):
            continue
        sess = (role_map or {}).get(role)
        if sess:
            return sess
    for role_map in (sessions_by_target or {}).values():
        if role in (role_map or {}):
            return role_map[role]
    return {}


def dual_ready(sessions_by_target: dict[str, dict[str, dict]] | None) -> bool:
    """是否至少在某个 target 上具备 A+B 两套有效会话。"""
    for role_map in (sessions_by_target or {}).values():
        a = role_map.get("A") or {}
        b = role_map.get("B") or {}
        a_ok = bool(a.get("cookies") or a.get("token"))
        b_ok = bool(b.get("cookies") or b.get("token"))
        if a_ok and b_ok:
            return True
    return False


def summarize_sessions(sessions_by_target: dict[str, dict[str, dict]] | None) -> str:
    parts = []
    for target, role_map in (sessions_by_target or {}).items():
        roles = []
        for role, sess in (role_map or {}).items():
            ok = "✅" if (sess.get("cookies") or sess.get("token")) else "❌"
            uid = sess.get("user_id") or "?"
            roles.append(f"{role}{ok}(uid={uid})")
        parts.append(f"{target}: " + ",".join(roles))
    return " | ".join(parts) if parts else "无会话"
