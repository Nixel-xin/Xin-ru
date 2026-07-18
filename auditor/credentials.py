"""xinru 凭证表 + 失效停机/重建

铁律 4：凭证缺失/失效则停，不绕过。
"""

from __future__ import annotations

import json
import os
import re
import threading
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


_LOCK = threading.RLock()
# task_id -> CredentialStore
_STORES: dict[int, "CredentialStore"] = {}


def _truthy_env_unattended() -> bool:
    import os
    return str(os.environ.get("EXAM_MODE") or os.environ.get("XINRU_UNATTENDED") or "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def work_dir_for_task(task_id: int) -> Path:
    data = Path(os.environ.get("DATA_DIR") or Path(__file__).resolve().parents[1] / ".." / "data").resolve()
    return data / "collected" / f"task_{task_id}" / ".xinru"


@dataclass
class CredentialRecord:
    domain: str
    role: str = "A"  # A/B/anon/admin...
    auth_type: str = "cookie"  # cookie|header|token|signature|mixed
    cookies: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    token: str = ""
    token_header: str = "Authorization"
    username: str = ""
    password: str = ""
    sign_alg: str = ""
    sign_key: str = ""
    sign_helper: str = ""
    source: str = "bootstrap"
    valid: bool = True
    last_status: int | None = None
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    notes: str = ""


class CredentialStore:
    def __init__(self, task_id: int):
        self.task_id = task_id
        self.path = work_dir_for_task(task_id) / "credentials.json"
        self.records: list[CredentialRecord] = []
        self.waf_authorized: bool | None = None
        self.paused: bool = False
        self.pause_reason: str = ""
        self._load()

    def _load(self):
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.waf_authorized = data.get("waf_authorized")
            self.paused = bool(data.get("paused"))
            self.pause_reason = data.get("pause_reason") or ""
            for item in data.get("records") or []:
                self.records.append(CredentialRecord(**{
                    k: item.get(k, getattr(CredentialRecord, k).default if hasattr(getattr(CredentialRecord, k, None), 'default') else ({} if k in ("headers",) else ""))
                    for k in CredentialRecord.__dataclass_fields__.keys()
                    if k in item or True
                }))
            # safer load
            self.records = []
            for item in data.get("records") or []:
                rec = CredentialRecord(
                    domain=item.get("domain") or "*",
                    role=item.get("role") or "A",
                    auth_type=item.get("auth_type") or "cookie",
                    cookies=item.get("cookies") or "",
                    headers=item.get("headers") or {},
                    token=item.get("token") or "",
                    token_header=item.get("token_header") or "Authorization",
                    username=item.get("username") or "",
                    password=item.get("password") or "",
                    sign_alg=item.get("sign_alg") or "",
                    sign_key=item.get("sign_key") or "",
                    sign_helper=item.get("sign_helper") or "",
                    source=item.get("source") or "bootstrap",
                    valid=bool(item.get("valid", True)),
                    last_status=item.get("last_status"),
                    updated_at=item.get("updated_at") or datetime.now().isoformat(),
                    notes=item.get("notes") or "",
                )
                self.records.append(rec)
        except Exception:
            self.records = []

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "task_id": self.task_id,
            "waf_authorized": self.waf_authorized,
            "paused": self.paused,
            "pause_reason": self.pause_reason,
            "updated_at": datetime.now().isoformat(),
            "records": [asdict(r) for r in self.records],
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def upsert(self, rec: CredentialRecord):
        with _LOCK:
            for i, old in enumerate(self.records):
                if old.domain == rec.domain and old.role == rec.role:
                    self.records[i] = rec
                    self.save()
                    return
            self.records.append(rec)
            self.save()

    def list_valid(self) -> list[CredentialRecord]:
        return [r for r in self.records if r.valid]

    def pick(self, url_or_domain: str, role: str = "A") -> CredentialRecord | None:
        host = url_or_domain
        try:
            if "://" in url_or_domain:
                host = (urlsplit(url_or_domain).hostname or url_or_domain).lower()
            else:
                host = url_or_domain.lower()
        except Exception:
            host = (url_or_domain or "").lower()
        cands = [r for r in self.records if r.valid and r.role == role]
        # exact / suffix match
        for r in cands:
            d = (r.domain or "").lower().lstrip(".")
            if d in {"*", "any", host}:
                return r
            if host.endswith("." + d) or d.endswith("." + host):
                return r
        # any valid same role
        return cands[0] if cands else None

    def mark_invalid(self, url_or_domain: str, role: str, status: int | None, reason: str):
        rec = self.pick(url_or_domain, role=role)
        if not rec:
            rec = CredentialRecord(domain=_host(url_or_domain), role=role, valid=False, last_status=status, notes=reason, source="runtime")
            self.upsert(rec)
            return rec
        rec.valid = False
        rec.last_status = status
        rec.notes = reason
        rec.updated_at = datetime.now().isoformat()
        self.upsert(rec)
        return rec

    def pause(self, reason: str):
        self.paused = True
        self.pause_reason = reason
        self.save()

    def resume(self):
        self.paused = False
        self.pause_reason = ""
        self.save()

    def to_cookie_map(self, targets: list[str] | None = None) -> dict[str, str]:
        out: dict[str, str] = {}
        for r in self.list_valid():
            if not r.cookies:
                continue
            # map onto targets if host matches
            if targets:
                for t in targets:
                    th = _host(t)
                    if r.domain in {"*", th} or th.endswith("." + r.domain) or r.domain.endswith("." + th):
                        # prefer A
                        if r.role == "A" or t not in out:
                            out[t] = r.cookies
            else:
                key = r.domain if r.domain != "*" else "default"
                if r.role == "A" or key not in out:
                    out[key] = r.cookies
        return out


def _host(url_or_domain: str) -> str:
    try:
        if "://" in (url_or_domain or ""):
            return (urlsplit(url_or_domain).hostname or url_or_domain).lower()
        return (url_or_domain or "").lower()
    except Exception:
        return (url_or_domain or "").lower()


def get_store(task_id: int) -> CredentialStore:
    with _LOCK:
        if task_id not in _STORES:
            _STORES[task_id] = CredentialStore(task_id)
        return _STORES[task_id]


def bootstrap_from_config(task_id: int, config: dict[str, Any], targets: list[str]) -> CredentialStore:
    store = get_store(task_id)
    store.waf_authorized = bool(config.get("waf_authorized")) if config.get("waf_authorized") is not None else None
    # A
    if config.get("cookies") or config.get("token") or config.get("credentials"):
        user = passwd = ""
        cred = (config.get("credentials") or "").strip()
        if ":" in cred:
            user, passwd = cred.split(":", 1)
        for t in targets or ["*"]:
            store.upsert(CredentialRecord(
                domain=_host(t) or "*",
                role="A",
                auth_type="mixed" if (config.get("cookies") and config.get("token")) else ("token" if config.get("token") else "cookie"),
                cookies=config.get("cookies") or "",
                token=config.get("token") or "",
                token_header="Authorization",
                username=user,
                password=passwd,
                source="task_config",
                valid=True,
            ))
    # B
    if config.get("cookies_b") or config.get("token_b") or config.get("credentials_b"):
        user = passwd = ""
        cred = (config.get("credentials_b") or "").strip()
        if ":" in cred:
            user, passwd = cred.split(":", 1)
        for t in targets or ["*"]:
            store.upsert(CredentialRecord(
                domain=_host(t) or "*",
                role="B",
                auth_type="mixed" if (config.get("cookies_b") and config.get("token_b")) else ("token" if config.get("token_b") else "cookie"),
                cookies=config.get("cookies_b") or "",
                token=config.get("token_b") or "",
                token_header="Authorization",
                username=user,
                password=passwd,
                source="task_config",
                valid=True,
            ))
    # accounts list
    for acc in config.get("accounts") or []:
        if not isinstance(acc, dict):
            continue
        role = acc.get("role") or "A"
        store.upsert(CredentialRecord(
            domain=_host(acc.get("domain") or (targets[0] if targets else "*")) or "*",
            role=role,
            auth_type=acc.get("auth_type") or "cookie",
            cookies=acc.get("cookies") or "",
            headers=acc.get("headers") or {},
            token=acc.get("token") or "",
            token_header=acc.get("token_header") or "Authorization",
            username=acc.get("username") or "",
            password=acc.get("password") or "",
            sign_alg=acc.get("sign_alg") or "",
            sign_key=acc.get("sign_key") or "",
            source="accounts",
            valid=True,
        ))
    store.save()
    return store


def is_auth_failure(status: int | None, body: str = "") -> bool:
    if status in (401, 403):
        return True
    if re.search(r'"(?:code|status|errCode|errorCode)"\s*:\s*(?:401|403|10001|10002|20001|login|unauthorized)', body or "", re.I):
        return True
    if re.search(r"unauthorized|not\s*login|token\s*expired|请先登录|登录失效|未授权", body or "", re.I):
        return True
    return False


async def handle_auth_failure(
    task_id: int,
    *,
    url: str,
    role: str = "A",
    status: int | None,
    body: str = "",
    config: dict[str, Any] | None = None,
    unattended: bool = True,
) -> dict[str, Any]:
    """凭证失效处理。无人值守：尝试用账号密码重登；否则暂停。"""
    store = get_store(task_id)
    store.mark_invalid(url, role, status, reason=f"auth failure status={status}")
    # 尝试重建
    rebuilt = False
    config = config or {}
    try:
        from collector.session_bootstrap import bootstrap_account_session
        # 组装 account
        rec = None
        for r in store.records:
            if r.role == role and (r.username and r.password):
                rec = r
                break
        if rec and rec.username and rec.password:
            account = {
                "role": role,
                "username": rec.username,
                "password": rec.password,
                "cookies": "",
                "token": "",
            }
            work = str(work_dir_for_task(task_id) / "auth_rebuild")
            Path(work).mkdir(parents=True, exist_ok=True)
            sess = await bootstrap_account_session(target=url, account=account, work_dir=work, allow_register=False)
            if sess.get("success"):
                store.upsert(CredentialRecord(
                    domain=_host(url) or rec.domain,
                    role=role,
                    auth_type="cookie",
                    cookies=sess.get("cookies") or "",
                    token=sess.get("token") or "",
                    token_header=sess.get("token_header") or "Authorization",
                    username=rec.username,
                    password=rec.password,
                    source="relogin",
                    valid=True,
                    notes="rebuilt after auth failure",
                ))
                rebuilt = True
                store.resume()
    except Exception as e:
        store.pause(f"凭证失效且重建失败: {e}")
        return {"paused": True, "rebuilt": False, "reason": str(e)}

    if rebuilt:
        return {"paused": False, "rebuilt": True, "reason": "relogin ok"}

    # 无人值守/考试模式：绝不等人，凭证失效只标记，审计继续（需认证接口标 uncertain）
    if unattended or _truthy_env_unattended():
        store.pause(f"凭证失效 status={status}，无人值守无法重建，后续需认证接口将标为无法验证")
        return {"paused": True, "rebuilt": False, "reason": "no relogin material"}

    store.pause(f"凭证失效 status={status}，等待人工更新凭证")
    return {"paused": True, "rebuilt": False, "reason": "wait human"}
