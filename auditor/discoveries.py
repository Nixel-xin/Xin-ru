"""全局发现广播 — xinru 模式 B 主 Agent 维护

.xinru/discoveries.json:
- universal_token / universal_sign_key / universal_bypass / hardcode_secret / auth_header
- 子 Agent 上报后即时广播，后续批次启动时附带
"""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from auditor.credentials import work_dir_for_task

_LOCK = threading.RLock()
_BUSES: dict[int, "DiscoveryBus"] = {}


class DiscoveryBus:
    def __init__(self, task_id: int):
        self.task_id = task_id
        self.path = work_dir_for_task(task_id) / "discoveries.json"
        self.broadcasts: list[dict[str, Any]] = []
        self._load()

    def _load(self):
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.broadcasts = list(data.get("broadcasts") or [])
        except Exception:
            self.broadcasts = []

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "task_id": self.task_id,
            "updated_at": datetime.now().isoformat(),
            "broadcasts": self.broadcasts,
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def publish(
        self,
        *,
        type: str,
        content: str,
        from_worker: str = "",
        payload: dict[str, Any] | None = None,
        domains: list[str] | None = None,
    ) -> dict[str, Any]:
        with _LOCK:
            # 去重：同 type+content 前缀
            key = f"{type}|{(content or '')[:160]}"
            for b in self.broadcasts:
                if f"{b.get('type')}|{str(b.get('content') or '')[:160]}" == key:
                    return b
            item = {
                "id": len(self.broadcasts) + 1,
                "from_subagent": from_worker,
                "timestamp": datetime.now().isoformat(),
                "type": type,
                "content": content,
                "domains": domains or [],
                "payload": payload or {},
                "broadcasted_to": [],
            }
            self.broadcasts.append(item)
            self.save()
            return item

    def snapshot(self, for_worker: str | None = None) -> list[dict[str, Any]]:
        with _LOCK:
            items = list(self.broadcasts)
            if for_worker:
                for b in self.broadcasts:
                    if for_worker not in (b.get("broadcasted_to") or []):
                        b.setdefault("broadcasted_to", []).append(for_worker)
                self.save()
            return items

    def high_value(self) -> list[dict[str, Any]]:
        hv = {
            "universal_token",
            "universal_sign_key",
            "universal_bypass",
            "hardcode_secret",
            "auth_header",
            "admin_endpoint",
        }
        return [b for b in self.broadcasts if b.get("type") in hv]

    def as_prompt_block(self, limit: int = 20) -> str:
        items = self.high_value()[-limit:]
        if not items:
            return "(no broadcasts yet)"
        lines = []
        for b in items:
            lines.append(f"- #{b.get('id')} [{b.get('type')}] {b.get('content')}")
        return "\n".join(lines)


def get_bus(task_id: int) -> DiscoveryBus:
    with _LOCK:
        if task_id not in _BUSES:
            _BUSES[task_id] = DiscoveryBus(task_id)
        return _BUSES[task_id]


def publish_from_finding(
    task_id: int,
    finding: dict[str, Any],
    *,
    worker_id: str = "",
) -> list[dict[str, Any]]:
    """从 finding/威胁中提炼可广播情报。"""
    bus = get_bus(task_id)
    published: list[dict[str, Any]] = []
    name = str(finding.get("name") or "")
    impact = str(finding.get("attack_impact") or finding.get("reason") or "")
    text = f"{name} {impact} {finding.get('fix_suggestion') or ''}".lower()
    endpoint = finding.get("api_endpoint")
    if isinstance(endpoint, str):
        try:
            endpoint = json.loads(endpoint)
        except Exception:
            endpoint = {}
    endpoint = endpoint or {}

    # 硬编码密钥/token
    if any(k in text for k in ("hardcod", "硬编码", "secret", "api_key", "apikey", "appkey", "token")):
        if finding.get("verdict") in ("confirmed", "uncertain", None):
            published.append(
                bus.publish(
                    type="hardcode_secret",
                    content=f"{name} @ {finding.get('file_path')}:{finding.get('line_number')} — {impact[:160]}",
                    from_worker=worker_id,
                    payload={"file_path": finding.get("file_path"), "line": finding.get("line_number")},
                )
            )

    # 无认证开放
    if "无认证" in impact or "no auth" in text or "unauthenticated" in text:
        published.append(
            bus.publish(
                type="universal_bypass",
                content=f"疑似无认证可达: {endpoint.get('full_url') or endpoint.get('path') or name}",
                from_worker=worker_id,
                payload={"endpoint": endpoint},
            )
        )

    # 越权
    if any(k in text for k in ("越权", "idor", "bola", "horizontal", "vertical")):
        published.append(
            bus.publish(
                type="auth_header",
                content=f"授权边界可疑: {name} — {impact[:160]}",
                from_worker=worker_id,
                payload={"endpoint": endpoint, "verdict": finding.get("verdict")},
            )
        )

    return published


def publish_signature_key(
    task_id: int,
    *,
    domain: str,
    alg: str,
    key: str,
    worker_id: str = "",
) -> dict[str, Any]:
    bus = get_bus(task_id)
    return bus.publish(
        type="universal_sign_key",
        content=f"{domain} alg={alg} key={key[:8]}***",
        from_worker=worker_id,
        domains=[domain] if domain else [],
        payload={"domain": domain, "alg": alg, "key": key},
    )


def publish_token(
    task_id: int,
    *,
    token: str,
    domains: list[str] | None = None,
    worker_id: str = "",
) -> dict[str, Any]:
    bus = get_bus(task_id)
    preview = (token or "")[:12] + ("..." if len(token or "") > 12 else "")
    return bus.publish(
        type="universal_token",
        content=f"token {preview} domains={domains or []}",
        from_worker=worker_id,
        domains=domains or [],
        payload={"token": token, "domains": domains or []},
    )
