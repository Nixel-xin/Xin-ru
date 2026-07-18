"""可恢复工作队列 — WorkItem claim/complete + task pause/resume

设计目标:
1. 进程崩溃后重启，只重做未完成单元
2. 已 done 的 audit_file 永不重做
3. LLM 熔断时任务进入 paused，不标 failed/completed
"""

from __future__ import annotations

import json
import os
import socket
import uuid
from datetime import datetime, timedelta
from typing import Any, Iterable

from peewee import fn
from storage.models import Task, WorkItem, CollectedFile, db


DEFAULT_LEASE_SEC = int(os.environ.get("XINRU_WORKITEM_LEASE_SEC", "180"))
DEFAULT_MAX_ATTEMPTS = int(os.environ.get("XINRU_WORKITEM_MAX_ATTEMPTS", "5"))
LLM_FAIL_THRESHOLD = int(os.environ.get("XINRU_LLM_FAIL_THRESHOLD", "8"))

# 进程内 LLM 连续失败计数（按 task）
_LLM_FAIL_STREAK: dict[int, int] = {}


def worker_id(prefix: str = "worker") -> str:
    host = socket.gethostname().split(".")[0]
    return f"{prefix}-{host}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


def _now() -> datetime:
    return datetime.now()


def set_phase(task_id: int, phase: str, status: str | None = None, pause_reason: str | None = None):
    """更新任务粗粒度阶段。status 默认跟随 phase。"""
    task = Task.get_by_id(task_id)
    task.phase = phase
    if status is None:
        # phase -> status 映射
        mapping = {
            "pending": "pending",
            "collecting": "collecting",
            "authenticating": "authenticating",
            "auditing": "auditing",
            "verifying_chain": "verifying_chain",
            "reporting": "generating_report",
            "done": "completed",
            "paused": "paused",
        }
        status = mapping.get(phase, task.status)
    task.status = status
    if pause_reason is not None:
        task.pause_reason = pause_reason
    elif status != "paused":
        task.pause_reason = None
    task.updated_at = _now()
    if status == "completed":
        task.completed_at = _now()
    task.save()
    return task


def pause_task(task_id: int, reason: str, phase: str | None = None):
    task = Task.get_by_id(task_id)
    task.status = "paused"
    task.pause_reason = reason
    if phase:
        task.phase = phase
    task.updated_at = _now()
    task.save()
    return task


def request_pause(task_id: int, reason: str = "user_pause") -> Task:
    """协作式暂停：标记 paused，worker 不再 claim；当前 running 会在检查点释放。"""
    task = Task.get_by_id(task_id)
    paused = pause_task(task_id, reason, phase=task.phase or "auditing")
    _progress(task_id, f"⏸️ 任务暂停 — {reason}", "warning")
    return paused


def threat_dedupe_key(file_id: int | None, file_path: str, line: int, pattern_name: str) -> str:
    base = f"file:{file_id}" if file_id else f"path:{file_path}"
    pname = (pattern_name or "threat").strip().lower().replace(" ", "_")[:80]
    return f"handle_threat:{base}:{int(line)}:{pname}"


def verify_dedupe_key(method: str, url: str, role_hint: str = "") -> str:
    import hashlib
    raw = f"{(method or 'GET').upper()}|{(url or '').strip()}|{role_hint}"
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:20]
    return f"verify_endpoint:{digest}"


def get_item(task_id: int, dedupe_key: str) -> WorkItem | None:
    return WorkItem.select().where(
        (WorkItem.task_id == task_id) & (WorkItem.dedupe_key == dedupe_key)
    ).first()


def begin_or_skip_item(
    task_id: int,
    item_type: str,
    dedupe_key: str,
    payload: dict | None = None,
    *,
    worker: str,
    priority: int = 50,
    lease_sec: int | None = None,
) -> tuple[WorkItem | None, str]:
    """获取可恢复子单元。

    返回 (item, action):
      - action=done: 已完成，调用方应跳过
      - action=run: 已标记 running，调用方执行
      - action=blocked: 任务暂停/无法领取
    """
    if is_task_paused(task_id):
        return None, "blocked"

    item = enqueue_item(
        task_id,
        item_type,
        dedupe_key,
        payload=payload,
        priority=priority,
    )
    if item.status == "done":
        return item, "done"
    if item.status == "skipped":
        return item, "done"
    if item.status == "running":
        # 自己的 lease 可续；别人的未过期则跳过等待
        if item.locked_by and item.locked_by != worker:
            if item.locked_until and item.locked_until > _now():
                return item, "blocked"
        # 过期或同 worker：接管
        lease = int(lease_sec or DEFAULT_LEASE_SEC)
        now = _now()
        WorkItem.update(
            status="running",
            locked_by=worker,
            locked_until=now + timedelta(seconds=lease),
            heartbeat_at=now,
            updated_at=now,
            attempts=WorkItem.attempts + 1,
        ).where(WorkItem.id == item.id).execute()
        return WorkItem.get_by_id(item.id), "run"

    # pending/failed → running
    lease = int(lease_sec or DEFAULT_LEASE_SEC)
    now = _now()
    updated = (
        WorkItem.update(
            status="running",
            locked_by=worker,
            locked_until=now + timedelta(seconds=lease),
            heartbeat_at=now,
            started_at=now if not item.started_at else item.started_at,
            attempts=WorkItem.attempts + 1,
            updated_at=now,
            error=None,
            payload_json=json.dumps(payload or item.get_payload() or {}, ensure_ascii=False),
        )
        .where(WorkItem.id == item.id)
        .where(WorkItem.status.in_(["pending", "failed"]))
        .execute()
    )
    if not updated:
        # 可能被并发抢走
        item = WorkItem.get_by_id(item.id)
        if item.status == "done":
            return item, "done"
        return item, "blocked"
    return WorkItem.get_by_id(item.id), "run"



def resume_task_record(task_id: int, phase: str | None = None):
    task = Task.get_by_id(task_id)
    prev = task.status
    if task.status == "paused":
        task.status = phase or task.phase or "auditing"
        if task.status == "paused":
            task.status = "auditing"
    if phase:
        task.phase = phase
    task.pause_reason = None
    task.updated_at = _now()
    task.save()
    if prev == "paused":
        _progress(task_id, f"▶️ 任务恢复 — phase={task.phase} status={task.status}", "info")
    return task


def is_task_paused(task_id: int) -> bool:
    try:
        task = Task.get_by_id(task_id)
        return task.status == "paused"
    except Exception:
        return False


def note_llm_success(task_id: int):
    _LLM_FAIL_STREAK[task_id] = 0


def note_llm_failure(task_id: int, error: Exception | str | None = None) -> dict[str, Any]:
    """记录 LLM 失败。达到阈值则 pause 任务。"""
    streak = _LLM_FAIL_STREAK.get(task_id, 0) + 1
    _LLM_FAIL_STREAK[task_id] = streak
    msg = str(error or "")
    fatal = _is_fatal_llm_error(msg)
    paused = False
    if fatal or streak >= LLM_FAIL_THRESHOLD:
        reason = f"llm_unreachable: {msg[:300]}" if msg else f"llm_unreachable: streak={streak}"
        try:
            task = Task.get_by_id(task_id)
            pause_task(task_id, reason, phase=task.phase or "auditing")
            paused = True
        except Exception:
            paused = False
    return {"streak": streak, "fatal": fatal, "paused": paused, "threshold": LLM_FAIL_THRESHOLD}


def _is_fatal_llm_error(message: str) -> bool:
    m = (message or "").lower()
    keys = (
        "401", "402", "403",
        "insufficient balance", "余额不足", "invalid api key",
        "unauthorized", "authentication", "permission denied",
        "model not found",
    )
    return any(k in m for k in keys)


def enqueue_item(
    task_id: int,
    item_type: str,
    dedupe_key: str,
    payload: dict | None = None,
    *,
    priority: int = 100,
    max_attempts: int | None = None,
) -> WorkItem:
    """幂等入队：已存在则返回已有记录，不重置 done。"""
    existing = WorkItem.select().where(
        (WorkItem.task_id == task_id) & (WorkItem.dedupe_key == dedupe_key)
    ).first()
    if existing:
        # 若之前 failed 且仍有重试次数，允许回到 pending
        if existing.status == "failed" and existing.attempts < existing.max_attempts:
            existing.status = "pending"
            existing.error = None
            existing.locked_by = None
            existing.locked_until = None
            existing.updated_at = _now()
            existing.save()
        return existing

    item = WorkItem.create(
        task=task_id,
        item_type=item_type,
        dedupe_key=dedupe_key,
        status="pending",
        attempts=0,
        max_attempts=max_attempts or DEFAULT_MAX_ATTEMPTS,
        priority=priority,
        payload_json=json.dumps(payload or {}, ensure_ascii=False),
        created_at=_now(),
        updated_at=_now(),
    )
    return item


def enqueue_audit_files(
    task_id: int,
    file_paths: Iterable[str],
    *,
    priority_base: int = 100,
) -> dict[str, int]:
    """为未完成文件创建 audit_file 工作单元。已 audited / 已 done 的跳过。"""
    created = 0
    skipped_done = 0
    skipped_audited = 0
    for idx, path in enumerate(file_paths):
        if not path:
            continue
        dbf = CollectedFile.select().where(
            (CollectedFile.task_id == task_id) & (CollectedFile.local_path == path)
        ).first()
        if dbf and dbf.is_audited:
            # 确保 workitem 也是 done，便于统计
            key = f"audit_file:{dbf.id if dbf else path}"
            item = enqueue_item(
                task_id,
                "audit_file",
                key,
                payload={
                    "file_path": path,
                    "file_id": dbf.id if dbf else None,
                    "file_name": dbf.file_name if dbf else os.path.basename(path),
                },
                priority=priority_base + idx,
            )
            if item.status != "done":
                complete_item(item.id, {"skipped": True, "reason": "already_audited", "file_path": path})
            skipped_audited += 1
            continue

        file_id = dbf.id if dbf else None
        key = f"audit_file:{file_id}" if file_id else f"audit_file:path:{path}"
        before = WorkItem.select().where(
            (WorkItem.task_id == task_id) & (WorkItem.dedupe_key == key)
        ).first()
        item = enqueue_item(
            task_id,
            "audit_file",
            key,
            payload={
                "file_path": path,
                "file_id": file_id,
                "file_name": (dbf.file_name if dbf else os.path.basename(path)),
                "audit_start_line": int(dbf.audit_start_line) if dbf else 0,
            },
            priority=priority_base + idx,
        )
        if before is None:
            created += 1
        elif before.status == "done":
            skipped_done += 1
    return {
        "created": created,
        "skipped_done": skipped_done,
        "skipped_audited": skipped_audited,
    }


def reclaim_expired(task_id: int | None = None) -> int:
    """回收 lease 过期的 running 项。"""
    now = _now()
    q = WorkItem.update(
        status="pending",
        locked_by=None,
        locked_until=None,
        updated_at=now,
        error="lease expired; reclaimed",
    ).where(
        (WorkItem.status == "running")
        & (WorkItem.locked_until.is_null(False))
        & (WorkItem.locked_until < now)
    )
    if task_id is not None:
        q = q.where(WorkItem.task_id == task_id)
    return q.execute()


def claim_next(
    task_id: int,
    worker: str,
    *,
    item_types: list[str] | None = None,
    lease_sec: int | None = None,
) -> WorkItem | None:
    """原子领取一个 pending 工作单元。"""
    if is_task_paused(task_id):
        return None

    reclaim_expired(task_id)
    lease = int(lease_sec or DEFAULT_LEASE_SEC)
    now = _now()
    until = now + timedelta(seconds=lease)

    with db.atomic():
        q = (
            WorkItem.select()
            .where(
                (WorkItem.task_id == task_id)
                & (WorkItem.status == "pending")
                & (WorkItem.attempts < WorkItem.max_attempts)
            )
            .order_by(WorkItem.priority.asc(), WorkItem.id.asc())
        )
        if item_types:
            q = q.where(WorkItem.item_type.in_(item_types))
        item = q.first()
        if not item:
            return None

        # 乐观锁：仅当仍是 pending 时更新
        updated = (
            WorkItem.update(
                status="running",
                locked_by=worker,
                locked_until=until,
                heartbeat_at=now,
                started_at=now if not item.started_at else item.started_at,
                attempts=WorkItem.attempts + 1,
                updated_at=now,
                error=None,
            )
            .where((WorkItem.id == item.id) & (WorkItem.status == "pending"))
            .execute()
        )
        if not updated:
            return None
        return WorkItem.get_by_id(item.id)


def heartbeat(item_id: int, worker: str, *, lease_sec: int | None = None) -> bool:
    lease = int(lease_sec or DEFAULT_LEASE_SEC)
    now = _now()
    until = now + timedelta(seconds=lease)
    n = (
        WorkItem.update(
            heartbeat_at=now,
            locked_until=until,
            updated_at=now,
        )
        .where(
            (WorkItem.id == item_id)
            & (WorkItem.status == "running")
            & (WorkItem.locked_by == worker)
        )
        .execute()
    )
    return bool(n)


def complete_item(item_id: int, result: dict | None = None) -> WorkItem:
    now = _now()
    item = WorkItem.get_by_id(item_id)
    item.status = "done"
    item.result_json = json.dumps(result or {}, ensure_ascii=False)
    item.locked_by = None
    item.locked_until = None
    item.completed_at = now
    item.updated_at = now
    item.error = None
    item.save()
    payload = item.get_payload()
    label = payload.get("file_name") or payload.get("pattern_name") or payload.get("url") or item.dedupe_key
    _progress(
        item.task_id,
        f"✅ WorkItem完成 [{item.item_type}] #{item.id} {label}",
        "info",
    )
    return item


def fail_item(
    item_id: int,
    error: str,
    *,
    retryable: bool = True,
    result: dict | None = None,
) -> WorkItem:
    now = _now()
    item = WorkItem.get_by_id(item_id)
    item.error = (error or "")[:2000]
    if result is not None:
        item.result_json = json.dumps(result, ensure_ascii=False)
    item.locked_by = None
    item.locked_until = None
    item.updated_at = now
    if retryable and item.attempts < item.max_attempts:
        item.status = "pending"
    else:
        item.status = "failed"
        item.completed_at = now
    item.save()
    payload = item.get_payload()
    label = payload.get("file_name") or payload.get("pattern_name") or payload.get("url") or item.dedupe_key
    st = "可重试" if item.status == "pending" else "失败"
    _progress(
        item.task_id,
        f"⚠️ WorkItem{st} [{item.item_type}] #{item.id} {label}: {(error or '')[:160]}",
        "warning" if item.status == "pending" else "error",
    )
    return item


def skip_item(item_id: int, reason: str = "") -> WorkItem:
    now = _now()
    item = WorkItem.get_by_id(item_id)
    item.status = "skipped"
    item.error = reason[:2000] if reason else None
    item.locked_by = None
    item.locked_until = None
    item.completed_at = now
    item.updated_at = now
    item.save()
    return item


def queue_stats(task_id: int) -> dict[str, int]:
    stats = {
        "pending": 0,
        "running": 0,
        "done": 0,
        "failed": 0,
        "skipped": 0,
        "total": 0,
    }
    for row in (
        WorkItem.select(WorkItem.status, fn.COUNT(WorkItem.id).alias("c"))
        .where(WorkItem.task_id == task_id)
        .group_by(WorkItem.status)
    ):
        stats[row.status] = int(row.c)
        stats["total"] += int(row.c)
    stats["unfinished"] = stats["pending"] + stats["running"]
    return stats


def has_unfinished(task_id: int, item_types: list[str] | None = None) -> bool:
    q = WorkItem.select().where(
        (WorkItem.task_id == task_id)
        & (WorkItem.status.in_(["pending", "running"]))
    )
    if item_types:
        q = q.where(WorkItem.item_type.in_(item_types))
    return q.exists()


def load_collected_files(task_id: int) -> list[dict]:
    """从 DB 恢复 collected_files，供 resume 跳过收集阶段。"""
    out = []
    for dbf in CollectedFile.select().where(CollectedFile.task == task_id):
        out.append({
            "source_type": dbf.source_type,
            "url": dbf.url,
            "local_path": dbf.local_path,
            "file_name": dbf.file_name,
            "file_size": dbf.file_size,
            "line_count": dbf.line_count,
            "content_hash": dbf.content_hash or "",
            "is_audited": bool(dbf.is_audited),
            "audit_start_line": dbf.audit_start_line,
        })
    return out



def _progress(task_id: int, message: str, log_type: str = "info"):
    try:
        from storage.models import ProgressLog
        ProgressLog.create(task=task_id, message=message, log_type=log_type)
    except Exception:
        pass


def workitem_to_dict(item: WorkItem) -> dict[str, Any]:
    payload = item.get_payload()
    result = item.get_result()
    return {
        "id": item.id,
        "task_id": item.task_id,
        "item_type": item.item_type,
        "dedupe_key": item.dedupe_key,
        "status": item.status,
        "attempts": item.attempts,
        "max_attempts": item.max_attempts,
        "priority": item.priority,
        "locked_by": item.locked_by,
        "locked_until": item.locked_until.isoformat() if item.locked_until else None,
        "heartbeat_at": item.heartbeat_at.isoformat() if item.heartbeat_at else None,
        "payload": payload,
        "result": result,
        "error": item.error,
        "label": (
            payload.get("file_name")
            or payload.get("pattern_name")
            or payload.get("url")
            or payload.get("file_path")
            or item.dedupe_key
        ),
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
        "started_at": item.started_at.isoformat() if item.started_at else None,
        "completed_at": item.completed_at.isoformat() if item.completed_at else None,
    }


def list_work_items(
    task_id: int,
    *,
    status: str | None = None,
    item_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
    order: str = "updated_desc",
) -> list[dict[str, Any]]:
    q = WorkItem.select().where(WorkItem.task_id == task_id)
    if status:
        q = q.where(WorkItem.status == status)
    if item_type:
        q = q.where(WorkItem.item_type == item_type)
    if order == "id_asc":
        q = q.order_by(WorkItem.id.asc())
    elif order == "id_desc":
        q = q.order_by(WorkItem.id.desc())
    else:
        q = q.order_by(WorkItem.updated_at.desc(), WorkItem.id.desc())
    limit = max(1, min(int(limit or 100), 500))
    offset = max(0, int(offset or 0))
    rows = list(q.offset(offset).limit(limit))
    return [workitem_to_dict(x) for x in rows]


def workitem_history_summary(task_id: int) -> dict[str, Any]:
    stats = queue_stats(task_id)
    recent_done = list_work_items(task_id, status="done", limit=20, order="updated_desc")
    recent_failed = list_work_items(task_id, status="failed", limit=10, order="updated_desc")
    recent_running = list_work_items(task_id, status="running", limit=10, order="updated_desc")
    return {
        "queue": stats,
        "recent_done": recent_done,
        "recent_failed": recent_failed,
        "recent_running": recent_running,
    }


def decide_resume_entry(task_id: int) -> dict[str, Any]:
    """决定 resume 应从哪一阶段进入。

    返回:
      mode: fresh | resume_audit | resume_report | resume_collect
      skip_collect: bool
      skip_auth: bool
      entry_phase: str
    """
    task = Task.get_by_id(task_id)
    files = list(CollectedFile.select().where(CollectedFile.task == task_id))
    existing_paths = [f for f in files if f.local_path and os.path.exists(f.local_path)]
    stats = queue_stats(task_id)
    phase = (task.phase or "").strip()
    status = (task.status or "").strip()
    # phase 优先；旧任务 phase 可能为空/pending，回退 status
    effective = phase if phase and phase not in {"pending", ""} else (status or "pending")

    # 已完成
    if status == "completed" or phase == "done" or effective == "completed":
        return {
            "mode": "already_done",
            "skip_collect": True,
            "skip_auth": True,
            "entry_phase": "done",
            "files": len(existing_paths),
            "queue": stats,
        }

    # 有文件且（有未完成 workitem / 已审过 / 已有 finding / 已进入审计后阶段）→ 直接审计
    unfinished = stats.get("unfinished", 0) > 0
    audited_any = any(bool(f.is_audited) or int(f.audit_start_line or 0) > 0 for f in files)
    try:
        from storage.models import Finding
        has_findings = Finding.select().where(Finding.task_id == task_id).exists()
    except Exception:
        has_findings = False

    in_audit_or_later = effective in {
        "auditing", "verifying_chain", "reporting", "generating_report",
        "paused", "authenticating",
    } and len(existing_paths) > 0

    if existing_paths and (
        unfinished
        or audited_any
        or has_findings
        or in_audit_or_later
        or stats.get("done", 0) > 0
    ):
        return {
            "mode": "resume_audit",
            "skip_collect": True,
            "skip_auth": False,  # 会话可能过期，轻量重做 auth
            "entry_phase": "auditing",
            "files": len(existing_paths),
            "queue": stats,
        }

    if existing_paths and effective in {"collecting", "pending", "authenticating"}:
        # 收集已有结果，跳过重采
        return {
            "mode": "resume_collect_partial",
            "skip_collect": True,
            "skip_auth": False,
            "entry_phase": "authenticating",
            "files": len(existing_paths),
            "queue": stats,
        }

    return {
        "mode": "fresh",
        "skip_collect": False,
        "skip_auth": False,
        "entry_phase": "collecting",
        "files": len(existing_paths),
        "queue": stats,
    }
