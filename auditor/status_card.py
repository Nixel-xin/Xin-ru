"""状态卡 + 硬回流约束 — xinru 强位置锚点

在多 Agent / 单 Agent 循环中输出状态卡，并做行号单调 / 指纹连续校验。
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Any

from auditor.credentials import work_dir_for_task

_LOCK = threading.RLock()


@dataclass
class StatusSnapshot:
    file_path: str = ""
    line: int = 0
    total_lines: int = 0
    prev_fingerprint: str = ""
    curr_fingerprint: str = ""
    threats_found: int = 0
    confirmed: int = 0
    excluded: int = 0
    uncertain: int = 0
    processing: int = 0
    next_step: str = ""
    worker_id: str = ""
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())


def fingerprint_line(lines: list[str], line_no: int) -> str:
    """line_no 为 0-based。"""
    if line_no < 0 or line_no >= len(lines):
        return ""
    return (lines[line_no] or "")[:20].replace("\t", " ")


def render_status_card(snap: StatusSnapshot) -> str:
    name = Path(snap.file_path).name if snap.file_path else "-"
    return (
        "╔══════════════════════════════════════════════════╗\n"
        f"║ 📁 当前文件: {name}\n"
        f"║ 📍 当前行号: 第 {snap.line} 行 / 共 {snap.total_lines} 行\n"
        f"║ 🔍 上一行指纹: {snap.prev_fingerprint}\n"
        f"║ 📌 当前行指纹: {snap.curr_fingerprint}\n"
        f"║ 🔢 全局威胁计数: 已发现 {snap.threats_found}\n"
        f"║    ✅ 已确认 {snap.confirmed} / ❌ 已排除 {snap.excluded} / ⚠️ 无法验证 {snap.uncertain}\n"
        f"║    ⏳ 处理中 {snap.processing}\n"
        f"║ 📋 下一步: {snap.next_step}\n"
        f"║ 👷 worker: {snap.worker_id or '-'}\n"
        "╚══════════════════════════════════════════════════╝"
    )


class StatusTracker:
    def __init__(self, task_id: int):
        self.task_id = task_id
        self.path = work_dir_for_task(task_id) / "status_cards.jsonl"
        self.last_by_worker: dict[str, StatusSnapshot] = {}
        self.global_threats = 0
        self.confirmed = 0
        self.excluded = 0
        self.uncertain = 0

    def update_counts(self, *, confirmed=0, excluded=0, uncertain=0, found_delta=0):
        with _LOCK:
            self.confirmed += confirmed
            self.excluded += excluded
            self.uncertain += uncertain
            self.global_threats += found_delta

    def make(
        self,
        *,
        file_path: str,
        line: int,
        total_lines: int,
        lines: list[str] | None = None,
        next_step: str = "",
        worker_id: str = "main",
        processing: int = 0,
    ) -> StatusSnapshot:
        lines = lines or []
        # line 用 1-based 展示
        idx = max(line - 1, 0)
        prev_fp = fingerprint_line(lines, idx - 1) if idx > 0 else ""
        curr_fp = fingerprint_line(lines, idx) if lines else ""
        snap = StatusSnapshot(
            file_path=file_path,
            line=line,
            total_lines=total_lines,
            prev_fingerprint=prev_fp,
            curr_fingerprint=curr_fp,
            threats_found=self.global_threats,
            confirmed=self.confirmed,
            excluded=self.excluded,
            uncertain=self.uncertain,
            processing=processing,
            next_step=next_step,
            worker_id=worker_id,
        )
        return snap

    def validate_and_commit(self, snap: StatusSnapshot) -> dict[str, Any]:
        """硬约束：行号单调、指纹连续（同文件）。"""
        with _LOCK:
            prev = self.last_by_worker.get(snap.worker_id)
            errors: list[str] = []
            if prev and prev.file_path == snap.file_path:
                if snap.line < prev.line:
                    errors.append(f"行号回退 {prev.line}->{snap.line}")
                if prev.curr_fingerprint and snap.prev_fingerprint and prev.curr_fingerprint != snap.prev_fingerprint:
                    # 允许跨威胁处理后的小偏差，只记 warning
                    errors.append("指纹不连续(warning)")
                if prev.total_lines and snap.total_lines and prev.total_lines != snap.total_lines:
                    errors.append("文件总行数变化")
            self.last_by_worker[snap.worker_id] = snap
            self._append(snap, errors)
            return {"ok": not any(e for e in errors if "warning" not in e), "errors": errors, "card": render_status_card(snap)}

    def _append(self, snap: StatusSnapshot, errors: list[str]):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        rec = asdict(snap)
        rec["errors"] = errors
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


_TRACKERS: dict[int, StatusTracker] = {}


def get_tracker(task_id: int) -> StatusTracker:
    with _LOCK:
        if task_id not in _TRACKERS:
            _TRACKERS[task_id] = StatusTracker(task_id)
        return _TRACKERS[task_id]
