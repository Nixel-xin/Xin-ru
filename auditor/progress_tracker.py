"""审计进度追踪 — 文件级 + 行级断点，支持无人值守恢复"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any


def progress_path(work_dir: str) -> str:
    return os.path.join(work_dir, ".xinru_progress.json")


def default_progress() -> dict[str, Any]:
    return {
        "updated_at": datetime.now().isoformat(),
        "current_file_index": 0,
        "current_file": "",
        "current_line": 0,
        "files_completed": 0,
        "total_files": 0,
        "total_lines_audited": 0,
        "handled_threats": [],
        "findings_count": 0,
        "return_marker": None,
    }


def load_progress(work_dir: str) -> dict[str, Any]:
    path = progress_path(work_dir)
    if not os.path.isfile(path):
        return default_progress()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return default_progress()
        base = default_progress()
        base.update(data)
        return base
    except Exception:
        return default_progress()


def save_progress(work_dir: str, progress: dict[str, Any]) -> str:
    os.makedirs(work_dir, exist_ok=True)
    path = progress_path(work_dir)
    tmp = path + ".tmp"
    payload = dict(progress or {})
    payload["updated_at"] = datetime.now().isoformat()
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return path


def update_from_state(work_dir: str, state: dict[str, Any]) -> dict[str, Any]:
    progress = {
        "current_file_index": state.get("current_file_index", 0),
        "current_file": "",
        "current_line": state.get("current_line", 0),
        "files_completed": state.get("files_completed", 0),
        "total_files": state.get("total_files", 0),
        "total_lines_audited": state.get("total_lines_audited", 0),
        "handled_threats": list(state.get("handled_threats", [])),
        "findings_count": len(state.get("findings", []) or []),
        "return_marker": state.get("return_marker"),
    }
    paths = state.get("sorted_file_paths") or []
    idx = state.get("current_file_index", 0)
    if 0 <= idx < len(paths):
        progress["current_file"] = paths[idx]
    save_progress(work_dir, progress)
    return progress
