#!/usr/bin/env python3
"""Robust unattended task runner (file-based, no heredoc stdin)."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

# Defaults for hard targets: skip blocking LLM asset extract
os.environ.setdefault("XINRU_SKIP_LLM_SOURCE", "1")
os.environ.setdefault("XINRU_WORKERS", os.environ.get("XINRU_WORKERS", "3"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-id", type=int, default=0)
    parser.add_argument("--targets", default="https://www.bmw.com.cn")
    parser.add_argument("--create", action="store_true")
    parser.add_argument("--brief", default="BBASRC authorized anonymous test")
    args = parser.parse_args()

    from storage.models import init_db, Task, ProgressLog
    from orchestrator.graph import start_task

    init_db()
    task_id = args.task_id
    if args.create or not task_id:
        targets = [x.strip() for x in args.targets.split(",") if x.strip()]
        task = Task.create(
            target=json.dumps(targets, ensure_ascii=False),
            config=json.dumps({
                "brief": args.brief,
                "waf_authorized": True,
                "unattended": True,
                "subdomain_discovery": False,
                "path_brute": False,
                "allow_register": False,
                "allow_brute": False,
                "filter_leads_by_scope": True,
                "scope_file": "scope/bbasrc_scope.json",
                "skip_llm_extract": True,
            }, ensure_ascii=False),
            status="pending",
        )
        task_id = task.id
        ProgressLog.create(task=task, message=f"runner created task #{task_id} targets={targets}", log_type="info")
        print(f"created task={task_id}", flush=True)
        Path("/tmp/bbasrc_current_task.txt").write_text(str(task_id), encoding="utf-8")

    print(f"start task={task_id}", flush=True)
    asyncio.run(start_task(task_id))
    t = Task.get_by_id(task_id)
    print(
        f"DONE status={t.status} files={t.total_files_collected} findings={t.total_findings} lines={t.total_lines_audited}",
        flush=True,
    )
    return 0 if t.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
