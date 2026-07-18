#!/usr/bin/env python3
"""恢复任务：复用已收集文件 + WorkItem 队列，不重做已完成单元。"""
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Resume a xinru task without losing finished work")
    parser.add_argument("task_id", type=int, help="Task ID to resume")
    parser.add_argument("--force-fresh", action="store_true", help="Ignore resume and start fresh collect")
    parser.add_argument("--status-only", action="store_true", help="Only print resume decision / queue stats")
    parser.add_argument("--pause", action="store_true", help="Request cooperative pause and exit")
    parser.add_argument("--pause-reason", default="user_pause", help="Pause reason")
    parser.add_argument("--history", action="store_true", help="Show WorkItem execution history and exit")
    parser.add_argument("--history-limit", type=int, default=30, help="History rows to show")
    args = parser.parse_args()

    from storage.models import init_db, Task, CollectedFile, Finding
    from orchestrator import workqueue as wq
    from orchestrator.graph import start_task

    init_db()
    try:
        task = Task.get_by_id(args.task_id)
    except Exception:
        print(f"task {args.task_id} not found", file=sys.stderr)
        return 2

    wq.reclaim_expired(args.task_id)
    decision = wq.decide_resume_entry(args.task_id)
    qstats = wq.queue_stats(args.task_id)
    files = CollectedFile.select().where(CollectedFile.task_id == args.task_id)
    audited = sum(1 for f in files if f.is_audited)
    partial = sum(1 for f in files if (not f.is_audited) and (f.audit_start_line or 0) > 0)
    findings = Finding.select().where(Finding.task_id == args.task_id).count()

    print("=" * 60)
    print(f"task=#{task.id} status={task.status} phase={getattr(task, 'phase', None)}")
    print(f"pause_reason={task.pause_reason}")
    print(f"files={task.total_files_collected} audited={audited} partial={partial} findings={findings}")
    print(f"resume_decision={json.dumps(decision, ensure_ascii=False)}")
    print(f"queue={qstats}")
    print("=" * 60)

    if args.status_only:
        return 0

    if args.history:
        items = wq.list_work_items(args.task_id, limit=args.history_limit, order="updated_desc")
        print(f"workitem history (latest {len(items)}):")
        for it in items:
            print(
                f"  #{it['id']} {it['item_type']:16} {it['status']:8} "
                f"attempts={it['attempts']} label={it.get('label')} "
                f"started={it.get('started_at')} done={it.get('completed_at')} "
                f"err={(it.get('error') or '')[:80]}"
            )
        # also show recent progress logs
        from storage.models import ProgressLog
        logs = list(ProgressLog.select().where(ProgressLog.task_id == args.task_id).order_by(ProgressLog.id.desc()).limit(15))
        print("recent progress logs:")
        for log in reversed(logs):
            msg = (log.message or "").replace("\n", " ")[:140]
            print(f"  [{log.created_at}] {log.log_type}: {msg}")
        return 0

    if args.pause:
        t = wq.request_pause(args.task_id, args.pause_reason)
        print(f'paused status={t.status} reason={t.pause_reason} queue={wq.queue_stats(args.task_id)}')
        return 0

    print(f"resuming task={args.task_id} force_fresh={args.force_fresh}", flush=True)
    asyncio.run(start_task(args.task_id, force_fresh=bool(args.force_fresh)))
    task = Task.get_by_id(args.task_id)
    qstats = wq.queue_stats(args.task_id)
    print(
        f"DONE status={task.status} phase={getattr(task, 'phase', None)} "
        f"files={task.total_files_collected} findings={task.total_findings} "
        f"lines={task.total_lines_audited} queue={qstats}",
        flush=True,
    )
    return 0 if task.status in {"completed", "paused", "auditing", "verifying_chain", "generating_report"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
