"""BBASRC 启动入口：先加载范围说明，再启动无人值守 agent 测试。"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


async def main():
    parser = argparse.ArgumentParser(description="Run BBASRC xinru agent")
    parser.add_argument("--targets", default="", help="comma-separated targets; default=seed list")
    parser.add_argument("--credentials", default="", help="A user:pass")
    parser.add_argument("--credentials-b", default="", help="B user:pass")
    parser.add_argument("--cookies", default="", help="A cookies")
    parser.add_argument("--cookies-b", default="", help="B cookies")
    parser.add_argument("--token", default="", help="A token")
    parser.add_argument("--token-b", default="", help="B token")
    parser.add_argument("--allow-register", action="store_true", help="allow auto-register B")
    parser.add_argument("--no-subdomain", action="store_true")
    parser.add_argument("--no-path-brute", action="store_true")
    args = parser.parse_args()

    kickoff = load_json(ROOT / "scope" / "bbasrc_kickoff.json")
    scope = load_json(ROOT / "scope" / "bbasrc_scope.json")
    brief = (ROOT / "scope" / "bbasrc_kickoff.md").read_text(encoding="utf-8")

    targets = [t.strip() for t in args.targets.split(",") if t.strip()] or list(kickoff.get("default_targets") or [])

    # scope filter
    from scope.scope_matcher import is_in_scope

    filtered = []
    for t in targets:
        ok, reason = is_in_scope(t)
        if ok:
            filtered.append(t)
        else:
            print(f"[scope] skip {t} ({reason})")
    if not filtered:
        raise SystemExit("no in-scope targets")

    from storage.models import init_db, Task, ProgressLog
    from orchestrator.graph import start_task

    init_db()
    config = {
        "brief": kickoff.get("brief"),
        "kickoff_markdown": brief[:4000],
        "scope_name": scope.get("name"),
        "scope_file": "scope/bbasrc_scope.json",
        "credentials": args.credentials,
        "credentials_b": args.credentials_b,
        "cookies": args.cookies,
        "cookies_b": args.cookies_b,
        "token": args.token,
        "token_b": args.token_b,
        "subdomain_discovery": not args.no_subdomain,
        "path_brute": not args.no_path_brute,
        "allow_register": bool(args.allow_register),
        "allow_brute": False,
        "unattended": True,
        "filter_leads_by_scope": True,
        "waf_authorized": True,
    }

    task = Task.create(
        target=json.dumps(filtered, ensure_ascii=False),
        config=json.dumps(config, ensure_ascii=False),
        status="pending",
    )
    ProgressLog.create(
        task=task,
        message="📋 BBASRC 启动说明已加载：\n" + kickoff.get("brief", ""),
        log_type="info",
    )
    ProgressLog.create(
        task=task,
        message=f"🎯 in-scope 目标: {filtered}",
        log_type="info",
    )
    print("=" * 60)
    print(kickoff.get("brief"))
    print("=" * 60)
    print(f"task=#{task.id}")
    print("targets:")
    for t in filtered:
        print(" -", t)
    print("auth A:", "yes" if (args.credentials or args.cookies or args.token) else "no")
    print("auth B:", "yes" if (args.credentials_b or args.cookies_b or args.token_b) else "no")
    print("starting agent...")
    await start_task(task.id)

    task = Task.get_by_id(task.id)
    print(f"done status={task.status} files={task.total_files_collected} findings={task.total_findings}")


if __name__ == "__main__":
    asyncio.run(main())
