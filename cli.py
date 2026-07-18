#!/usr/bin/env python3
"""xinru Agent CLI — exam/ops entrypoint.

Examples:
  python cli.py health
  python cli.py run --target https://example.com --brief "exam demo"
  python cli.py status --task-id 1
  python cli.py wait --task-id 1 --timeout 1800
  python cli.py report --task-id 1 --out /tmp/report.html
  python cli.py logs --task-id 1 --tail 50
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urljoin

import httpx

DEFAULT_BASE = os.environ.get("XINRU_BASE_URL", "http://127.0.0.1:8000")


def _client(timeout: float = 30.0) -> httpx.Client:
    return httpx.Client(timeout=timeout, follow_redirects=True)


def cmd_health(args) -> int:
    url = urljoin(args.base.rstrip("/") + "/", "healthz")
    with _client() as c:
        r = c.get(url)
        print(r.text)
        return 0 if r.status_code == 200 and r.json().get("ok") else 1


def cmd_run(args) -> int:
    url = urljoin(args.base.rstrip("/") + "/", "api/tasks")
    data = {
        "target": args.target,
        "brief": args.brief or "exam unattended run",
        "credentials": args.credentials or "",
        "credentials_b": args.credentials_b or "",
        "cookies": args.cookies or "",
        "cookies_b": args.cookies_b or "",
        "token": args.token or "",
        "token_b": args.token_b or "",
        "subdomain_discovery": "true" if args.subdomain else "false",
        "path_brute": "true" if args.path_brute else "false",
        "allow_register": "true" if args.allow_register else "false",
        "allow_brute": "false",
        "unattended": "true",
        "waf_authorized": "true" if args.waf_authorized else "",
    }
    with _client(timeout=60) as c:
        r = c.post(url, data=data)
        print(r.text)
        if r.status_code >= 400:
            return 1
        task = r.json()
        tid = task.get("id")
        if args.wait and tid:
            return cmd_wait(
                argparse.Namespace(
                    base=args.base,
                    task_id=tid,
                    timeout=args.timeout,
                    interval=args.interval,
                )
            )
        return 0


def cmd_status(args) -> int:
    url = urljoin(args.base.rstrip("/") + "/", f"api/tasks/{args.task_id}")
    with _client() as c:
        r = c.get(url)
        print(json.dumps(r.json(), ensure_ascii=False, indent=2))
        return 0 if r.status_code == 200 else 1


def cmd_logs(args) -> int:
    url = urljoin(args.base.rstrip("/") + "/", f"api/tasks/{args.task_id}/logs")
    with _client() as c:
        r = c.get(url, params={"limit": args.tail})
        if r.status_code >= 400:
            print(r.text)
            return 1
        logs = r.json()
        for item in logs[-args.tail :]:
            ts = item.get("created_at") or ""
            print(f"[{ts}] {item.get('log_type')}: {item.get('message')}")
        return 0


def cmd_findings(args) -> int:
    url = urljoin(args.base.rstrip("/") + "/", f"api/tasks/{args.task_id}/findings")
    with _client() as c:
        r = c.get(url)
        print(json.dumps(r.json(), ensure_ascii=False, indent=2))
        return 0 if r.status_code == 200 else 1


def cmd_report(args) -> int:
    url = urljoin(args.base.rstrip("/") + "/", f"api/tasks/{args.task_id}/report")
    out = Path(args.out or f"task_{args.task_id}_report.html")
    with _client(timeout=60) as c:
        r = c.get(url)
        if r.status_code >= 400:
            print(r.text)
            return 1
        out.write_bytes(r.content)
        print(f"saved {out} ({len(r.content)} bytes)")
        return 0


def cmd_wait(args) -> int:
    terminal = {"completed", "failed", "cancelled"}
    url = urljoin(args.base.rstrip("/") + "/", f"api/tasks/{args.task_id}")
    deadline = time.time() + max(30, int(args.timeout))
    last = ""
    with _client() as c:
        while time.time() < deadline:
            r = c.get(url)
            if r.status_code >= 400:
                print(r.text)
                return 1
            data = r.json()
            status = data.get("status")
            prog = data.get("progress") or {}
            line = (
                f"status={status} files={prog.get('files')} "
                f"lines={prog.get('lines')} findings={prog.get('findings')} "
                f"report={data.get('report_ready')}"
            )
            if line != last:
                print(line, flush=True)
                last = line
            if status in terminal:
                return 0 if status == "completed" else 1
            time.sleep(max(2, int(args.interval)))
    print("timeout waiting for task", file=sys.stderr)
    return 2


def cmd_queue(args) -> int:
    url = urljoin(args.base.rstrip("/") + "/", f"api/tasks/{args.task_id}/queue")
    with _client() as c:
        r = c.get(url)
        print(json.dumps(r.json(), ensure_ascii=False, indent=2))
        return 0 if r.status_code == 200 else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="xinru Agent CLI")
    p.add_argument("--base", default=DEFAULT_BASE, help="Agent base URL")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("health")
    s.set_defaults(func=cmd_health)

    s = sub.add_parser("run")
    s.add_argument("--target", required=True)
    s.add_argument("--brief", default="exam unattended demo")
    s.add_argument("--credentials", default="")
    s.add_argument("--credentials-b", default="")
    s.add_argument("--cookies", default="")
    s.add_argument("--cookies-b", default="")
    s.add_argument("--token", default="")
    s.add_argument("--token-b", default="")
    s.add_argument("--subdomain", action="store_true")
    s.add_argument("--path-brute", action="store_true")
    s.add_argument("--allow-register", action="store_true")
    s.add_argument("--waf-authorized", action="store_true")
    s.add_argument("--wait", action="store_true")
    s.add_argument("--timeout", type=int, default=1800)
    s.add_argument("--interval", type=int, default=5)
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("status")
    s.add_argument("--task-id", type=int, required=True)
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("logs")
    s.add_argument("--task-id", type=int, required=True)
    s.add_argument("--tail", type=int, default=50)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("findings")
    s.add_argument("--task-id", type=int, required=True)
    s.set_defaults(func=cmd_findings)

    s = sub.add_parser("report")
    s.add_argument("--task-id", type=int, required=True)
    s.add_argument("--out", default="")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("wait")
    s.add_argument("--task-id", type=int, required=True)
    s.add_argument("--timeout", type=int, default=1800)
    s.add_argument("--interval", type=int, default=5)
    s.set_defaults(func=cmd_wait)

    s = sub.add_parser("queue")
    s.add_argument("--task-id", type=int, required=True)
    s.set_defaults(func=cmd_queue)

    args = p.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
