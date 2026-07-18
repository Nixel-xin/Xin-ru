"""xinru Agent — Web 层主入口 (FastAPI)

部署后提供:
1. 页面输入前置信息（目标 / A+B 认证 / 选项）
2. 实时进度（WebSocket + HTTP 日志轮询兜底）
3. 报告下载接口
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader

from orchestrator.graph import start_task, resume_task
from storage.models import Finding, HumanLoopRequest, ProgressLog, Task, init_db
from web.ws import ws_manager

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# 统一数据目录，兼容本地与容器
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data"))).resolve()
REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", str(BASE_DIR / "reports"))).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("DATA_DIR", str(DATA_DIR))

app = FastAPI(title="xinru Agent", version="0.2.0")
templates = Environment(loader=FileSystemLoader(str(BASE_DIR / "web" / "templates")))

# 后台任务句柄，避免被 GC
_RUNNING_TASKS: dict[int, asyncio.Task] = {}


def _report_path(task_id: int) -> Path:
    return REPORTS_DIR / f"task_{task_id}_report.html"


def _bool_form(value: str | bool | None, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _json_error(message: str, status_code: int = 400):
    return JSONResponse({"ok": False, "error": message}, status_code=status_code)


@app.on_event("startup")
async def startup():
    init_db()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _exam_mode() -> bool:
    return str(os.environ.get("EXAM_MODE", "")).strip().lower() in {"1", "true", "yes", "on"}


def _env_unattended() -> bool:
    return _exam_mode() or str(os.environ.get("XINRU_UNATTENDED", "")).strip().lower() in {"1", "true", "yes", "on"}


@app.get("/healthz")
async def healthz():
    return {
        "ok": True,
        "service": "xinru-agent",
        "exam_mode": _exam_mode(),
        "unattended": _env_unattended(),
        "data_dir": str(DATA_DIR),
        "reports_dir": str(REPORTS_DIR),
        "time": datetime.now().isoformat(),
    }


@app.get("/", response_class=HTMLResponse)
async def index():
    tmpl = templates.get_template("index.html")
    return tmpl.render()


@app.get("/api/tasks")
async def list_tasks(limit: int = 50):
    limit = max(1, min(int(limit or 50), 200))
    rows = list(Task.select().order_by(Task.id.desc()).limit(limit))
    return [t.to_dict() for t in rows]


@app.post("/api/tasks")
async def create_task(
    target: str = Form(...),
    brief: str = Form(""),
    credentials: str = Form(""),
    credentials_b: str = Form(""),
    cookies: str = Form(""),
    cookies_b: str = Form(""),
    token: str = Form(""),
    token_b: str = Form(""),
    accounts_json: str = Form(""),
    subdomain_discovery: str = Form("false"),
    path_brute: str = Form("false"),
    allow_register: str = Form("false"),
    allow_brute: str = Form("false"),
    unattended: str = Form("true"),
    waf_authorized: str = Form(""),
    yakit_export: UploadFile | None = File(None),
):
    """创建任务：一次性提交前置信息后无人值守运行。"""
    targets = [t.strip() for t in target.replace("\n", ",").split(",") if t.strip()]
    if not targets:
        return _json_error("请输入至少一个目标")

    accounts = None
    if accounts_json.strip():
        try:
            accounts = json.loads(accounts_json)
        except Exception:
            return _json_error("accounts_json 不是合法 JSON")

    # 考试/无人值守默认：EXAM_MODE 或 XINRU_UNATTENDED 时强制 unattended
    force_unattended = _env_unattended()
    config = {
        "brief": (brief or "").strip(),
        "credentials": credentials.strip(),
        "credentials_b": credentials_b.strip(),
        "cookies": cookies.strip(),
        "cookies_b": cookies_b.strip(),
        "token": token.strip(),
        "token_b": token_b.strip(),
        "subdomain_discovery": _bool_form(subdomain_discovery, False),
        "path_brute": _bool_form(path_brute, False),
        "allow_register": _bool_form(allow_register, False),
        "allow_brute": _bool_form(allow_brute, False),
        "unattended": True if force_unattended else _bool_form(unattended, True),
        "filter_leads_by_scope": False,
    }
    if str(waf_authorized or "").strip() != "":
        config["waf_authorized"] = _bool_form(waf_authorized, False)

    if isinstance(accounts, list) and accounts:
        config["accounts"] = accounts

    task = Task.create(
        target=json.dumps(targets, ensure_ascii=False),
        config=json.dumps(config, ensure_ascii=False),
        status="pending",
    )

    if yakit_export and yakit_export.filename:
        yakit_dir = DATA_DIR / "yakit_exports"
        yakit_dir.mkdir(parents=True, exist_ok=True)
        yakit_path = yakit_dir / f"task_{task.id}_{Path(yakit_export.filename).name}"
        content = await yakit_export.read()
        yakit_path.write_bytes(content)
        task.yakit_export_path = str(yakit_path)
        task.save()

    ProgressLog.create(
        task=task,
        message=(
            f"任务已创建 — 目标: {targets} | "
            f"账号A: {'有' if (config.get('credentials') or config.get('cookies') or config.get('token')) else '无'} | "
            f"账号B: {'有' if (config.get('credentials_b') or config.get('cookies_b') or config.get('token_b') or (isinstance(config.get('accounts'), list) and len(config.get('accounts') or []) >= 2)) else '无'} | "
            f"子域名: {config['subdomain_discovery']} | 路径爆破: {config['path_brute']} | WAF授权: {config.get('waf_authorized', 'auto')}"
        ),
        log_type="info",
    )
    if config.get("brief"):
        ProgressLog.create(task=task, message="📋 任务说明: " + config["brief"][:800], log_type="info")

    bg = asyncio.create_task(start_task(task.id))
    _RUNNING_TASKS[task.id] = bg

    def _cleanup(done: asyncio.Task, tid: int = task.id):
        _RUNNING_TASKS.pop(tid, None)

    bg.add_done_callback(_cleanup)
    return task.to_dict()


@app.get("/api/tasks/{task_id}")
async def get_task(task_id: int):
    try:
        task = Task.get_by_id(task_id)
    except Task.DoesNotExist:
        return _json_error("任务不存在", 404)
    data = task.to_dict()
    report = _report_path(task_id)
    data["report_ready"] = report.exists()
    data["report_url"] = f"/api/tasks/{task_id}/report" if report.exists() else None
    data["progress"] = {
        "files": task.total_files_collected,
        "lines": task.total_lines_audited,
        "findings": task.total_findings,
    }
    try:
        from orchestrator import workqueue as wq
        data["queue"] = wq.queue_stats(task_id)
        data["resume"] = wq.decide_resume_entry(task_id)
    except Exception:
        data["queue"] = None
        data["resume"] = None
    return data


@app.post("/api/tasks/{task_id}/pause")
async def pause_task_api(task_id: int, reason: str = Form("user_pause")):
    """协作式暂停：worker 停止领取新 WorkItem，当前威胁处理完后停下。"""
    try:
        task = Task.get_by_id(task_id)
    except Task.DoesNotExist:
        return _json_error("任务不存在", 404)
    if task.status == "completed":
        return _json_error("任务已完成", 400)
    if task.status == "cancelled":
        return _json_error("任务已取消", 400)

    from orchestrator import workqueue as wq
    paused = wq.request_pause(task_id, reason or "user_pause")
    try:
        await ws_manager.send_status_update(task_id, "paused", {"reason": paused.pause_reason})
    except Exception:
        pass
    return {
        "ok": True,
        "task_id": task_id,
        "status": paused.status,
        "phase": paused.phase,
        "pause_reason": paused.pause_reason,
        "queue": wq.queue_stats(task_id),
    }


@app.post("/api/tasks/{task_id}/resume")
async def resume_task_api(task_id: int):
    """恢复暂停/中断的任务，不重做已完成 WorkItem。"""
    try:
        task = Task.get_by_id(task_id)
    except Task.DoesNotExist:
        return _json_error("任务不存在", 404)

    if task.status == "completed":
        return _json_error("任务已完成", 400)
    # 若进程内仍在跑，只清 pause 标记让 worker 继续；否则重新拉起
    running = task_id in _RUNNING_TASKS and not _RUNNING_TASKS[task_id].done()
    from orchestrator import workqueue as wq
    if task.status == "paused":
        wq.resume_task_record(task_id, phase=task.phase or "auditing")

    if running:
        try:
            await ws_manager.send_status_update(task_id, task.phase or "auditing", {"resumed": True})
        except Exception:
            pass
        return {
            "ok": True,
            "task_id": task_id,
            "message": "pause cleared; workers will continue",
            "running": True,
            "queue": wq.queue_stats(task_id),
        }

    bg = asyncio.create_task(resume_task(task_id))
    _RUNNING_TASKS[task_id] = bg

    def _cleanup(done: asyncio.Task, tid: int = task_id):
        _RUNNING_TASKS.pop(tid, None)

    bg.add_done_callback(_cleanup)
    return {"ok": True, "task_id": task_id, "message": "resume started", "running": False}


@app.get("/api/tasks/{task_id}/queue")
async def get_task_queue(task_id: int):
    try:
        Task.get_by_id(task_id)
    except Task.DoesNotExist:
        return _json_error("任务不存在", 404)
    from orchestrator import workqueue as wq
    wq.reclaim_expired(task_id)
    return {
        "task_id": task_id,
        "queue": wq.queue_stats(task_id),
        "resume": wq.decide_resume_entry(task_id),
        "history": wq.workitem_history_summary(task_id),
    }


@app.get("/api/tasks/{task_id}/workitems")
async def get_task_workitems(
    task_id: int,
    status: str = "",
    item_type: str = "",
    limit: int = 100,
    offset: int = 0,
):
    """WorkItem 历史时间线（可恢复单元执行记录）。"""
    try:
        Task.get_by_id(task_id)
    except Task.DoesNotExist:
        return _json_error("任务不存在", 404)
    from orchestrator import workqueue as wq
    items = wq.list_work_items(
        task_id,
        status=(status or None),
        item_type=(item_type or None),
        limit=limit,
        offset=offset,
        order="updated_desc",
    )
    return {
        "task_id": task_id,
        "count": len(items),
        "queue": wq.queue_stats(task_id),
        "items": items,
    }


@app.get("/api/tasks/{task_id}/logs")
async def get_task_logs(task_id: int, limit: int = 200, offset: int = 0, after_id: int = 0):
    """进度日志。after_id>0 时只返回增量，方便前端轮询兜底。"""
    try:
        Task.get_by_id(task_id)
    except Task.DoesNotExist:
        return _json_error("任务不存在", 404)

    limit = max(1, min(int(limit or 200), 1000))
    offset = max(0, int(offset or 0))
    after_id = max(0, int(after_id or 0))

    query = ProgressLog.select().where(ProgressLog.task_id == task_id)
    if after_id:
        query = query.where(ProgressLog.id > after_id).order_by(ProgressLog.id.asc()).limit(limit)
        logs = list(query)
    else:
        logs = list(query.order_by(ProgressLog.id.desc()).limit(limit).offset(offset))
        logs = list(reversed(logs))
    return [log.to_dict() for log in logs]


@app.get("/api/tasks/{task_id}/findings")
async def get_task_findings(task_id: int):
    try:
        Task.get_by_id(task_id)
    except Task.DoesNotExist:
        return _json_error("任务不存在", 404)

    findings = (
        Finding.select()
        .where(Finding.task_id == task_id)
        .order_by(Finding.finding_number)
    )
    return [
        {
            "id": f.id,
            "finding_number": f.finding_number,
            "name": f.name,
            "severity": f.severity,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "call_chain": f.call_chain,
            "api_endpoint": f.api_endpoint,
            "parameters": f.parameters,
            "verdict": f.verdict,
            "yakit_evidence": f.yakit_evidence,
            "attack_impact": f.attack_impact,
            "fix_suggestion": f.fix_suggestion,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in findings
    ]


@app.get("/api/tasks/{task_id}/report")
async def download_report(task_id: int):
    """下载 HTML 报告。"""
    try:
        task = Task.get_by_id(task_id)
    except Task.DoesNotExist:
        return _json_error("任务不存在", 404)

    report_path = _report_path(task_id)
    if not report_path.exists():
        return _json_error("报告尚未生成，请等任务完成后再下载", 404)

    return FileResponse(
        path=str(report_path),
        filename=f"xinru_report_{task_id}.html",
        media_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "X-Task-Status": task.status,
        },
    )


@app.get("/api/tasks/{task_id}/report/status")
async def report_status(task_id: int):
    try:
        task = Task.get_by_id(task_id)
    except Task.DoesNotExist:
        return _json_error("任务不存在", 404)
    ready = _report_path(task_id).exists()
    return {
        "task_id": task_id,
        "status": task.status,
        "report_ready": ready,
        "report_url": f"/api/tasks/{task_id}/report" if ready else None,
        "total_findings": task.total_findings,
        "total_files_collected": task.total_files_collected,
        "total_lines_audited": task.total_lines_audited,
    }


@app.post("/api/human-loop/{loop_id}/respond")
async def respond_human_loop(loop_id: int, response: str = Form(...)):
    from orchestrator.human_loop import resolve_human_loop

    try:
        loop_req = HumanLoopRequest.get_by_id(loop_id)
    except HumanLoopRequest.DoesNotExist:
        return _json_error("请求不存在", 404)

    loop_req.response = response
    loop_req.status = "answered"
    loop_req.resolved_at = datetime.now()
    loop_req.save()
    await resolve_human_loop(loop_id, response)
    return {"ok": True}


@app.websocket("/ws/{task_id}")
async def websocket_endpoint(ws: WebSocket, task_id: int):
    await ws_manager.connect(task_id, ws)
    try:
        # 连接后先推送最近日志，避免刷新丢进度
        recent = list(
            ProgressLog.select()
            .where(ProgressLog.task_id == task_id)
            .order_by(ProgressLog.id.desc())
            .limit(30)
        )
        for log in reversed(recent):
            await ws.send_text(
                json.dumps(
                    {
                        "type": "progress",
                        "timestamp": datetime.now().isoformat(),
                        "data": {"message": log.message, "log_type": log.log_type},
                    },
                    ensure_ascii=False,
                )
            )

        report = _report_path(task_id)
        if report.exists():
            await ws.send_text(
                json.dumps(
                    {
                        "type": "report_ready",
                        "timestamp": datetime.now().isoformat(),
                        "data": {"report_path": f"/api/tasks/{task_id}/report"},
                    },
                    ensure_ascii=False,
                )
            )

        while True:
            data = await ws.receive_text()
            try:
                msg = json.loads(data)
            except Exception:
                continue
            if msg.get("type") == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        await ws_manager.disconnect(task_id, ws)
    except Exception:
        await ws_manager.disconnect(task_id, ws)
