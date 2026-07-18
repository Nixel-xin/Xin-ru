"""Human-in-the-loop 交互管理

考试/无人值守模式 (EXAM_MODE=1 或 unattended=true) 下：
- 不创建等待事件
- 不阻塞编排流程
- 直接返回安全默认值，保证端到端可托管
"""

from __future__ import annotations

import asyncio
import json
import os

from storage.models import HumanLoopRequest, Task
from web.ws import ws_manager

# task_id → {loop_id: Event}
_pause_events: dict[int, dict[int, asyncio.Event]] = {}


def _truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v or "").strip().lower() in {"1", "true", "yes", "on"}


def is_unattended(task_id: int | None = None, config: dict | None = None) -> bool:
    """考试强制无人值守，或任务配置 unattended=true。"""
    if _truthy(os.environ.get("EXAM_MODE")) or _truthy(os.environ.get("XINRU_UNATTENDED")):
        return True
    if config is not None:
        return _truthy(config.get("unattended", True))
    if task_id:
        try:
            cfg = Task.get_by_id(task_id).get_config() or {}
            return _truthy(cfg.get("unattended", True))
        except Exception:
            return True
    return True


async def create_human_loop(
    task_id: int,
    request_type: str,
    message: str,
    options: list[str] | None = None,
    image_path: str | None = None,
    *,
    auto_response: str | None = None,
) -> HumanLoopRequest:
    """创建 human-loop 请求。

    无人值守：直接 resolved，不 await。
    有人值守：推送前端并等待回复。
    """
    unattended = is_unattended(task_id)
    if unattended and auto_response is None:
        # 默认安全回落
        defaults = {
            "danger_confirm": "拒绝，跳过此操作",
            "captcha": "",
            "ask_credentials": "跳过",
            "ask_cookie": "跳过",
        }
        auto_response = defaults.get(request_type, "跳过")

    loop_req = HumanLoopRequest.create(
        task_id=task_id,
        request_type=request_type,
        message=message,
        options=json.dumps(options, ensure_ascii=False) if options else None,
        image_path=image_path,
        status="answered" if unattended else "pending",
        response=auto_response if unattended else None,
    )

    if unattended:
        try:
            from storage.models import ProgressLog
            ProgressLog.create(
                task=task_id,
                message=f"🤖 无人值守自动处理 human-loop[{request_type}]: {auto_response or '(空)'}",
                log_type="info",
            )
        except Exception:
            pass
        return loop_req

    await ws_manager.send_human_loop(task_id, loop_req.to_dict())
    await ws_manager.send_status_update(task_id, "paused")

    event = asyncio.Event()
    _pause_events.setdefault(task_id, {})[loop_req.id] = event
    await event.wait()
    return HumanLoopRequest.get_by_id(loop_req.id)


async def resolve_human_loop(loop_id: int, response: str):
    loop_req = HumanLoopRequest.get_by_id(loop_id)
    task_id = loop_req.task_id
    loop_req.response = response
    loop_req.status = "answered"
    loop_req.save()
    if task_id in _pause_events and loop_id in _pause_events[task_id]:
        _pause_events[task_id][loop_id].set()
        del _pause_events[task_id][loop_id]


async def confirm_dangerous_operation(task_id: int, operation: str, details: str) -> bool:
    """危险操作确认。无人值守默认拒绝（安全优先，不阻塞）。"""
    if is_unattended(task_id):
        try:
            from storage.models import ProgressLog
            ProgressLog.create(
                task=task_id,
                message=f"🤖 无人值守跳过危险操作: {operation}",
                log_type="warning",
            )
        except Exception:
            pass
        return False
    loop_req = await create_human_loop(
        task_id=task_id,
        request_type="danger_confirm",
        message=f"⚠️ 检测到危险操作：{operation}\n\n{details}\n\n是否继续？",
        options=["批准，继续执行", "拒绝，跳过此操作"],
    )
    return "批准" in (loop_req.response or "")


async def ask_captcha(task_id: int, image_path: str) -> str:
    """验证码。无人值守返回空，让上层走 OCR/失败降级。"""
    loop_req = await create_human_loop(
        task_id=task_id,
        request_type="captcha",
        message="请输入验证码（截图已保存）",
        image_path=image_path,
        auto_response="",
    )
    return (loop_req.response or "").strip()


async def ask_credentials(task_id: int, target: str) -> str | None:
    loop_req = await create_human_loop(
        task_id=task_id,
        request_type="ask_credentials",
        message=f"需要账号密码登录: {target}\n请回复 user:pass，或'跳过'",
        options=["跳过"],
        auto_response="跳过",
    )
    resp = (loop_req.response or "").strip()
    if not resp or resp == "跳过":
        return None
    return resp


async def ask_cookie(task_id: int, reason: str) -> str | None:
    loop_req = await create_human_loop(
        task_id=task_id,
        request_type="ask_cookie",
        message=f"自动登录失败：{reason}\n请粘贴 Cookie，或回复'跳过'",
        options=["跳过"],
        auto_response="跳过",
    )
    resp = (loop_req.response or "").strip()
    if not resp or resp == "跳过":
        return None
    return resp
