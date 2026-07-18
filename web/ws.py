"""WebSocket 管理器 — Agent ↔ 前端双向实时推送"""

import json
import asyncio
from datetime import datetime
from typing import Optional
from fastapi import WebSocket


class WSManager:
    """WebSocket 连接管理器"""

    def __init__(self):
        # task_id → set of WebSocket connections
        self._connections: dict[int, set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, task_id: int, ws: WebSocket):
        """建立 WebSocket 连接"""
        await ws.accept()
        async with self._lock:
            if task_id not in self._connections:
                self._connections[task_id] = set()
            self._connections[task_id].add(ws)

    async def disconnect(self, task_id: int, ws: WebSocket):
        """断开 WebSocket 连接"""
        async with self._lock:
            if task_id in self._connections:
                self._connections[task_id].discard(ws)
                if not self._connections[task_id]:
                    del self._connections[task_id]

    async def send_message(self, task_id: int, msg_type: str, data: dict):
        """向指定任务的所有连接推送消息"""
        async with self._lock:
            connections = self._connections.get(task_id, set())
            if not connections:
                return

        payload = json.dumps({
            "type": msg_type,
            "timestamp": datetime.now().isoformat(),
            "data": data,
        }, ensure_ascii=False)

        dead: list[WebSocket] = []
        for ws in connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.get(task_id, set()).discard(ws)

    async def send_progress(self, task_id: int, message: str, log_type: str = "info"):
        """推送进度日志"""
        await self.send_message(task_id, "progress", {
            "message": message,
            "log_type": log_type,
        })

    async def send_status_update(self, task_id: int, status: str, extra: dict | None = None):
        """推送任务状态更新"""
        data = {"status": status}
        if extra:
            data.update(extra)
        await self.send_message(task_id, "status_update", data)

    async def send_human_loop(self, task_id: int, loop_request: dict):
        """推送 human-in-the-loop 请求"""
        await self.send_message(task_id, "human_loop", loop_request)

    async def send_discovery(self, task_id: int, finding: dict):
        """推送新发现的漏洞"""
        await self.send_message(task_id, "discovery", finding)

    async def send_report_ready(self, task_id: int, report_path: str):
        """推送报告完成通知"""
        await self.send_message(task_id, "report_ready", {"report_path": report_path})


# 全局单例
ws_manager = WSManager()
