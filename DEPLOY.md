# 部署说明

完整考试交付与验证步骤见 [README.md](./README.md)。

# 服务器部署

## 一键启动
```bash
cp .env.example .env
# 编辑 .env 填入 OPENAI_API_KEY 等
docker compose up -d --build
```

访问：`http://服务器IP:8000`

## 页面能力
1. 输入前置信息：目标、任务说明、A/B Cookie+账号密码、收集选项
2. 实时进度：WebSocket 推送 + HTTP 日志轮询兜底
3. 报告下载：任务完成后按钮/接口 `/api/tasks/{id}/report`

## 关键接口
- `GET /healthz`
- `POST /api/tasks` 创建任务（multipart form）
- `GET /api/tasks` 任务列表
- `GET /api/tasks/{id}` 任务状态（含 report_ready）
- `GET /api/tasks/{id}/logs?after_id=` 进度日志
- `GET /api/tasks/{id}/findings`
- `GET /api/tasks/{id}/report` 下载 HTML 报告
- `WS /ws/{id}` 实时进度

## 本地不容器启动
```bash
cd agent
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export DATA_DIR=./data REPORTS_DIR=./reports DATABASE_PATH=./data/xinru.db
uvicorn web.main:app --host 0.0.0.0 --port 8000
```


## 乌云对照（wooyun-legacy）
Agent 自检阶段会加载 `wooyun-legacy` skill 做定级锚点：
- 默认路径：`~/.codex/skills/wooyun-legacy`
- 可通过环境变量 `WOOYUN_SKILL_DIR` 指定
- 作用：抑制“静态资源 200 = 高危”等误报，并在结论中写入乌云领域对照

## 暂停 / 恢复（WorkItem 可恢复调度）
- `POST /api/tasks/{id}/pause` 协作式暂停（当前威胁处理完后停下，进度保留）
- `POST /api/tasks/{id}/resume` 恢复；不重做已完成 `audit_file/handle_threat/verify_endpoint`
- `GET /api/tasks/{id}/queue` 查看队列与 resume 决策

CLI:
```bash
./venv/bin/python run_resume_task.py <task_id> --status-only
./venv/bin/python run_resume_task.py <task_id> --pause
./venv/bin/python run_resume_task.py <task_id>
```
- 历史：`./venv/bin/python run_resume_task.py <task_id> --history`
- API：`GET /api/tasks/{id}/workitems`
