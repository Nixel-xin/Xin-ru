# xinru Agent

全自动前端/JS 源码安全审计 Agent。  
从目标触发 → 信息收集 → 认证预获取 → 多 Agent 审计 → 威胁验证 → HTML 报告，**全程无人值守闭环**。

> 实战考试交付：可在 **agent-compose** 上运行，并可用 CLI 直接调用。

## 核心能力

- **无人值守闭环**：`EXAM_MODE=1` / `XINRU_UNATTENDED=1` 下不等人、不卡 captcha/人工确认
- **可恢复执行**：`WorkItem` 队列（audit_file / handle_threat / verify_endpoint），LLM 挂掉可 pause/resume，不重做已完成单元
- **多 Agent 审计**：文件级并行 + 威胁处理 + 端点验证
- **报告产出**：`/api/tasks/{id}/report` 下载 HTML

## 快速启动（agent-compose / docker）

```bash
cp .env.example .env
# 必填：OPENAI_API_KEY（或 ANTHROPIC_AUTH_TOKEN）
# 建议：EXAM_MODE=1  XINRU_UNATTENDED=1

# 优先 agent-compose（考试平台）
agent-compose -f agent-compose.yaml up -d --build

# 或 docker compose
docker compose -f docker-compose.yaml up -d --build

# 或脚本兜底
./scripts/up.sh
```

服务：`http://127.0.0.1:8000`  
健康检查：`GET /healthz`（返回 `exam_mode` / `unattended`）

## CLI 调用（agent-compose 评估建议走这条）

```bash
export XINRU_BASE_URL=http://127.0.0.1:8000

./venv/bin/python cli.py health

# 创建无人值守任务
./venv/bin/python cli.py run --target https://example.com --brief "exam demo"

# 等待闭环完成并拉报告
./venv/bin/python cli.py wait --task-id <id> --timeout 1800
./venv/bin/python cli.py status --task-id <id>
./venv/bin/python cli.py logs --task-id <id> --tail 50
./venv/bin/python cli.py findings --task-id <id>
./venv/bin/python cli.py report --task-id <id> --out /tmp/xinru_report.html
./venv/bin/python cli.py queue --task-id <id>
```

一键创建并等待：

```bash
./venv/bin/python cli.py run --target https://example.com --brief "exam closed-loop" --wait --timeout 1800
```

## 自测（务必自己跑一遍）

```bash
./scripts/up.sh
./scripts/verify_exam.sh
```

`verify_exam.sh` 会：
1. 打 `/healthz`
2. 创建 `unattended=true` 任务
3. 轮询状态 / 日志
4. 用 `cli.py health` 验证 CLI 可调用

完整闭环（需可用 LLM Key）：

```bash
./venv/bin/python cli.py run --target https://example.com --brief "exam full" --wait --timeout 1800
./venv/bin/python cli.py report --task-id <id> --out ./reports/exam_report.html
```

## 无人值守保证

| 场景 | 行为 |
|------|------|
| captcha / 人工输入 | 自动 skip，不阻塞 |
| 危险操作确认 | 自动 deny |
| Cookie/账号缺失 | 继续匿名审计，不等人 |
| LLM 超时/连不上 | 重试 → 熔断 pause；`resume` 从 WorkItem 队列续跑 |
| 进程重启 | `POST /api/tasks/{id}/resume` 或 `run_resume_task.py` |

环境变量：

```bash
EXAM_MODE=1
XINRU_UNATTENDED=1
XINRU_WORKERS=2
XINRU_LLM_MAX_RETRIES=5
```

创建任务时 `cli.py` / 表单默认 `unattended=true`；`EXAM_MODE` 下服务端强制开启。

## 本地开发（非容器）

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
export DATA_DIR=./data REPORTS_DIR=./reports DATABASE_PATH=./data/xinru.db
export EXAM_MODE=1 XINRU_UNATTENDED=1
uvicorn web.main:app --host 0.0.0.0 --port 8000
```

## 主要 API

| Method | Path | 说明 |
|--------|------|------|
| GET | `/healthz` | 健康检查 |
| POST | `/api/tasks` | 创建任务（multipart form） |
| GET | `/api/tasks/{id}` | 状态 + progress + report_ready |
| GET | `/api/tasks/{id}/logs` | 进度日志 |
| GET | `/api/tasks/{id}/findings` | 发现列表 |
| GET | `/api/tasks/{id}/report` | HTML 报告 |
| POST | `/api/tasks/{id}/pause` | 协作暂停 |
| POST | `/api/tasks/{id}/resume` | 恢复 |
| GET | `/api/tasks/{id}/queue` | WorkItem 队列统计 |
| WS | `/ws/{id}` | 实时进度 |

## 目录结构

```
agent/
  agent-compose.yaml   # 考试部署（同 docker-compose.yaml）
  cli.py               # 外部调用入口
  Dockerfile
  orchestrator/        # LangGraph + WorkItem 恢复
  auditor/             # 多 Agent 审计
  collector/           # 源码/站点收集
  reporter/            # HTML 报告
  web/                 # FastAPI + UI
  scripts/up.sh
  scripts/verify_exam.sh
```

## 恢复进度（LLM 挂了也不丢）

```bash
./venv/bin/python run_resume_task.py <task_id> --status-only
./venv/bin/python run_resume_task.py <task_id> --history
./venv/bin/python run_resume_task.py <task_id>          # resume
./venv/bin/python run_resume_task.py <task_id> --pause
```



## 考试验收（必须自己跑）

> 平台要求：Agent 必须在 **agent-compose** 上运行，且可被 CLI 正常调用。  
> **不要只信 AI 文字**，按下面命令亲自验收，把输出截图/日志留下。

### A. agent-compose 拉起

```bash
cp .env.example .env   # 填 LLM Key
agent-compose -f agent-compose.yaml up -d --build
agent-compose -f agent-compose.yaml ps
# 期望: xinru-agent ... Up ... (healthy)
```

### B. 健康检查

```bash
curl -fsS http://127.0.0.1:8000/healthz
# 期望包含: "ok": true, "exam_mode": true, "unattended": true
```

### C. CLI 调用（两种都行）

```bash
# 1) 宿主机 CLI（无 urllib 回退，无需 venv）
python3 cli.py --base http://127.0.0.1:8000 health

# 2) 经 agent-compose 容器调用（推荐，和运行环境一致）
./scripts/agent_cli.sh health
./scripts/agent_cli.sh run --target https://example.com --brief "exam demo"
./scripts/agent_cli.sh wait --task-id <id> --timeout 1800
./scripts/agent_cli.sh report --task-id <id> --out /tmp/xinru_report.html
```

### D. 一键自检脚本

```bash
./scripts/verify_exam.sh
# 期望最后一行: VERIFY_BASIC_OK task_id=...
```

### E. 无人值守闭环抽检

```bash
./scripts/agent_cli.sh run --target https://example.com --brief "closed-loop" --wait --timeout 1800
./scripts/agent_cli.sh status --task-id <id>
# 期望 status=completed 且 report_ready=true（或至少进入 collecting/auditing 后无人工卡点）
```

### 本机已验证记录（部署机）

在 `ubuntu@43.162.126.132:/home/ubuntu/Xin-ru` 实测过：

```text
agent-compose -f agent-compose.yaml ps
# xinru-agent ... Up (healthy)  127.0.0.1:8000->8000/tcp

curl -fsS http://127.0.0.1:8000/healthz
# {"ok":true,"service":"xinru-agent","exam_mode":true,"unattended":true,...}

docker exec xinru-agent python /app/cli.py --base http://127.0.0.1:8000 health
# {"ok":true,...}
```

安全说明：生产/共享 VPS 上端口绑定为 `127.0.0.1:8000`，评估请用 SSH 隧道，勿公网裸奔。

```bash
ssh -L 8000:127.0.0.1:8000 ubuntu@<host>
curl -fsS http://127.0.0.1:8000/healthz
```

## 提交检查清单（考试）

- [ ] GitLab FDE 仓库可访问（不含 `.env` / `*.db` / `venv`）
- [ ] Devbox 上服务运行：`curl http://<host>:8000/healthz`
- [ ] `agent-compose -f agent-compose.yaml up -d --build` 可起
- [ ] `./venv/bin/python cli.py health` / `run` / `wait` / `report` 可走通
- [ ] 任务从触发到报告**无人接管**
- [ ] README 验证步骤自己跑过（避免 AI 评估幻觉）

## 注意事项

- 仅用于**授权**目标
- 需要可用的 OpenAI-compatible / Anthropic LLM Key
- 大型目标建议 `XINRU_WORKERS=2~3`，并预留磁盘给 `data/` 与 `reports/`
