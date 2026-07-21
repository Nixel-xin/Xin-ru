# xinru Agent

全自动前端 / JS 源码安全审计 Agent。

输入目标后自动完成：

**信息收集 → 认证预获取 → 多 Agent 源码审计 → 威胁验证 → HTML 报告**

全程无人值守闭环，支持 LLM 故障后的 WorkItem 级恢复。

> 实战考试交付要求：必须可在 **agent-compose** 上运行，并可用 CLI 正常调用。  
> README 验证步骤请本人实跑，AI 评估会有幻觉。

## 架构

采用 **FastAPI 服务 + LangGraph 编排 + WorkItem 队列**。

```text
agent-compose up
        │
        ▼
  web/main.py  (FastAPI :8000)
        │
        ├─ POST /api/tasks          创建任务
        ├─ GET  /api/tasks/{id}     状态/进度
        ├─ GET  /api/tasks/{id}/report
        └─ CLI  cli.py / scripts/agent_cli.sh
                │
                ▼
        orchestrator/graph.py
          info_gather
            → source_collect
            → auth_acquire
            → setup_audit
            → multi_agent_audit
            → (supplement | attack_chain | paused)
            → report
```

核心组件：

| 模块 | 职责 |
|------|------|
| `collector/` | 站点/源码收集：spider、sourcemap、git leak、路径爆破、LLM 资产提取 |
| `orchestrator/` | 任务编排、human-loop 无人值守、WorkItem 恢复队列 |
| `auditor/` | 多 Agent 审计、调用链追溯、端点定位、自检、乌云对照 |
| `yakit/` | 验证器（可接 Yakit MCP） |
| `reporter/` | HTML 报告生成 |
| `web/` | API / WebUI / WebSocket 进度 |
| `cli.py` | 外部调用入口（health/run/status/wait/report） |

任一步进入 `paused`（如 LLM 熔断）不会丢进度；恢复后跳过已 `done` 的 WorkItem。

## 目录结构

```text
.
├── agent-compose.yaml         # 考试部署编排（推荐）
├── docker-compose.yaml        # docker compose 兼容
├── Dockerfile
├── requirements.txt
├── cli.py                     # 宿主机 CLI
├── .env.example
├── scripts/
│   ├── up.sh                  # 一键启动（agent-compose / docker / uvicorn 兜底）
│   ├── verify_exam.sh         # 考试验收脚本（必须亲自跑）
│   └── agent_cli.sh           # 经 agent-compose 容器调用 CLI
├── orchestrator/
│   ├── graph.py               # 主流程
│   ├── workqueue.py           # 可恢复 WorkItem
│   ├── human_loop.py          # 考试模式自动跳过人工确认
│   └── llm.py
├── collector/                 # 源码/资产收集
├── auditor/                   # 多 Agent 审计
├── reporter/                  # HTML 报告
├── storage/                   # SQLite 模型
├── web/                       # FastAPI + 模板
├── yakit/                     # 验证适配
├── data/                      # 运行时数据（gitignore）
└── reports/                   # 报告输出（gitignore）
```

## 环境要求

| 依赖 | 版本/说明 | 用途 |
|------|-----------|------|
| Python | 3.10+（容器内 3.11） | 运行服务与 CLI |
| Docker / docker-compose | — | 镜像构建与运行 |
| agent-compose | — | 考试平台编排入口（兼容 docker-compose CLI） |
| LLM API | OpenAI-compatible 或 Anthropic | 审计/提取/自检 |
| Playwright Chromium | 镜像内安装 | 浏览器收集（可选路径） |

## 安装

### 容器方式（推荐，考试）

```bash
cp .env.example .env
# 编辑 .env，至少填 OPENAI_API_KEY（或 ANTHROPIC_AUTH_TOKEN）

agent-compose -f agent-compose.yaml up -d --build
# 若无 agent-compose：
# docker compose -f docker-compose.yaml up -d --build
```

### 本地开发（非容器）

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
playwright install chromium

export DATA_DIR=./data
export REPORTS_DIR=./reports
export DATABASE_PATH=./data/xinru.db
export EXAM_MODE=1
export XINRU_UNATTENDED=1

uvicorn web.main:app --host 127.0.0.1 --port 8000
```

## 配置

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `LLM_PROVIDER` | `openai` | `openai` / `anthropic` |
| `LLM_MODEL` | `grok-4.5` | 模型名 |
| `OPENAI_BASE_URL` | — | OpenAI-compatible Base URL |
| `OPENAI_API_KEY` | — | **必填（openai 模式）** |
| `ANTHROPIC_AUTH_TOKEN` | — | anthropic 模式 token |
| `ANTHROPIC_BASE_URL` | — | anthropic 网关 |
| `ANTHROPIC_MODEL` | — | anthropic 模型 |
| `LLM_TIMEOUT` | `120` | 单次 LLM 超时秒 |
| `EXAM_MODE` | `1`（compose 默认） | 考试强制无人值守 |
| `XINRU_UNATTENDED` | `1` | 不等人、不卡 captcha/人工确认 |
| `XINRU_WORKERS` | `2` | 审计 worker 数 |
| `XINRU_LLM_MAX_RETRIES` | `5` | LLM 重试上限 |
| `XINRU_WORKITEM_LEASE_SEC` | `180` | WorkItem 租约秒 |
| `XINRU_WORKITEM_MAX_ATTEMPTS` | `5` | 单 WorkItem 最大尝试 |
| `DATABASE_PATH` | `/app/data/xinru.db` | SQLite 路径 |
| `DATA_DIR` | `/app/data` | 收集数据目录 |
| `REPORTS_DIR` | `/app/reports` | 报告目录 |
| `YAKIT_MCP_URL` | — | 可选 Yakit MCP |
| `WOOYUN_SKILL_DIR` | `~/.codex/skills/wooyun-legacy` | 乌云对照知识库 |
| `XINRU_BASE_URL` | `http://127.0.0.1:8000` | CLI 默认服务地址 |

### agent-compose 注意事项

1. **端口默认只绑本机**：`127.0.0.1:8000:8000`  
   - 好处：不公网裸奔  
   - 访问：服务器本机直接 `curl 127.0.0.1:8000`，或本机 SSH 隧道
2. compose 环境变量请在 `.env` 写字面量，不要依赖未展开的 `${VAR:-default}` 占位（部分编排器不会做 bash 默认值展开）。
3. 密钥只放服务器 `.env`，**不要提交 git**。

SSH 隧道示例：

```bash
ssh -L 8000:127.0.0.1:8000 ubuntu@<host>
# 然后浏览器打开 http://127.0.0.1:8000/
```

## 使用方式

### 方式一：agent-compose + CLI（考试推荐）

```bash
# 启动
agent-compose -f agent-compose.yaml up -d --build
agent-compose -f agent-compose.yaml ps

# 健康检查
curl -fsS http://127.0.0.1:8000/healthz

# 经容器调用 CLI（与运行环境一致）
./scripts/agent_cli.sh health
./scripts/agent_cli.sh run --target https://example.com --brief "exam demo"
./scripts/agent_cli.sh wait --task-id <id> --timeout 1800
./scripts/agent_cli.sh status --task-id <id>
./scripts/agent_cli.sh logs --task-id <id> --tail 50
./scripts/agent_cli.sh findings --task-id <id>
./scripts/agent_cli.sh report --task-id <id> --out /tmp/xinru_report.html
./scripts/agent_cli.sh queue --task-id <id>
```

一键创建并等待闭环：

```bash
./scripts/agent_cli.sh run --target https://example.com --brief "closed-loop" --wait --timeout 1800
```

### 方式二：宿主机 CLI

```bash
export XINRU_BASE_URL=http://127.0.0.1:8000
python3 cli.py health
python3 cli.py run --target https://example.com --brief "demo" --wait --timeout 1800
python3 cli.py report --task-id <id> --out ./reports/exam_report.html
```

> `cli.py` 优先用 `httpx`，没有时自动回退到标准库 `urllib`，宿主机无 venv 也能做基础调用。

### 方式三：HTTP API / WebUI

```bash
# 创建任务
curl -fsS -X POST http://127.0.0.1:8000/api/tasks \
  -F "target=https://example.com" \
  -F "brief=exam verify unattended" \
  -F "unattended=true" \
  -F "subdomain_discovery=false" \
  -F "path_brute=false"

# 查状态
curl -fsS http://127.0.0.1:8000/api/tasks/1

# 下载报告
curl -fsS -o report.html http://127.0.0.1:8000/api/tasks/1/report
```

浏览器：`http://127.0.0.1:8000/`

### 方式四：暂停 / 恢复（LLM 挂了也不丢进度）

```bash
# API
curl -X POST http://127.0.0.1:8000/api/tasks/<id>/pause
curl -X POST http://127.0.0.1:8000/api/tasks/<id>/resume
curl -fsS http://127.0.0.1:8000/api/tasks/<id>/queue

# 脚本
./venv/bin/python run_resume_task.py <id> --status-only
./venv/bin/python run_resume_task.py <id> --history
./venv/bin/python run_resume_task.py <id>
```

## 考试验收（必须自己跑）

平台硬性要求：

1. Agent 运行在 **agent-compose** 上  
2. 可被 CLI 正常调用  
3. 从触发到产出闭环，**无人接管**

### A. 编排状态

```bash
cd /path/to/Xin-ru
agent-compose -f agent-compose.yaml ps
# 期望: xinru-agent ... Up ... (healthy)
```

### B. 健康检查

```bash
curl -fsS http://127.0.0.1:8000/healthz
# 期望包含:
#   "ok": true
#   "exam_mode": true
#   "unattended": true
```

### C. CLI 双通道

```bash
python3 cli.py --base http://127.0.0.1:8000 health
./scripts/agent_cli.sh health
```

### D. 一键脚本

```bash
./scripts/verify_exam.sh
# 期望最后输出: VERIFY_BASIC_OK task_id=...
```

`verify_exam.sh` 会检查：

1. `agent-compose ps` / 容器状态  
2. `/healthz`  
3. 创建 `unattended=true` 任务  
4. 轮询状态与日志  
5. 宿主机 CLI + 容器 CLI

### E. 闭环抽检

```bash
./scripts/agent_cli.sh run --target https://example.com --brief "exam closed-loop" --wait --timeout 1800
./scripts/agent_cli.sh status --task-id <id>
# 期望 status=completed 且 report_ready=true
# 至少应自动进入 collecting/auditing，不出现人工确认卡死
```

### 本机已验证记录（部署机）

在 `ubuntu@43.162.126.132:/home/ubuntu/Xin-ru` 实测：

```text
agent-compose -f agent-compose.yaml ps
# xinru-agent ... Up (healthy)  127.0.0.1:8000->8000/tcp

curl -fsS http://127.0.0.1:8000/healthz
# {"ok":true,"exam_mode":true,"unattended":true,...}

python3 cli.py --base http://127.0.0.1:8000 health
./scripts/agent_cli.sh health
./scripts/verify_exam.sh
# VERIFY_BASIC_OK
```

## 主要 API

| Method | Path | 说明 |
|--------|------|------|
| GET | `/healthz` | 健康检查（含 exam_mode/unattended） |
| POST | `/api/tasks` | 创建任务（multipart form） |
| GET | `/api/tasks` | 任务列表 |
| GET | `/api/tasks/{id}` | 状态 + progress + report_ready |
| GET | `/api/tasks/{id}/logs` | 进度日志 |
| GET | `/api/tasks/{id}/findings` | 发现列表 |
| GET | `/api/tasks/{id}/report` | 下载 HTML 报告 |
| POST | `/api/tasks/{id}/pause` | 协作暂停 |
| POST | `/api/tasks/{id}/resume` | 恢复 |
| GET | `/api/tasks/{id}/queue` | WorkItem 队列统计 |
| GET | `/api/tasks/{id}/workitems` | WorkItem 明细 |
| WS | `/ws/{id}` | 实时进度 |

## 无人值守行为

| 场景 | 行为 |
|------|------|
| captcha / 人工输入 | 自动 skip，不阻塞 |
| 危险操作确认 | 自动 deny |
| Cookie/账号缺失 | 继续匿名审计，不等人 |
| LLM 超时/连不上 | 重试 → 熔断 pause → resume 续跑 |
| 进程重启 | `resume` / `run_resume_task.py` 从队列续跑 |

`EXAM_MODE=1` 时，即使请求里 `unattended=false`，服务端也会强制无人值守。

## 输出物

| 路径/接口 | 内容 |
|-----------|------|
| `GET /api/tasks/{id}/report` | HTML 漏洞报告 |
| `reports/task_{id}_report.html` | 容器/本机落盘报告 |
| `data/collected/task_{id}/` | 收集到的源码与资产 |
| `GET /api/tasks/{id}/findings` | 结构化发现 JSON |
| `GET /api/tasks/{id}/logs` | 执行日志 |

## 提交检查清单（考试）

- [ ] GitLab/GitHub 仓库可访问（不含 `.env` / `*.db` / `venv` / `data`）
- [ ] Devbox/服务器可登录
- [ ] `agent-compose -f agent-compose.yaml up -d --build` 可起
- [ ] `agent-compose -f agent-compose.yaml ps` 显示 healthy
- [ ] `./scripts/agent_cli.sh health` 与 `python3 cli.py health` 可走通
- [ ] `./scripts/verify_exam.sh` 输出 `VERIFY_BASIC_OK`
- [ ] 任务从触发到报告**无人接管**
- [ ] 以上命令**本人实跑**过（避免 AI 评估幻觉）

### 评估平台建议填写

```text
代码仓库: https://github.com/Nixel-xin/Xin-ru
SSH: ssh ubuntu@<host>
目录: /home/ubuntu/Xin-ru
启动: cd /home/ubuntu/Xin-ru && sudo agent-compose -f agent-compose.yaml up -d
服务: http://127.0.0.1:8000  （仅本机；公网请用 SSH 隧道）
验证:
  curl -fsS http://127.0.0.1:8000/healthz
  ./scripts/agent_cli.sh health
  ./scripts/verify_exam.sh
```

## 安全说明

- 仅用于**授权**目标
- 默认不把 Agent 端口裸奔公网
- `.env`、数据库、报告、收集数据均已在 `.gitignore`
- 大型目标建议 `XINRU_WORKERS=1~3`，并预留磁盘给 `data/` / `reports/`

## 常见问题

**Q: `agent-compose` 找不到？**  
A: 考试平台一般自带；本地可用 `docker compose -f docker-compose.yaml` 或仓库内 shim（`scripts/up.sh` 会自动兜底）。

**Q: 公网打不开 `:8000`？**  
A: 默认绑定 `127.0.0.1:8000`。登录服务器访问本机，或：

```bash
ssh -L 8000:127.0.0.1:8000 user@host
```

**Q: 宿主机 `cli.py` 报缺少 httpx？**  
A: 已支持 urllib 回退；或用 `./scripts/agent_cli.sh` 走容器内依赖。

**Q: LLM 中途挂了怎么办？**  
A: 任务会 pause，进度在 WorkItem 队列；`resume` 后不重做已完成单元。
