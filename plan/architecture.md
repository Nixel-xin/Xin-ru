# xinru Agent 架构规划

## 一、Agent 核心定义

将 xinru 从一个 Claude Code Skill 改造为**独立运行的自主渗透测试 Agent**。

**一句话描述：** 给定一个 URL/域名，Agent 自主完成「拿源码 → 逐行审计 → 追溯调用链 → 验证漏洞 → 出报告」全流程，仅在人机交互点（危险操作确认、验证码输入等）暂停等待输入。

---

## 二、技术选型

| 层 | 选型 | 理由 |
|---|---|---|
| 语言 | **Python 3.11+** | LLM SDK 最成熟，安全工具链最全，Playwright/beautifulsoup4 生态好 |
| Web 框架 | **FastAPI** | WebSocket 原生支持，异步性能好，适合长连接对话 |
| LLM 编排 | **LangGraph** | 状态图比 LangChain Chain 更适合有分支/循环/暂停的复杂 Agent 流程 |
| 前端 | **Jinja2 模板 + 原生 JS** | 零依赖，轻量，聊天框 + 任务面板就够了 |
| 浏览器自动化 | **Playwright for Python** | 翻页登录、验证码截图、JS bundle 拦截，一站式 |
| 容器化 | **agent-compose / docker-compose** | 考核必选项 |
| 持久化 | **SQLite + 文件系统** | 进度状态、已发现漏洞、任务日志 |

---

## 三、总体架构

```
                        ┌──────────────────────────────┐
 浏览器                  │          Web 聊天界面          │
 http://agent:8000 ────▶│  FastAPI + Jinja2 + WebSocket │
                        │  ┌──────────────────────────┐ │
                        │  │   聊天面板  │  任务面板     │ │
                        │  │  Agent消息  │  进度+发现    │ │
                        │  │  人工输入   │              │ │
                        │  └────────────┴──────────────┘ │
                        └──────────────┬───────────────┘
                                       │
                        ┌──────────────▼───────────────┐
                        │       编排引擎 (Orchestrator)  │
                        │  ┌──────────────────────────┐ │
                        │  │  LangGraph StateGraph    │ │
                        │  │                          │ │
                        │  │  状态节点:                │ │
                        │  │  1. 信息收集              │ │
                        │  │  2. 源码全量收集           │ │
                        │  │  3. 认证获取              │ │
                        │  │  4. 逐文件审计 (xinru)    │ │
                        │  │  5. 攻击链端到端验证       │ │
                        │  │  6. 报告生成              │ │
                        │  │                          │ │
                        │  │  Human-in-the-loop 节点   │ │
                        │  │  危险操作确认              │ │
                        │  │  验证码/真人间歇           │ │
                        │  │  进度汇报                 │ │
                        │  └──────────────────────────┘ │
                        └──────┬───────────┬───────────┘
                               │           │
                    ┌──────────▼──┐  ┌─────▼──────────┐
                    │  LLM API    │  │  Yakit MCP     │
                    │  (Claude/   │  │  / HTTP API    │
                    │   OpenAI)   │  │  发包验证        │
                    └─────────────┘  └─────┬──────────┘
                                           │
                              ┌────────────▼────────────┐
                              │     工具执行层            │
                              │  ┌────────────────────┐ │
                              │  │ Playwright 浏览器   │ │
                              │  │ requests HTTP客户端  │ │
                              │  │ python-sourcemap    │ │
                              │  │ GitLeaks/git探测    │ │
                              │  │ 子域名枚举/路径爆破  │ │
                              │  │ OCR (验证码识别)    │ │
                              │  └────────────────────┘ │
                              └─────────────────────────┘
```

---

## 四、模块划分

### 模块1：Web 交互层 `web/`

```
web/
├── main.py          # FastAPI 应用入口
├── ws.py            # WebSocket 管理器（Agent ↔ 前端双向推送）
├── templates/
│   └── index.html   # 聊天界面 + 任务面板
├── static/
│   └── agent.js     # 前端 WebSocket 逻辑
└── api.py           # REST API（下载报告、提交任务）
```

**功能：**
- 用户输入目标 URL/域名 → 启动任务
- Agent 实时推送进度日志到聊天框
- Agent 发送 human-in-the-loop 请求（危险操作确认、验证码截图）→ 用户回复
- 任务完成后提供 HTML 报告下载

### 模块2：编排引擎 `orchestrator/`

```
orchestrator/
├── graph.py         # LangGraph StateGraph 定义
├── state.py         # Agent 状态定义（dataclass）
├── nodes/
│   ├── info_gather.py       # 信息收集节点
│   ├── source_collect.py    # 源码全量收集节点
│   ├── auth_acquire.py      # 认证获取节点
│   ├── audit.py             # 审计主循环（xinru 方法论）
│   ├── attack_chain.py      # 攻击链端到端验证
│   └── report.py            # 报告生成节点
├── human_loop.py   # Human-in-the-loop 交互管理
└── progress.py     # 进度持久化（SQLite）
```

**LangGraph 状态图流转：**

```
START
  │
  ▼
[信息收集] ───── 子域名/路径发现（可选）
  │              浏览器爬取入口
  │              Yakit 导入历史流量（如有）
  ▼
[源码全量收集] ── JS bundle / chunk
  │               sourcemap → 还原
  │               Git 泄露 / 备份文件 / 临时文件
  │               开源框架 → GitHub 拉参考源码
  ▼
[认证获取] ──── 表单登录 / SSO /
  │             OCR 验证码 / 人工提供 Cookie
  │             (需要用户交互)
  ▼
[逐文件审计] ◄── xinru 方法论循环
  │              选文件 → 逐行审 → 发现可疑
  │              → 追溯调用链 → Yakit 验证
  │              → 自检 → 写下结论 → 回到原位
  │
  ▼
[攻击链端到端验证] ── 2+ 漏洞组合成链
  │                   串行重跑验证
  ▼
[报告生成] ──── HTML 报告
  │             Yakit 可导入数据包
  ▼
  END
```

### 模块3：源码收集引擎 `collector/`

```
collector/
├── js_collector.py      # JS bundle/chunk 下载 + 解析
├── sourcemap.py         # .map 文件发现 → 还原原始源码
├── git_leak.py          # .git/ 泄露探测
├── backup_detector.py   # 常见备份/临时文件扫描
├── spider.py            # 浏览器爬虫（Playwright）— 点遍所有路由
├── framework_matcher.py # 开源框架指纹识别 → GitHub 拉参考源码
├── subdomain.py         # 子域名暴力枚举
└── path_brute.py        # 目录/路径爆破
```

**源码收集策略（按优先级）：**

1. Playwright 浏览器自动化 — 启动无头浏览器，拦截所有网络请求，抓全部 `.js`/`.map`/chunk
2. 子域名枚举（crt.sh / 字典爆破）
3. 路径爆破（常见路由、API 路径、配置文件路径）
4. Git 泄露探测（`.git/HEAD`、`.git/config`、`.git/index`）
5. 备份/临时文件扫描（`*.js.bak`、`*.js~`、`.swp`、`.DS_Store`）
6. webpack chunk 自动发现（从主 bundle 解析 `webpackJsonp` chunk 列表）
7. sourcemap 发现 + 自动用 `python-sourcemap` 还原
8. 开源框架指纹识别 → 从 GitHub API 拉对应版本源码（若依/JeecgBoot/等）

### 模块4：审计引擎 `auditor/`

```
auditor/
├── xinru_loop.py        # 审计主循环（xinru 方法论核心）
├── threat_patterns.py   # 威胁模式库（硬编码密钥/URL拼接/参数注入/...）
├── call_chain.py        # 调用链追溯引擎
├── endpoint_locator.py  # API 接口精确定位
├── verifier.py          # 验证模块（Yakit MCP 发包）
├── self_check.py        # 结论自检引擎
└── progress_tracker.py  # 文件级+行级进度追踪（断点续扫）
```

**核心逻辑（从 SKILL.md 移植）：**

- 按优先级选文件（config → api/module → utils/http → pages → components → 子包）
- 逐行读取 → 匹配威胁模式 → 发现可疑 → 暂停
- 追溯完整调用链（5问：谁调→参数来源→数据流→定位接口→防护分析）
- Yakit 发包验证（7步：无认证/空参数/假参数/错误签名/越权/写操作/注入）
- 结论自检（5问：认证载体/利用条件/跳过环节/更简解释/可组合性）
- 回到原位继续（pending_return 机制内化为代码逻辑）

### 模块5：Yakit 集成 `yakit/`

```
yakit/
├── mcp_client.py    # Yakit MCP 协议客户端
├── fuzzer.py        # HTTP Fuzzer 封装
├── flow_query.py    # HTTP Flow 历史查询
└── packet_format.py # 生成 Yakit 可导入的数据包格式
```

**双模式：**
- 有 Yakit MCP：直接调用发包验证，效率最高
- 无 Yakit：Agent 自身发 HTTP，但输出格式保持一致（Yakit 兼容数据包）

### 模块6：报告生成 `reporter/`

```
reporter/
├── html_report.py     # HTML 报告生成
├── templates/
│   └── report.html    # Jinja2 报告模板
└── packet_export.py   # Yakit 可导入数据包导出
```

**报告内容：**
- 漏洞概览（按严重级别排序）
- 每个漏洞：名称/级别/文件+行号/调用链/接口/Yakit证据/攻击影响/修复建议
- 攻击链端到端验证结果
- 每个漏洞附带 Yakit 可直接导入的 HTTP 数据包（JSON/YAML 格式）
- 下载为独立 HTML 文件

### 模块7：持久化 `storage/`

```
storage/
├── db.py          # SQLite ORM（peewee）
├── models.py      # 数据模型：Task / File / Finding / Progress
└── migrations/    # 数据库迁移
```

---

## 五、分阶段实施计划

### Phase 1: 骨架搭建（先跑通端到端）

**目标：** agent-compose 上能 `docker compose up`，浏览器打开聊天框，输入 URL → Agent 返回 "Hello World" 级别的审计结果。

**内容：**
1. `Dockerfile` + `docker-compose.yaml`（Python 3.11 + FastAPI + Playwright 依赖）
2. FastAPI + WebSocket 聊天框基础 UI
3. LangGraph 空状态图（节点串行跑通）
4. LLM API 调用封装
5. 任务创建/状态持久化（SQLite）

### Phase 2: 源码收集引擎

**目标：** 输入 URL → 自动拿到全部 JS 源码。

**内容：**
1. Playwright 浏览器自动化（拦截网络请求，收集 JS）
2. 子域名枚举（crt.sh + 字典）
3. 路径爆破
4. Git 泄露探测
5. 备份文件扫描
6. sourcemap 发现 + 还原
7. 开源框架指纹识别 + GitHub 拉源码

### Phase 3: 认证获取

**目标：** 自动登录目标应用，获取认证凭证。

**内容：**
1. 表单登录自动化（Playwright 填表）
2. 验证码 OCR 识别（pytesseract + 回退人工输入）
3. SSO/OAuth 处理
4. Cookie 获取与持久化
5. Human-in-the-loop 集成（验证码截图 → Web 聊天框 → 用户输入）

### Phase 4: 审计引擎（xinru 方法论）

**目标：** 在 Agent 内完整复现 xinru 的审计工作流。

**内容：**
1. 威胁模式库（6 大类 + 20+ 子模式）
2. 调用链追溯引擎（Grep + Read + LLM 辅助分析）
3. Yakit MCP 集成（发包验证）
4. 结论自检引擎
5. "回到原位"内化（pending_return 机制 → 代码逻辑）

### Phase 5: 报告 + Human-in-the-Loop

**目标：** 完整的用户交互体验 + 专业 HTML 报告。

**内容：**
1. HTML 漏洞报告生成（含 Yakit 可导入数据包）
2. 危险操作确认机制（Web 聊天框 Ask-Confirm 流程）
3. 攻击链端到端验证
4. 完整联调测试

---

## 六、report.html 包含内容

```html
报告结构：
├── 标题：渗透测试审计报告 + 目标信息 + 时间
├── 漏洞总览表（严重级别/名称/接口/状态）
├── 源码收集摘要（收集了多少文件/来源统计）
├── 漏洞详情（每个独立页面）
│   ├── 漏洞名称 + 严重级别标签
│   ├── 调用链图（文件:行号 → 文件:行号 → ...）
│   ├── 接口信息（方法 + URL + 参数 + Header）
│   ├── 验证过程（每个测试步骤的 Yakit 数据包）
│   ├── 攻击影响
│   └── 修复建议
├── 攻击链端到端验证
└── 附录：Yakit 一键导入数据包合集
```

Yakit 数据包格式示例（可直接复制到 Yakit HTTP Fuzzer）：
```
GET /api/v1/users/10817 HTTP/1.1
Host: api.example.com
Authorization: Bearer <token>
```
或提供 Yakit Fuzzer 兼容的 JSON 导入格式。

---

## 七、关键设计决策

### 7.1 为什么用 LangGraph 而不是手写状态机？
- 审计流程有大量分支（发现可疑→追溯→验证→确认/排除→回到原位）
- Human-in-the-loop 需要暂停-恢复能力（LangGraph 有原生 `interrupt` 支持）
- LLM 节点生成的结果需要结构化流转到下一节点
- 方便后续扩展（加新攻击面/新验证策略）

### 7.2 为什么保留"回到原位"机制？
- 这是 xinru 方法论的核心创新——对抗 AI 跳步和丢失上下文
- 但不再需要 Python Hook + pending_return.json，直接变成 LangGraph 的状态约束：发现可疑 → 进入"验证分支" → 必须回到 `current_file:current_line` 才能继续下一行

### 7.3 Yakit 的角色
- 默认连接 Yakit MCP（环境变量 `YAKIT_MCP_URL`）
- 发包验证时优先用 Yakit
- 如果连不上，Agent 自己发 HTTP 请求
- **数据包输出格式始终是 Yakit 兼容的**，确保评估者能一键导入

---

## 八、Docker 部署结构

```
xinru-agent/
├── Dockerfile
├── docker-compose.yaml
├── requirements.txt
├── .env.example
├── web/                 # Web 聊天界面
├── orchestrator/        # LangGraph 编排
├── collector/           # 源码收集
├── auditor/             # 审计引擎
├── yakit/               # Yakit 集成
├── reporter/            # 报告生成
├── storage/             # SQLite 持久化
├── xinru_skill.md       # 原始 SKILL.md（作为审计 system prompt 基础）
└── reports/             # 报告输出目录（volume mount）
```

---

## 九、验收标准

1. `docker compose up` 一把启动，浏览器打开 `http://localhost:8000` 看到聊天界面
2. 输入目标 URL → Agent 自动完成源码收集 → 逐文件审计 → 发现漏洞 → 验证 → 出 HTML 报告
3. 遇到危险操作 → Web 聊天框提示确认 → 用户回复后继续
4. 遇到验证码 → 截图展示 → 用户输入 → Agent 继续登录
5. 报告中有每个漏洞的 Yakit 可导入数据包
6. 全程（除人为交互点）无人工干预
