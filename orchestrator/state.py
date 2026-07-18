"""xinru Agent 状态定义 — 贯穿全部节点的共享状态

LangGraph 要求所有状态字段可序列化（dict/list/str/int/float/bool/None）。
"""

from typing import TypedDict


class AgentState(TypedDict, total=False):
    # ========== 任务标识 ==========
    task_id: int
    targets: list[str]
    status: str  # pending/collecting/authenticating/auditing/verifying_chain/generating_report/paused/completed/failed

    # ========== 收集阶段 ==========
    collected_files: list[dict]  # [{source_type, url, local_path, file_name, file_size, line_count, priority}]
    yakit_flows_imported: int

    # ========== 认证阶段 ==========
    cookies: dict[str, str]  # target → cookie string（兼容旧逻辑，默认账号A）
    sessions: dict  # target → {A: session, B: session}

    # ========== 审计阶段（xinru 内循环核心） ==========
    # 文件排序后的索引
    sorted_file_paths: list[str]
    current_file_index: int
    # 当前文件已审计到的行号（下一轮从这里开始）
    current_line: int
    # 当前文件总行数
    current_file_line_count: int
    # 当前文件内容（缓存，避免重复读）
    current_file_content: str
    current_file_path: str
    # 发现的漏洞
    findings: list[dict]
    # 当前正在处理的发现（临时状态）
    active_threat: dict | None  # {line, pattern, pattern_name, description, severity_guess}
    handled_threats: list[str]  # 已处理威胁键，防回流死循环
    return_marker: dict | None  # 回流标记 {file,line,threat_key,line_fp}

    # ========== 攻击链验证阶段 ==========
    attack_chains: list[dict]

    # ========== 错误处理 ==========
    error: str | None

    # ========== 进度统计 ==========
    total_lines_audited: int
    files_completed: int
    total_files: int

    # ========== 动态补充收集 ==========
    pending_leads: list[dict]  # 审计中发现的待补收线索 [{"url": "...", "reason": "..."}, ...]
    processed_leads: list[str]  # 已登记过的规范化 URL，跨补收循环去重

    # ========== 内部路由字段（临时状态，不持久化）==========
    _scan_result: str  # "no_threat" | "threat_found" | "file_end"
    _trace_result: dict  # 追溯结果
    _verify_results: list  # Yakit 验证结果列表
    _self_check_result: dict  # 结论自检结果
    _endpoint: dict  # 精确定位后的 endpoint
    _pending_amt: int  # 本轮补收了多少文件（用于判断是否有新文件追加到队列）
    pause_reason: str | None
    resume_mode: bool
