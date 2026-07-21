"""LangGraph 编排引擎 — xinru Agent 核心

主流程图:

    info_gather → source_collect → auth_acquire → setup_audit
        → multi_agent_audit (WorkItem 可恢复并行审计)
            ├─ pending_leads → supplement_collect → setup_audit
            ├─ paused / 队列未完成 → END（可 resume）
            └─ 完成 → attack_chain → generate_report
"""

import json
import os
import asyncio
import ipaddress
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

from storage.models import (
    Task,
    CollectedFile,
    Finding,
    AttackChain,
    ProgressLog,
    AuditLead,
)
from web.ws import ws_manager
from orchestrator.state import AgentState





_IGNORED_LEAD_HOSTS = {
    "github.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "npmjs.com",
    "www.npmjs.com",
    "w3.org",
    "www.w3.org",
    "schema.org",
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
}

_SECURITY_URL_MARKERS = (
    "api", "auth", "oauth", "sso", "idp", "token", "login", "callback",
    "webhook", "upload", "storage", "internal", "preprod", "staging", "dev",
)





def _normalize_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = f"https://{value}"
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    if not parsed.hostname:
        return ""
    scheme = (parsed.scheme or "https").lower()
    host = parsed.hostname.lower().rstrip(".")
    port = parsed.port
    netloc = host
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{host}:{port}"
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit((scheme, netloc, path, "", ""))


def _root_domain(host: str) -> str:
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if parts[-2] in {"com", "net", "org", "gov", "edu", "ac", "co"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_actionable_lead(state: AgentState, url: str, source_text: str = "") -> bool:
    """过滤许可证、文档和公共 CDN，只保留 xinru 需要验证的攻击面。

    若任务配置了 BBASRC scope，则额外强制 in-scope。
    """
    normalized = _normalize_url(url)
    if not normalized:
        return False

    # BBASRC / 任务级 scope 过滤
    try:
        task = Task.get_by_id(state.get("task_id", 0)) if state.get("task_id") else None
        cfg = task.get_config() if task else {}
    except Exception:
        cfg = {}
    if cfg.get("filter_leads_by_scope") or cfg.get("scope_file") or cfg.get("scope_name") == "BBASRC":
        try:
            from scope.scope_matcher import is_in_scope
            ok, _reason = is_in_scope(normalized)
            if not ok:
                return False
            # 额外文本排除（如 tupu360）
            from scope.scope_matcher import is_out_of_scope
            excluded, _ = is_out_of_scope(normalized, source_text)
            if excluded:
                return False
        except Exception:
            pass
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    if host in _IGNORED_LEAD_HOSTS:
        return False

    target_hosts = {
        (urlsplit(_normalize_url(target)).hostname or "")
        for target in state.get("targets", [])
    }
    target_roots = {_root_domain(item) for item in target_hosts if item}
    if host in target_hosts or _root_domain(host) in target_roots:
        return True

    try:
        address = ipaddress.ip_address(host)
        if address.is_private or address.is_loopback:
            return True
    except ValueError:
        pass

    haystack = f"{host} {parsed.path} {source_text}".lower()
    return any(marker in haystack for marker in _SECURITY_URL_MARKERS)


def _is_fatal_llm_error(error: Exception) -> bool:
    status = getattr(error, "status_code", None)
    message = str(error).lower()
    return status in (401, 402) or "insufficient balance" in message or "余额不足" in message




# ============================================================
# 辅助函数 — 双写进度（WS + DB），执行期零人工干预必须靠 DB 看进度
# ============================================================
async def _log(task_id: int, message: str, log_type: str = "info"):
    """同时写 WebSocket（实时推送）和 ProgressLog DB（持久化，崩了也能查）"""
    try:
        await ws_manager.send_progress(task_id, message, log_type)
    except Exception:
        pass
    try:
        ProgressLog.create(task=task_id, message=message, log_type=log_type)
    except Exception as e:
        # 兜底打印，避免进度静默丢失
        print(f"[progress-db-fail] task={task_id} type={log_type} err={e} msg={message[:180]}", flush=True)
    # CLI 无人值守时也要能从 stdout 看到进度
    print(f"[progress][{log_type}] {message}", flush=True)


def _safe_node(name: str):
    """装饰器：给节点函数加 try/except 保护，崩了不拖垮整个 graph"""
    def deco(fn):
        async def wrapper(state):
            try:
                return await fn(state)
            except Exception as e:
                import traceback
                err = f"[{name}] 节点异常: {e}\n{traceback.format_exc()[:300]}"
                print(err)
                try:
                    await _log(state.get("task_id", 0), err, "error")
                except Exception:
                    pass
                if isinstance(state, dict):
                    state["error"] = str(e)[:200]
                return state
        return wrapper
    return deco


# ============================================================
# 主入口节点
# ============================================================
async def node_info_gather(state: AgentState) -> AgentState:
    """信息收集 — 解析 Yakit 导出、子域名发现、初始化审计环境"""
    task_id = state["task_id"]
    task = Task.get_by_id(task_id)

    await _log(task_id, "🔍 开始信息收集...", "info")

    # 导入 Yakit 导出数据（如果有）
    if task.yakit_export_path:
        await _log(task_id, f"📥 导入 Yakit 导出数据...", "info")
        # TODO Phase 2 — 解析 Yakit 导出
        task.yakit_flows_imported = 0
        task.save()

    for target in state["targets"]:
        await _log(task_id, f"🎯 目标: {target}", "info")

    state["status"] = "collecting"
    task.status = "collecting"
    task.save()
    return state


@_safe_node("source_collect")
async def node_source_collect(state: AgentState) -> AgentState:
    """源码全量收集 — 首次全部手段一网打尽：
    LLM/HTTP 主导拿源码 → sourcemap/备份等补充 →（可选）爬虫/子域/路径爆破

    后续补收也走这里，通过 pending_leads 参数化目标范围。
    resume_mode 下若 DB 已有文件，直接加载并跳过重采。
    """
    from collector.orchestrator import collect_all
    from orchestrator import workqueue as wq

    task_id = state["task_id"]
    leads = state.get("pending_leads", [])
    targets = state["targets"]

    # ---- 可恢复：跳过已完成的全量收集 ----
    if state.get("resume_mode") and not leads:
        existing = wq.load_collected_files(task_id)
        existing = [f for f in existing if f.get("local_path") and os.path.exists(f["local_path"])]
        if existing:
            state["collected_files"] = existing
            try:
                wq.set_phase(task_id, "authenticating", status="authenticating")
            except Exception:
                Task.update(status="authenticating").where(Task.id == task_id).execute()
            state["status"] = "authenticating"
            await _log(
                task_id,
                f"♻️ resume 跳过源码重采 — 复用 DB 中 {len(existing)} 个已收集文件",
                "info",
            )
            return state

    if leads:
        await _log(
            task_id,
            f"🔄 补充收集 — {len(leads)} 条新线索...",
            "info",
        )
        # 把 leads 里的 URL 作为补充目标
        extra_targets = [lead["url"] for lead in leads]
        targets = list(set(targets + extra_targets))

    work_dir = os.path.join(
        os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "data")),
        "collected",
        f"task_{task_id}",
    )

    await _log(
        task_id,
        f"📦 启动全量源码收集 — {len(targets)} 个目标",
        "info",
    )

    try:
        files = await collect_all(
            targets=targets,
            work_dir=work_dir,
            cookies=state.get("cookies", {}),
            leads=leads or None,
            options={
                "subdomain_discovery": bool((Task.get_by_id(task_id).get_config() or {}).get("subdomain_discovery", False)),
                "path_brute": bool((Task.get_by_id(task_id).get_config() or {}).get("path_brute", False)),
                "enable_git_leak": False,
                "enable_backup": False,  # 备份探测噪声大，默认关；需要时可开
                "enable_framework": False,
                "enable_spider": False,   # 爬虫降为补充，默认关闭
                "enable_sourcemap": False,  # sourcemap 易卡，默认关；需要可开
                "llm_source_timeout": 240,
                "llm_call_timeout": 30,
                "max_downloads": 80,
                "download_timeout": 12,
            },
        )
    except Exception as e:
        import traceback
        await _log(
            task_id,
            f"⚠️ 源码收集出错: {e}\n{traceback.format_exc()[:300]}",
            "error",
        )
        files = []

    # 写入 CollectedFile 表 + 更新 collected_files 状态
    task = Task.get_by_id(task_id)

    # 加载 DB 中已有的文件（补收前可能已有人工注入或断点续扫保留的文件）
    existing_db_files = list(CollectedFile.select().where(CollectedFile.task == task))
    existing_paths = {
        f["local_path"] for f in state.get("collected_files", [])
    }
    for dbf in existing_db_files:
        if dbf.local_path not in existing_paths:
            existing_paths.add(dbf.local_path)
            state.setdefault("collected_files", []).append({
                "source_type": dbf.source_type,
                "url": dbf.url,
                "local_path": dbf.local_path,
                "file_name": dbf.file_name,
                "file_size": dbf.file_size,
                "line_count": dbf.line_count,
            })

    new_count = 0

    for file_info in files:
        if file_info["local_path"] in existing_paths:
            continue
        existing_paths.add(file_info["local_path"])

        CollectedFile.create(
            task=task,
            source_type=file_info["source_type"],
            url=file_info["url"],
            local_path=file_info["local_path"],
            file_name=file_info["file_name"],
            file_size=file_info.get("file_size", 0),
            line_count=file_info.get("line_count", 0),
        )
        state.setdefault("collected_files", []).append(file_info)
        new_count += 1

    task.total_files_collected = len(state.get("collected_files", []))
    task.save()

    await _log(
        task_id,
        f"📦 源码收集完成 — 共 {len(state.get('collected_files', []))} 个文件"
        + (f"（本轮新增 {new_count} 个）" if new_count else ""),
        "info",
    )

    # 清空已处理的 leads
    if leads:
        state["pending_leads"] = []

    try:
        from orchestrator import workqueue as wq
        wq.set_phase(task_id, "authenticating", status="authenticating")
    except Exception:
        Task.update(status="authenticating").where(Task.id == task_id).execute()
    state["status"] = "authenticating"
    return state


async def node_auth_acquire(state: AgentState) -> AgentState:
    """认证获取 — 无人值守双身份（Cookie + 账号都先给）

    对 A/B 每个身份:
    1. 有 Cookie/Token → 先探活
    2. 失效且有账号密码 → 自动找登录口并登录回落
    3. 仍失败且 allow_register → 自动注册再登录（多用于 B）
    4. 提取 user_id/token，供后续双账号越权

    兼容旧字段 cookies/credentials，同时支持 cookies_b/credentials_b/accounts。
    """
    from collector.accounts import parse_account_configs, dual_ready, summarize_sessions
    from collector.session_bootstrap import bootstrap_account_session

    task_id = state["task_id"]
    targets = state["targets"]
    task = Task.get_by_id(task_id)
    config = task.get_config()
    work_dir = os.path.join(
        os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "data")),
        "collected",
        f"task_{task_id}",
    )

    account_cfgs = parse_account_configs(config)
    sessions: dict[str, dict[str, dict]] = state.get("sessions") or {}
    cookies = dict(state.get("cookies") or {})
    allow_register = bool(config.get("allow_register"))

    if not account_cfgs:
        await _log(
            task_id,
            "🔑 未配置任何账号/Cookie — 以无认证模式继续（仍可测未授权）",
            "warning",
        )
        state["sessions"] = sessions
        state["cookies"] = cookies
        state["status"] = "auditing"
        Task.update(status="auditing").where(Task.id == task_id).execute()
        return state

    await _log(
        task_id,
        f"🔑 启动身份引导 — {len(account_cfgs)} 套配置（Cookie优先，失效回落密码，可选自动注册）",
        "info",
    )

    for target in targets:
        role_map = sessions.setdefault(target, {})
        for acc in account_cfgs:
            role = acc.get("role") or "A"
            existing = role_map.get(role) or {}
            if existing.get("success") and (existing.get("cookies") or existing.get("token")):
                continue

            # 只有 B 默认允许注册回落；A 仅当显式 allow_register 且 A 也失败时可选
            reg_allowed = allow_register and (role == "B" or not any(
                (a.get("role") or "A") == "B" for a in account_cfgs
            ))

            await _log(
                task_id,
                f"🔑 引导身份 {role}@{target} "
                f"(cookie={'有' if acc.get('cookies') or acc.get('token') else '无'}, "
                f"pwd={'有' if acc.get('username') and acc.get('password') else '无'}, "
                f"register={'on' if reg_allowed else 'off'})",
                "info",
            )
            try:
                sess = await bootstrap_account_session(
                    target=target,
                    account=acc,
                    work_dir=os.path.join(work_dir, "auth"),
                    allow_register=reg_allowed,
                )
            except Exception as e:
                sess = {
                    "role": role,
                    "label": acc.get("label") or f"account_{role}",
                    "username": acc.get("username") or "",
                    "cookies": acc.get("cookies") or "",
                    "token": acc.get("token") or "",
                    "token_header": acc.get("token_header") or "",
                    "headers": acc.get("headers") or {},
                    "user_id": acc.get("user_id") or "",
                    "source": "failed",
                    "success": False,
                    "reason": f"引导异常: {e}",
                }

            role_map[role] = sess
            icon = "✅" if sess.get("success") else "⚠️"
            await _log(
                task_id,
                f"{icon} 身份 {role}@{target}: {sess.get('source')} — {sess.get('reason','')}"
                + (f" | uid={sess.get('user_id')}" if sess.get("user_id") else ""),
                "info" if sess.get("success") else "warning",
            )

        # 兼容旧 cookies：默认 A
        if role_map.get("A", {}).get("cookies"):
            cookies[target] = role_map["A"]["cookies"]
        else:
            for sess in role_map.values():
                if sess.get("cookies"):
                    cookies[target] = sess["cookies"]
                    break

    state["sessions"] = sessions
    state["cookies"] = cookies
    state["status"] = "auditing"
    Task.update(status="auditing").where(Task.id == task_id).execute()

    # xinru 第零步：凭证表 + WAF 策略落盘（无人值守，启动配置一次给齐）
    try:
        from auditor.credentials import bootstrap_from_config, CredentialRecord, _host
        from auditor.waf_policy import build_policy, resolve_waf_authorized
        store = bootstrap_from_config(task_id, config, targets)
        for target, role_map in (sessions or {}).items():
            for role, sess in (role_map or {}).items():
                if not isinstance(sess, dict):
                    continue
                if not (sess.get("cookies") or sess.get("token")):
                    continue
                store.upsert(CredentialRecord(
                    domain=_host(target) or "*",
                    role=str(role or "A"),
                    auth_type="mixed" if (sess.get("cookies") and sess.get("token")) else ("token" if sess.get("token") else "cookie"),
                    cookies=sess.get("cookies") or "",
                    token=sess.get("token") or "",
                    token_header=sess.get("token_header") or "Authorization",
                    headers=sess.get("headers") or {},
                    username=sess.get("username") or "",
                    source=sess.get("source") or "session",
                    valid=bool(sess.get("success", True)),
                    notes=sess.get("reason") or "",
                ))
        waf_flag = resolve_waf_authorized(config)
        if waf_flag is None:
            brief = str(config.get("brief") or "")
            waf_flag = any(k in brief.lower() for k in ("src", "授权", "bbasrc", "authorized", "pentest"))
            config["waf_authorized"] = waf_flag
        store.waf_authorized = bool(waf_flag)
        store.save()
        policy = build_policy(config)
        await _log(
            task_id,
            f"📇 凭证表已建立 records={len(store.records)} valid={len(store.list_valid())} | WAF authorized={policy.authorized} ({policy.notes})",
            "info",
        )
    except Exception as e:
        await _log(task_id, f"⚠️ 凭证表/WAF 初始化失败: {e}", "warning")

    if dual_ready(sessions):
        await _log(
            task_id,
            f"🔑 双账号会话就绪 — {summarize_sessions(sessions)}",
            "info",
        )
    else:
        await _log(
            task_id,
            f"⚠️ 双账号未齐备，越权将降级 — {summarize_sessions(sessions)}",
            "warning",
        )
    return state


def _add_pending_leads(state: AgentState, leads: list[dict]):
    """持久化新线索；同一任务中同一规范化 URL 永远只处理一次。"""
    seen = set(state.get("processed_leads", []))
    for lead in leads:
        normalized = _normalize_url(lead.get("url", ""))
        if not normalized or normalized in seen:
            continue
        if not _is_actionable_lead(state, normalized, lead.get("source_text", "")):
            continue

        payload = {
            "url": normalized,
            "reason": lead.get("reason", ""),
            "source_file": lead.get("source_file", state.get("current_file_path", "")),
            "source_line": lead.get("source_line", state.get("current_line", 0) + 1),
        }
        try:
            _, created = AuditLead.get_or_create(
                task=state["task_id"],
                normalized_url=normalized,
                defaults={
                    "original_url": lead.get("url", normalized),
                    "reason": payload["reason"],
                    "source_file": payload["source_file"],
                    "source_line": payload["source_line"],
                },
            )
        except Exception:
            created = False

        # 数据库唯一约束是最终防线；内存集合保证当前图内不重复。
        seen.add(normalized)
        state.setdefault("processed_leads", []).append(normalized)
        if created:
            state.setdefault("pending_leads", []).append(payload)


def _mark_leads_processed(state: AgentState, leads: list[dict]):
    normalized_urls = [_normalize_url(lead.get("url", "")) for lead in leads]
    normalized_urls = [url for url in normalized_urls if url]
    if not normalized_urls:
        return
    AuditLead.update(status="processed", processed_at=datetime.now()).where(
        (AuditLead.task_id == state["task_id"])
        & (AuditLead.normalized_url.in_(normalized_urls))
    ).execute()


async def node_setup_audit(state: AgentState) -> AgentState:
    """审计前准备 — 给收集到的文件按优先级排序，初始化审计游标

    这个节点在 首次审计 和 补收后重新排序 两个场景都会被调用。
    """
    from auditor.threat_patterns import FILE_PRIORITY_MAP

    task_id = state["task_id"]
    files_dict = state.get("collected_files", [])

    if not files_dict:
        # resume 兜底：state 空时从 DB 加载
        try:
            from orchestrator import workqueue as wq
            files_dict = [
                f for f in wq.load_collected_files(task_id)
                if f.get("local_path") and os.path.exists(f["local_path"])
            ]
            if files_dict:
                state["collected_files"] = files_dict
                await _log(task_id, f"♻️ setup_audit 从 DB 加载 {len(files_dict)} 个文件", "info")
        except Exception as e:
            await _log(task_id, f"⚠️ setup_audit DB 加载失败: {e}", "warning")

    if not files_dict:
        await _log(task_id, "⚠️ 没有收集到任何文件，跳过审计", "warning")
        return state

    # 按优先级排序
    def sort_key(f: dict) -> int:
        for pattern in FILE_PRIORITY_MAP:
            if pattern in f.get("file_name", ""):
                return FILE_PRIORITY_MAP[pattern]
        return 99

    sorted_files = sorted(files_dict, key=sort_key)
    paths = [f["local_path"] for f in sorted_files if f.get("local_path")]
    try:
        from auditor.preprocess import expand_inventory, inventory_stats
        expanded = expand_inventory(paths)
        # 保持优先级：原排序文件在前，扩展补充在后
        ordered = []
        seen = set()
        for pth in paths + expanded:
            if pth in seen:
                continue
            seen.add(pth)
            ordered.append(pth)
        state["sorted_file_paths"] = ordered
        stats = inventory_stats(ordered)
        await _log(task_id, f"📂 清单扩展 — {len(paths)}→{len(ordered)} by_ext={stats.get('by_ext')}", "info")
    except Exception as e:
        state["sorted_file_paths"] = paths
        await _log(task_id, f"⚠️ 清单扩展失败: {e}", "warning")
    state["total_files"] = len(state.get("sorted_file_paths") or [])

    # 首次初始化 vs 补收后重新排序（不重置游标）
    if state.get("current_file_index", -1) < 0:
        state["current_file_index"] = 0
    if state.get("current_line", -1) < 0:
        state["current_line"] = 0
    if state.get("files_completed", -1) < 0:
        state["files_completed"] = 0
    if state.get("total_lines_audited", -1) < 0:
        state["total_lines_audited"] = 0

    task = Task.get_by_id(task_id)
    task.total_files_collected = len(sorted_files)
    task.status = "auditing"
    task.phase = "auditing"
    task.save()
    state["status"] = "auditing"

    context = "补收后重新排列" if state.get("_pending_amt", 0) > 0 else ""
    await _log(
        task_id,
        f"📋 {'[补收] ' if context else ''}审计队列 — {len(sorted_files)} 个文件全量扫描（仅排序，不跳过）",
        "info",
    )
    state["_pending_amt"] = 0
    return state



@_safe_node("multi_agent_audit")
async def node_multi_agent_audit(state: AgentState) -> AgentState:
    """xinru 模式 B：主 Agent 分发多个子 Agent 并行审计文件。

    每个子 Agent 独立完成单文件的 扫→追→验→自检→回原位 全循环。
    文件数少时也可走此节点（内部自动降到 1 worker）。
    """
    from auditor.multi_agent import run_multi_agent_audit, should_use_multi_agent

    task_id = state["task_id"]
    paths = list(state.get("sorted_file_paths") or [])
    if not paths:
        # fallback to collected_files
        paths = [f.get("local_path") for f in (state.get("collected_files") or []) if f.get("local_path")]
        state["sorted_file_paths"] = paths

    # 估算行数
    total_lines = 0
    for p in paths:
        try:
            dbf = CollectedFile.select().where(
                (CollectedFile.task_id == task_id) & (CollectedFile.local_path == p)
            ).first()
            if dbf and dbf.line_count:
                total_lines += int(dbf.line_count)
        except Exception:
            pass

    use_multi = should_use_multi_agent(len(paths), total_lines)
    mode = "multi" if use_multi else "single-worker-via-multi-node"
    await _log(
        task_id,
        f"🧠 审计调度: files={len(paths)} lines≈{total_lines} mode={mode}",
        "info",
    )

    try:
        task_cfg = Task.get_by_id(task_id).get_config() or {}
    except Exception:
        task_cfg = {}

    result = await run_multi_agent_audit(
        task_id=task_id,
        file_paths=paths,
        cookies=state.get("cookies") or {},
        sessions=state.get("sessions") or {},
        targets=state.get("targets") or [],
        log=_log,
        config=task_cfg,
    )

    # 汇总 findings 到 state
    db_findings = list(Finding.select().where(Finding.task_id == task_id).order_by(Finding.finding_number))
    state["findings"] = [
        {
            "id": f.id,
            "finding_number": f.finding_number,
            "name": f.name,
            "severity": f.severity,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "verdict": f.verdict,
            "api_endpoint": f.api_endpoint,
            "attack_impact": f.attack_impact,
        }
        for f in db_findings
    ]
    state["files_completed"] = int(result.get("files_completed") or 0)
    state["total_lines_audited"] = int(result.get("lines_audited") or 0)
    state["total_files"] = len(paths)
    state["current_file_index"] = len(paths)

    # 子 Agent 产出的 leads 进入补收队列
    leads = result.get("leads") or []
    if leads:
        _add_pending_leads(state, leads)

    # WorkItem 队列未完成或任务 paused：不要进入攻击链/假完成
    try:
        from orchestrator import workqueue as wq
        qstats = result.get("queue") or wq.queue_stats(task_id)
        if result.get("paused") or wq.is_task_paused(task_id):
            state["status"] = "paused"
            state["pause_reason"] = Task.get_by_id(task_id).pause_reason
            await _log(task_id, f"⏸️ 审计暂停 — {state.get('pause_reason') or 'paused'} | queue={qstats}", "warning")
            return state
        if qstats.get("unfinished", 0) > 0:
            # 还有未完成 item（例如达到 max attempts 前的 pending），保持 auditing
            state["status"] = "auditing"
            wq.set_phase(task_id, "auditing", status="auditing")
            await _log(task_id, f"⏳ 审计队列仍有未完成 WorkItem: {qstats}", "warning")
            return state
    except Exception as e:
        await _log(task_id, f"⚠️ 队列状态检查失败: {e}", "warning")

    if state.get("pending_leads"):
        state["status"] = "collecting"
        state["_pending_amt"] = len(state.get("pending_leads") or [])
        await _log(task_id, f"🔄 多 Agent 结束后有 {state['_pending_amt']} 条线索待补收", "warning")
    else:
        state["status"] = "verifying_chain"
        try:
            from orchestrator import workqueue as wq
            wq.set_phase(task_id, "verifying_chain", status="verifying_chain")
        except Exception:
            Task.update(status="verifying_chain").where(Task.id == task_id).execute()
    return state


# 审计执行统一走 multi_agent_audit + WorkItem 队列（可恢复）。


@_safe_node("supplement_collect")
async def node_supplement_collect(state: AgentState) -> AgentState:
    """补充收集 — 审计中发现新线索，拿 leads 去跑收集手段。

    新文件追加到 collected_files 尾部（setup_audit 会按优先级重排）。
    """
    from collector.orchestrator import collect_all

    task_id = state["task_id"]
    leads = state.get("pending_leads", [])

    await _log(
        task_id,
        f"🔄 审计中触发补充收集 — {len(leads)} 条新线索",
        "warning",
    )

    work_dir = os.path.join(
        os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "data")),
        "collected",
        f"task_{task_id}",
    )

    try:
        # 补收只打 leads 目标，且避免再跑全量 LLM 爬站（否则会无限/重复收集）
        lead_targets = []
        for lead in leads:
            u = (lead.get("url") or "").strip()
            if u:
                lead_targets.append(u)
        lead_targets = list(dict.fromkeys(lead_targets)) or list(state["targets"])
        new_files = await collect_all(
            targets=lead_targets,
            work_dir=work_dir,
            cookies=state.get("cookies", {}),
            leads=leads,
            options={
                "subdomain_discovery": False,
                "path_brute": False,
                "enable_git_leak": False,
                "enable_backup": False,
                "enable_framework": False,
                "enable_spider": False,
                "enable_sourcemap": True,
                "llm_source_timeout": 120,
                "max_downloads": 40,
                "download_timeout": 10,
            },
        )
    except Exception as e:
        await _log(task_id, f"⚠️ 补充收集失败: {e}", "error")
        new_files = []

    # 写入 DB + 追加到状态
    task = Task.get_by_id(task_id)
    existing_paths = {f["local_path"] for f in state.get("collected_files", [])}
    new_count = 0

    for file_info in new_files:
        if file_info["local_path"] in existing_paths:
            continue
        existing_paths.add(file_info["local_path"])
        CollectedFile.create(
            task=task,
            source_type=file_info["source_type"],
            url=file_info["url"],
            local_path=file_info["local_path"],
            file_name=file_info["file_name"],
            file_size=file_info.get("file_size", 0),
            line_count=file_info.get("line_count", 0),
        )
        state.setdefault("collected_files", []).append(file_info)
        new_count += 1

    # 清除已处理的 leads
    state["pending_leads"] = []
    state["_pending_amt"] = new_count

    await _log(
        task_id,
        f"🔄 补充收集完成 — 新增 {new_count} 个文件（共 {len(state.get('collected_files', []))} 个）",
        "info",
    )
    return state


def route_after_multi_agent(state: AgentState) -> str:
    """多 Agent 审计后的路由。"""
    if state.get("status") == "paused":
        return "paused"
    if state.get("pending_leads"):
        return "supplement_collect"
    # 队列未完成时 multi 节点会把 status 留在 auditing；结束图等待 resume
    if state.get("status") == "auditing":
        return "paused"
    return "attack_chain"



async def node_attack_chain(state: AgentState) -> AgentState:
    """攻击链端到端验证 — LLM 串联 + 关键步骤真实复验。"""
    from orchestrator.llm import call_llm_json, SYSTEM_PROMPT
    from auditor.threat_patterns import ATTACK_CHAIN_PROMPT
    from auditor.discoveries import get_bus
    from auditor.waf_policy import build_policy, pace, apply_to_request
    from yakit.verifier import build_raw_request, classify_response, _format_response
    import httpx

    task_id = state["task_id"]
    db_findings = list(Finding.select().where(Finding.task_id == task_id).order_by(Finding.finding_number))
    useful = [f for f in db_findings if f.verdict in ("confirmed", "uncertain")]

    if len(useful) < 2:
        await _log(task_id, "⛓️ 可串联漏洞不足 2 个，跳过攻击链验证", "info")
        state["status"] = "generating_report"
        Task.update(status="generating_report").where(Task.id == task_id).execute()
        return state

    await _log(task_id, f"⛓️ 开始攻击链分析（{len(useful)} 个候选）...", "info")
    payload = [
        {
            "finding_number": f.finding_number,
            "name": f.name,
            "severity": f.severity,
            "verdict": f.verdict,
            "api_endpoint": f.api_endpoint,
            "attack_impact": f.attack_impact,
            "file_path": f.file_path,
            "line_number": f.line_number,
        }
        for f in useful[:30]
    ]
    try:
        bcast = get_bus(task_id).as_prompt_block(15)
    except Exception:
        bcast = "(none)"

    chains = []
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(
                call_llm_json,
                SYSTEM_PROMPT,
                ATTACK_CHAIN_PROMPT.format(findings_json=json.dumps(payload, ensure_ascii=False)[:6000])
                + f"\n\n全局广播情报:\n{bcast}\n请优先串联 confirmed，并给出可执行 steps。",
            ),
            timeout=90,
        )
        if isinstance(result, dict):
            chains = result.get("chains") or []
    except Exception as e:
        await _log(task_id, f"⚠️ 攻击链 LLM 分析失败: {e}", "warning")
        chains = []

    if not chains:
        by_host = {}
        for f in useful:
            host = "unknown"
            try:
                api = json.loads(f.api_endpoint or "{}")
                host = (api.get("domain") or urlsplit(api.get("full_url") or "").hostname or "unknown")
            except Exception:
                pass
            by_host.setdefault(str(host), []).append(f)
        for host, group in by_host.items():
            conf = [g for g in group if g.verdict == "confirmed"]
            if len(conf) >= 2:
                chains.append({
                    "name": f"{host} 组合利用链",
                    "finding_numbers": [g.finding_number for g in conf[:5]],
                    "steps": [f"利用 #{g.finding_number} {g.name}" for g in conf[:5]],
                    "impact": conf[-1].attack_impact or "组合影响待验证",
                    "feasible": True,
                })

    try:
        task_cfg = Task.get_by_id(task_id).get_config() or {}
    except Exception:
        task_cfg = {}
    policy = build_policy(task_cfg)
    sessions = state.get("sessions") or {}
    cookies = state.get("cookies") or {}

    async def _e2e_verify(chain: dict) -> dict:
        nums = chain.get("finding_numbers") or []
        by_num = {f.finding_number: f for f in useful}
        steps_out = []
        ok_steps = 0
        async with httpx.AsyncClient(timeout=12, follow_redirects=False, verify=False) as client:
            for num in nums[:5]:
                f = by_num.get(num)
                if not f:
                    continue
                try:
                    api = json.loads(f.api_endpoint or "{}")
                except Exception:
                    api = {}
                url = api.get("full_url") or ""
                if not url and api.get("domain") and api.get("path"):
                    dom = api.get("domain")
                    path = api.get("path")
                    if not str(dom).startswith("http"):
                        dom = "https://" + str(dom)
                    url = str(dom).rstrip("/") + "/" + str(path).lstrip("/")
                if not url or "待定位" in str(url):
                    steps_out.append({"finding": num, "ok": False, "reason": "no url"})
                    continue
                method = (api.get("method") or "GET").upper()
                headers = apply_to_request(url=url, headers={}, policy=policy, config=task_cfg)
                ck = cookies.get(url) or ""
                if not ck:
                    host = urlsplit(url).hostname or ""
                    for k, v in cookies.items():
                        if host and host in str(k):
                            ck = v
                            break
                if not ck:
                    host = urlsplit(url).hostname or ""
                    for t, role_map in sessions.items():
                        if host and host in str(t):
                            sess = (role_map or {}).get("A") or {}
                            ck = sess.get("cookies") or ck
                            tok = sess.get("token") or ""
                            if tok:
                                headers["Authorization"] = tok if str(tok).lower().startswith("bearer ") else f"Bearer {tok}"
                            break
                if ck:
                    headers["Cookie"] = ck
                raw_req = build_raw_request(method, url, headers, None)
                try:
                    await pace(url, policy)
                    resp = await client.request(method, url, headers=headers)
                    cls = classify_response(resp.status_code, resp.text or "", url, resp.headers.get("content-type", ""))
                    ok = bool(cls.get("business_open") or (resp.status_code == 200 and not cls.get("is_static")))
                    if ok:
                        ok_steps += 1
                    steps_out.append({
                        "finding": num,
                        "ok": ok,
                        "status": resp.status_code,
                        "class": cls,
                        "request": raw_req,
                        "response": _format_response(resp)[:1500],
                    })
                except Exception as e:
                    steps_out.append({"finding": num, "ok": False, "reason": str(e), "request": raw_req})
        feasible = ok_steps >= max(1, min(2, len(nums))) or bool(chain.get("feasible"))
        return {"e2e_steps": steps_out, "e2e_ok_steps": ok_steps, "feasible": feasible}

    saved = []
    for i, chain in enumerate(chains[:10], 1):
        if not isinstance(chain, dict):
            continue
        e2e = {"feasible": bool(chain.get("feasible")), "impact": chain.get("impact") or ""}
        try:
            e2e_res = await _e2e_verify(chain)
            e2e.update(e2e_res)
            chain["feasible"] = bool(e2e_res.get("feasible"))
        except Exception as e:
            e2e["e2e_error"] = str(e)

        obj = AttackChain.create(
            task=task_id,
            chain_number=i,
            name=chain.get("name") or f"攻击链#{i}",
            involved_findings=json.dumps(chain.get("finding_numbers") or [], ensure_ascii=False),
            steps=json.dumps(chain.get("steps") or [], ensure_ascii=False),
            final_verification=json.dumps(e2e, ensure_ascii=False),
        )
        saved.append({
            "chain_number": i,
            "name": obj.name,
            "finding_ids": chain.get("finding_numbers") or [],
            "impact": chain.get("impact") or "",
            "feasible": bool(chain.get("feasible")),
            "e2e_ok_steps": e2e.get("e2e_ok_steps"),
        })
        await _log(
            task_id,
            f"⛓️ 攻击链#{i}: {obj.name} — findings={chain.get('finding_numbers')} feasible={chain.get('feasible')} e2e={e2e.get('e2e_ok_steps')}",
            "discovery",
        )

    state["attack_chains"] = saved
    state["status"] = "generating_report"
    Task.update(status="generating_report").where(Task.id == task_id).execute()
    return state


async def node_generate_report(state: AgentState) -> AgentState:
    """生成 HTML 漏洞报告 — 含完整漏洞详情 + Yakit 可导入数据包"""
    from reporter.html_report import generate_html_report

    task_id = state["task_id"]
    await _log(task_id, "📝 生成 HTML 漏洞报告...", "info")

    try:
        report_path = await generate_html_report(task_id)
    except Exception as e:
        import traceback
        await _log(task_id, f"⚠️ 报告生成失败: {e}\n{traceback.format_exc()[:300]}", "error")
        report_path = None

    task = Task.get_by_id(task_id)
    task.status = "completed"
    task.phase = "done"
    task.pause_reason = None
    task.total_findings = sum(1 for f in (state.get("findings") or []) if (f.get("verdict") if isinstance(f, dict) else getattr(f, "verdict", None)) == "confirmed")
    try:
        from storage.models import Finding as _Finding
        task.total_findings = _Finding.select().where((_Finding.task_id == task_id) & (_Finding.verdict == "confirmed")).count()
    except Exception:
        pass
    task.total_lines_audited = state.get("total_lines_audited", 0)
    task.completed_at = datetime.now()
    task.save()

    ProgressLog.create(
        task=task,
        message=f"✅ 任务完成！审计 {state.get('total_lines_audited', 0)} 行，发现 {task.total_findings} 个漏洞"
        + (f" | 报告: {report_path}" if report_path else ""),
        log_type="info",
    )

    await ws_manager.send_status_update(task_id, "completed", {
        "total_findings": task.total_findings,
        "total_lines_audited": task.total_lines_audited,
    })
    await ws_manager.send_report_ready(task_id, f"/api/tasks/{task_id}/report")
    await _log(task_id, "✅ 任务完成！点击下方链接下载 HTML 报告", "info")

    state["status"] = "completed"
    return state


# ============================================================
# 构建完整 LangGraph 图
# ============================================================
def build_graph():
    """主路径: collect → auth → setup → multi_agent → (supplement|attack_chain|paused) → report。"""
    from langgraph.graph import StateGraph, END

    builder = StateGraph(AgentState)

    builder.add_node("info_gather", node_info_gather)
    builder.add_node("source_collect", node_source_collect)
    builder.add_node("auth_acquire", node_auth_acquire)
    builder.add_node("setup_audit", node_setup_audit)
    builder.add_node("multi_agent_audit", node_multi_agent_audit)
    builder.add_node("supplement_collect", node_supplement_collect)
    builder.add_node("attack_chain", node_attack_chain)
    builder.add_node("generate_report", node_generate_report)

    builder.set_entry_point("info_gather")
    builder.add_edge("info_gather", "source_collect")
    builder.add_edge("source_collect", "auth_acquire")
    builder.add_edge("auth_acquire", "setup_audit")
    builder.add_edge("setup_audit", "multi_agent_audit")

    builder.add_conditional_edges(
        "multi_agent_audit",
        route_after_multi_agent,
        {
            "supplement_collect": "supplement_collect",
            "attack_chain": "attack_chain",
            "paused": END,
        },
    )
    # 补收后重新 setup → 再进多 Agent
    builder.add_edge("supplement_collect", "setup_audit")
    builder.add_edge("attack_chain", "generate_report")
    builder.add_edge("generate_report", END)

    return builder.compile()


# ============================================================
# 任务启动入口
# ============================================================
async def start_task(task_id: int, *, force_fresh: bool = False):
    """异步启动/恢复编排流程。

    恢复策略（WorkItem 队列）:
    - DB 已有收集文件 → skip 重采，加载 collected_files
    - 已 done 的 audit_file WorkItem 不重做
    - 半文件靠 CollectedFile.audit_start_line 续扫
    - LLM 熔断 → status=paused，可再次 start_task 恢复
    """
    try:
        from orchestrator import workqueue as wq

        task = Task.get_by_id(task_id)
        targets = json.loads(task.target)
        config = task.get_config()

        # 考试/环境强制无人值守，避免 human-loop 卡住
        if str(os.environ.get("EXAM_MODE", "")).strip().lower() in {"1", "true", "yes", "on"} \
            or str(os.environ.get("XINRU_UNATTENDED", "")).strip().lower() in {"1", "true", "yes", "on"}:
            if not config.get("unattended", True):
                config["unattended"] = True
                task.config = json.dumps(config, ensure_ascii=False)
                task.save()
            await _log(task_id, "🤖 EXAM/UNATTENDED 模式：全程不等人，自动跳过人工确认", "info")

        # 已完成直接返回
        if task.status == "completed" and not force_fresh:
            await _log(task_id, "✅ 任务已完成，无需重启（传 force_fresh 可重跑）", "info")
            return

        decision = {
            "mode": "fresh",
            "skip_collect": False,
            "skip_auth": False,
            "entry_phase": "collecting",
            "files": 0,
            "queue": {},
        }
        if not force_fresh:
            decision = wq.decide_resume_entry(task_id)

        # 若之前 paused，恢复记录
        if task.status == "paused":
            prev_reason = task.pause_reason
            wq.resume_task_record(task_id, phase=decision.get("entry_phase") or task.phase or "auditing")
            await _log(task_id, f"▶️ 从暂停恢复 — reason_was={prev_reason}", "info")

        wq.reclaim_expired(task_id)

        ProgressLog.create(
            task=task,
            message=f"🚀 xinru Agent 启动/恢复，目标: {targets} | mode={decision.get('mode')}",
            log_type="info",
        )
        await _log(task_id, "🚀 xinru Agent 已启动", "info")
        await _log(
            task_id,
            f"♻️ resume decision: mode={decision.get('mode')} files={decision.get('files')} "
            f"skip_collect={decision.get('skip_collect')} queue={decision.get('queue')}",
            "info",
        )
        await _log(task_id, f"🎯 目标: {', '.join(targets)}", "info")
        if config.get("brief"):
            await _log(task_id, "📋 任务说明: " + str(config.get("brief"))[:500], "info")
        if config.get("scope_name"):
            await _log(
                task_id,
                f"🧭 Scope: {config.get('scope_name')} | filter={config.get('filter_leads_by_scope', False)}",
                "info",
            )
        await _log(
            task_id,
            f"📋 配置: 认证A={'有' if config.get('credentials') or config.get('cookies') or config.get('credentials_a') or config.get('cookies_a') else '无'} | "
            f"认证B={'有' if config.get('credentials_b') or config.get('cookies_b') or (isinstance(config.get('accounts'), list) and len(config.get('accounts') or [])>=2) else '无'} | "
            f"子域名={config.get('subdomain_discovery', True)} | 路径爆破={config.get('path_brute', True)} | "
            f"自动注册={config.get('allow_register', False)} | 爆破={config.get('allow_brute', False)}",
            "info",
        )

        # 启动前已给的 Cookie 直接写入 state
        initial_cookies: dict[str, str] = {}
        if config.get("cookies"):
            for t in targets:
                initial_cookies[t] = config["cookies"]

        collected_files = []
        resume_mode = False
        if decision.get("skip_collect") and not force_fresh:
            collected_files = wq.load_collected_files(task_id)
            collected_files = [
                f for f in collected_files
                if f.get("local_path") and os.path.exists(f["local_path"])
            ]
            resume_mode = True
            if collected_files:
                Task.update(
                    total_files_collected=len(collected_files),
                    updated_at=datetime.now(),
                ).where(Task.id == task_id).execute()

        # 阶段标记
        entry_phase = decision.get("entry_phase") or "collecting"
        if resume_mode and collected_files:
            wq.set_phase(
                task_id,
                "authenticating" if entry_phase in {"authenticating", "auditing"} else entry_phase,
            )
        else:
            wq.set_phase(task_id, "collecting", status="collecting")

        initial_state: AgentState = {
            "task_id": task_id,
            "targets": targets,
            "status": "pending",
            "collected_files": collected_files,
            "yakit_flows_imported": 0,
            "cookies": initial_cookies,
            "sessions": {},
            "sorted_file_paths": [f.get("local_path") for f in collected_files if f.get("local_path")],
            "current_file_index": 0,
            "current_line": 0,
            "current_file_line_count": 0,
            "current_file_content": "",
            "findings": [],
            "active_threat": None,
            "attack_chains": [],
            "error": None,
            "total_lines_audited": int(task.total_lines_audited or 0),
            "files_completed": 0,
            "total_files": len(collected_files),
            "pending_leads": [],
            "processed_leads": [],
            "handled_threats": [],
            "return_marker": None,
            "current_file_path": "",
            "_endpoint": None,
            "resume_mode": resume_mode,
            "pause_reason": None,
        }

        graph = build_graph()
        # 无人值守长审计：逐段扫描会很多次节点跳转，必须抬高 recursion_limit
        await graph.ainvoke(
            initial_state,
            config={
                "recursion_limit": int(__import__("os").environ.get("XINRU_RECURSION_LIMIT", "20000")),
            },
        )

        # 结束后若仍 paused / 有未完成队列，保持可恢复状态
        task = Task.get_by_id(task_id)
        qstats = wq.queue_stats(task_id)
        if task.status == "paused":
            await _log(
                task_id,
                f"⏸️ 任务保持暂停，可再次 resume — {task.pause_reason} | queue={qstats}",
                "warning",
            )
            await ws_manager.send_status_update(
                task_id, "paused", {"reason": task.pause_reason, "queue": qstats}
            )
        elif qstats.get("unfinished", 0) > 0 and task.status not in {"completed", "failed", "cancelled"}:
            wq.set_phase(task_id, "auditing", status="auditing")
            await _log(task_id, f"⏳ 仍有未完成 WorkItem，状态保持 auditing | queue={qstats}", "warning")

    except Exception as e:
        import traceback
        error_msg = f"任务执行失败: {str(e)}\n{traceback.format_exc()}"
        # LLM/网络类错误 → paused 而不是 failed，便于 resume
        msg_l = str(e).lower()
        pause_like = any(
            k in msg_l
            for k in (
                "timeout", "temporar", "503", "502", "504", "429",
                "balance", "余额", "unauthorized", "401", "402",
                "connect", "network", "llm",
            )
        )
        try:
            from orchestrator import workqueue as wq
            task = Task.get_by_id(task_id)
            if pause_like:
                wq.pause_task(task_id, f"runtime_pause: {e}", phase=task.phase or "auditing")
                ProgressLog.create(task=task, message=error_msg, log_type="error")
                await _log(task_id, f"⏸️ 可恢复暂停: {e}", "warning")
                await ws_manager.send_status_update(task_id, "paused", {"error": str(e)})
                return
            task.status = "failed"
            task.save()
            ProgressLog.create(task=task, message=error_msg, log_type="error")
        except Exception:
            pass
        await _log(task_id, f"❌ {error_msg}", "error")
        await ws_manager.send_status_update(task_id, "failed", {"error": str(e)})


async def resume_task(task_id: int):
    """显式恢复入口 — 等价于 start_task(task_id)。"""
    return await start_task(task_id, force_fresh=False)
