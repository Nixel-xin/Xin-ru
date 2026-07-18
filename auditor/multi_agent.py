"""xinru 模式 B — WorkItem 可恢复多 Agent 审计

- 文件级 audit_file 队列 claim/complete
- 威胁/验证子单元 handle_threat、verify_endpoint 可跳过重做
- 全局广播 / 签名 / 凭证 / WAF 策略接入
"""

from __future__ import annotations

import asyncio
import json
import os
import traceback
from datetime import datetime
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

from storage.models import CollectedFile, Finding, Task


LogFn = Callable[[int, str, str], Awaitable[None]]


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except Exception:
        return default


def choose_worker_count(file_count: int) -> int:
    env = _env_int("XINRU_WORKERS", 0)
    if env > 0:
        return max(1, min(env, 8))
    if file_count <= 1:
        return 1
    if file_count <= 10:
        return 2
    if file_count <= 40:
        return 3
    return min(5, max(3, file_count // 15))


def should_use_multi_agent(file_count: int, total_lines: int = 0) -> bool:
    mode = (os.environ.get("XINRU_AUDIT_MODE") or "auto").lower()
    if mode in {"multi", "b", "mode_b"}:
        return True
    if mode in {"single", "c", "mode_c"}:
        return False
    # auto: xinru 规则
    if file_count > 30:
        return True
    if total_lines and total_lines > 30000:
        return True
    return file_count > 8


def _is_meta_file(path: str) -> bool:
    base = os.path.basename(path).lower()
    return base in {"manifest.json", "package.json", "package-lock.json"} or base.endswith(".meta.json")


async def _default_log(task_id: int, message: str, log_type: str = "info"):
    try:
        from storage.models import ProgressLog
        ProgressLog.create(task=task_id, message=message, log_type=log_type)
    except Exception:
        pass
    print(f"[task {task_id}] {message}", flush=True)


def _persist_file_cursor(task_id: int, file_path: str, line: int, done: bool = False):
    """写审计游标。兼容路径未规范化/字段缺失，避免静默失败。"""
    try:
        q = (
            CollectedFile.update(
                audit_start_line=line,
                is_audited=done,
            )
            .where((CollectedFile.task_id == task_id) & (CollectedFile.local_path == file_path))
        )
        n = q.execute()
        if n:
            return n
        # fallback: file_id / basename 兜底
        import os
        base = os.path.basename(file_path or "")
        dbf = (
            CollectedFile.select()
            .where(
                (CollectedFile.task_id == task_id)
                & (
                    (CollectedFile.local_path == file_path)
                    | (CollectedFile.file_name == base)
                )
            )
            .first()
        )
        if not dbf:
            return 0
        dbf.audit_start_line = line
        dbf.is_audited = bool(done)
        dbf.save()
        return 1
    except Exception as e:
        print(f"[persist_cursor] fail task={task_id} path={file_path}: {e}", flush=True)
        return 0


def _finding_fingerprint(file_path: str, line: int, name: str, endpoint: str = "") -> str:
    return f"{file_path}|{line}|{name}|{endpoint}"


def _pick_cookie(cookies: dict[str, str] | None, url: str) -> str:
    if not cookies:
        return ""
    try:
        host = (urlsplit(url).hostname or "").lower()
    except Exception:
        host = ""
    if url in cookies:
        return cookies[url]
    for k, v in cookies.items():
        if host and host in k:
            return v
        if k in {"default", "*", host}:
            return v
    # fallback first
    return next(iter(cookies.values()), "")


async def audit_one_file(
    *,
    task_id: int,
    file_path: str,
    file_index: int,
    total_files: int,
    cookies: dict[str, str] | None,
    sessions: dict | None,
    targets: list[str],
    all_file_paths: list[str],
    log: LogFn,
    worker_id: str,
    config: dict | None = None,
    batch_files: list[str] | None = None,
) -> dict[str, Any]:
    """子 Agent：单文件 xinru 循环。"""
    from auditor.xinru_loop import (
        quick_scan_lines,
        pick_next_unhandled,
        threat_key,
        llm_rescan_snippet,
        is_noise_file,
    )
    from auditor.call_chain import trace_call_chain
    from auditor.endpoint_locator import locate_from_trace, endpoint_to_request_args
    from auditor.self_check import run_self_check
    from auditor.preprocess import preprocess_file
    from auditor.status_card import get_tracker
    from auditor.discoveries import get_bus, publish_from_finding, publish_signature_key
    from auditor.signature import extract_signature_profiles, pick_profile, scan_files_for_signatures
    from auditor.credentials import get_store, is_auth_failure, handle_auth_failure
    from auditor.waf_policy import build_policy
    from auditor.batching import cross_batch_context
    from orchestrator.llm import call_llm_json, SYSTEM_PROMPT
    from yakit.verifier import yakit_verify_7steps

    result: dict[str, Any] = {
        "worker_id": worker_id,
        "file_path": file_path,
        "lines_audited": 0,
        "findings": [],
        "leads": [],
        "error": None,
        "completed": False,
        "high_value": [],
    }
    base = os.path.basename(file_path)
    config = config or {}
    tracker = get_tracker(task_id)
    bus = get_bus(task_id)
    store = get_store(task_id)
    policy = build_policy(config)

    if _is_meta_file(file_path):
        _persist_file_cursor(task_id, file_path, 1, done=True)
        await log(task_id, f"[{worker_id}] ⏭️ 跳过元数据: {base}", "info")
        result["completed"] = True
        return result

    # 凭证表暂停：仍扫代码，但验证阶段标无法验证
    paused = bool(store.paused)

    pre = preprocess_file(file_path, write_sidecar=True)
    content = pre.get("content") or ""
    if pre.get("error"):
        result["error"] = f"read failed: {pre['error']}"
        await log(task_id, f"[{worker_id}] ❌ 读文件失败 {base}: {pre['error']}", "error")
        return result
    if pre.get("beautified"):
        await log(task_id, f"[{worker_id}] ✨ 已美化压缩源码: {base} ({pre.get('original_lines')}→{pre.get('lines')})", "info")

    lines = content.split("\n")
    total = len(lines)
    resume = 0
    try:
        dbf = CollectedFile.select().where(
            (CollectedFile.task_id == task_id) & (CollectedFile.local_path == file_path)
        ).first()
        if dbf and dbf.is_audited:
            result["completed"] = True
            result["lines_audited"] = dbf.line_count or total
            return result
        if dbf and dbf.audit_start_line:
            resume = min(max(0, int(dbf.audit_start_line)), total)
    except Exception:
        resume = 0

    # 签名线索提取（文件级）
    default_domain = ""
    if targets:
        try:
            default_domain = urlsplit(targets[0]).hostname or ""
        except Exception:
            default_domain = ""
    try:
        local_profiles = extract_signature_profiles(content, file_path=file_path, domain=default_domain or "*")
        for prof in local_profiles:
            if prof.key:
                publish_signature_key(
                    task_id,
                    domain=prof.domain,
                    alg=prof.alg,
                    key=prof.key,
                    worker_id=worker_id,
                )
                result["high_value"].append({"type": "sign_key", "alg": prof.alg, "domain": prof.domain})
        if local_profiles:
            # 合并写入 helper
            scan_files_for_signatures(task_id, [file_path], default_domain=default_domain or "*")
    except Exception:
        pass

    await log(
        task_id,
        f"[{worker_id}] 📄 [{file_index}/{total_files}] 开始: {base} ({total} 行, resume={resume})",
        "info",
    )
    # 状态卡
    snap0 = tracker.make(
        file_path=file_path,
        line=max(resume, 1),
        total_lines=total,
        lines=lines,
        next_step="逐行扫描",
        worker_id=worker_id,
    )
    card0 = tracker.validate_and_commit(snap0)
    if card0.get("card"):
        await log(task_id, card0["card"], "info")

    # 广播快照
    broadcasts = bus.snapshot(for_worker=worker_id)
    if broadcasts:
        await log(task_id, f"[{worker_id}] 📡 已接收广播 {len(broadcasts)} 条", "info")

    handled: set[str] = set()
    line = resume
    batch = 12 if is_noise_file(file_path) else 20
    findings_local: list[dict] = []
    leads_local: list[dict] = []

    # 同批文件优先用于调用链
    chain_files = list(dict.fromkeys((batch_files or []) + list(all_file_paths or [])))

    while line < total:
        from orchestrator import workqueue as wq
        if wq.is_task_paused(task_id):
            result["error"] = "task paused"
            result["lines_audited"] = line
            _persist_file_cursor(task_id, file_path, line, done=False)
            await log(task_id, f"[{worker_id}] ⏸️ 任务暂停，停止当前文件 line={line}", "warning")
            return result
        if store.paused:
            paused = True

        end_line = min(line + batch, total)
        hits = quick_scan_lines(content, start_line=line, end_line=end_line, file_path=file_path)

        if not hits and not is_noise_file(file_path) and (line // batch) % 20 == 0:
            try:
                hits = await llm_rescan_snippet(
                    content, file_path, line, end_line, call_llm_json, SYSTEM_PROMPT
                )
            except Exception:
                hits = hits or []

        for h in hits:
            lead = h.get("_lead")
            if lead:
                item = dict(lead)
                item["source_file"] = file_path
                leads_local.append(item)

        hit = pick_next_unhandled(hits, handled)
        if not hit:
            line = end_line
            result["lines_audited"] = line
            if line % 80 < batch:
                _persist_file_cursor(task_id, file_path, line, done=False)
                snap = tracker.make(
                    file_path=file_path,
                    line=max(line, 1),
                    total_lines=total,
                    lines=lines,
                    next_step="继续扫描",
                    worker_id=worker_id,
                )
                tracker.validate_and_commit(snap)
            continue

        handled.add(threat_key(hit))
        threat_line = int(hit.get("line", line) or line)

        # ---- 可恢复子单元：handle_threat ----
        from orchestrator import workqueue as wq
        file_id = None
        try:
            dbf_now = CollectedFile.select().where(
                (CollectedFile.task_id == task_id) & (CollectedFile.local_path == file_path)
            ).first()
            file_id = dbf_now.id if dbf_now else None
        except Exception:
            file_id = None
        tkey = wq.threat_dedupe_key(
            file_id,
            file_path,
            threat_line,
            str(hit.get("pattern_name") or hit.get("pattern") or "threat"),
        )
        threat_item, threat_action = wq.begin_or_skip_item(
            task_id,
            "handle_threat",
            tkey,
            payload={
                "file_path": file_path,
                "file_id": file_id,
                "line": threat_line,
                "pattern_name": hit.get("pattern_name"),
                "pattern": hit.get("pattern"),
                "description": hit.get("description"),
            },
            worker=worker_id,
            priority=40,
        )
        if threat_action == "done":
            await log(
                task_id,
                f"[{worker_id}] ♻️ 跳过已完成威胁 {hit.get('pattern_name')} @ {base}:{threat_line}",
                "info",
            )
            line = min(int(threat_line) + 1, total)
            result["lines_audited"] = line
            _persist_file_cursor(task_id, file_path, line, done=False)
            continue
        if threat_action == "blocked" or wq.is_task_paused(task_id):
            result["error"] = "task paused during threat handling"
            result["lines_audited"] = line
            _persist_file_cursor(task_id, file_path, line, done=False)
            await log(task_id, f"[{worker_id}] ⏸️ 任务暂停，释放当前文件进度 line={line}", "warning")
            return result

        tracker.update_counts(found_delta=1)
        await log(
            task_id,
            f"[{worker_id}] 🚩 {hit.get('pattern_name')} @ {base}:{threat_line} — {str(hit.get('description', ''))[:100]}",
            "warning",
        )
        snap_t = tracker.make(
            file_path=file_path,
            line=threat_line,
            total_lines=total,
            lines=lines,
            next_step=f"追溯威胁 {hit.get('pattern_name')}",
            worker_id=worker_id,
            processing=1,
        )
        tracker.validate_and_commit(snap_t)

        # 追溯（同批优先；跨批通过主 Agent 协议）
        try:
            trace = await trace_call_chain(
                file_path=file_path,
                content=content,
                line_no=threat_line,
                threat=hit,
                file_paths=chain_files,
                default_domain=default_domain,
                call_llm_json=call_llm_json,
                system_prompt=SYSTEM_PROMPT,
            )
        except Exception as e:
            trace = {
                "error": str(e),
                "callers": [],
                "api_endpoint": {"method": "GET", "domain": "待定位", "path": "待定位"},
            }

        # 若调用链提示缺文件，尝试跨批取上下文再补一次轻量 trace 标记
        if isinstance(trace, dict) and trace.get("need_file"):
            ctx = cross_batch_context(all_file_paths, str(trace.get("need_file")), around=str(trace.get("need_func") or ""), window=50)
            if ctx.get("ok"):
                trace["cross_batch_context"] = ctx
                await log(task_id, f"[{worker_id}] 📦 跨批上下文: {ctx.get('path')}", "info")

        endpoint = locate_from_trace(
            trace,
            content=content,
            line_no=threat_line,
            default_targets=targets,
        )
        if isinstance(trace, dict):
            trace["api_endpoint"] = endpoint

        # 验证（可恢复子单元 verify_endpoint）
        evidence: list[dict] = []
        verify_item = None
        if endpoint.get("locatable") and not paused:
            req = endpoint_to_request_args(endpoint)
            full_url = req.get("url") or ""
            method = req.get("method") or "GET"
            vkey = wq.verify_dedupe_key(method, full_url)
            verify_item, v_action = wq.begin_or_skip_item(
                task_id,
                "verify_endpoint",
                vkey,
                payload={
                    "method": method,
                    "url": full_url,
                    "file_path": file_path,
                    "line": threat_line,
                    "threat_key": tkey,
                },
                worker=worker_id,
                priority=30,
            )
            if v_action == "done":
                evidence = (verify_item.get_result() or {}).get("evidence") or [
                    {
                        "step": "cached",
                        "request": f"{method} {full_url}",
                        "response": "reused",
                        "finding": "verify already done",
                    }
                ]
                await log(task_id, f"[{worker_id}] ♻️ 复用已完成验证 {method} {full_url}", "info")
            elif v_action == "blocked" or wq.is_task_paused(task_id):
                if threat_item is not None:
                    wq.fail_item(threat_item.id, "paused before verify", retryable=True)
                result["error"] = "task paused before verify"
                result["lines_audited"] = threat_line
                _persist_file_cursor(task_id, file_path, threat_line, done=False)
                return result
            else:
                headers = dict(req.get("headers") or {})
                body = req.get("body")
                params = req.get("params")
                cookie = _pick_cookie(cookies, full_url)
                token_header = None
                token_value = None
                for k, v in list(headers.items()):
                    if str(k).lower() in ("authorization", "token", "x-token", "access-token"):
                        token_header = k
                        token_value = v
                        break
                sess_a = sess_b = None
                try:
                    from collector.accounts import pick_session
                    sess_a = pick_session(sessions or {}, full_url, "A")
                    sess_b = pick_session(sessions or {}, full_url, "B")
                    if sess_a and sess_a.get("cookies") and not cookie:
                        cookie = sess_a.get("cookies") or ""
                    if sess_a and sess_a.get("token") and not token_value:
                        token_header = sess_a.get("token_header") or token_header or "Authorization"
                        token_value = sess_a.get("token")
                except Exception:
                    pass

                # 凭证表补充
                rec = store.pick(full_url, "A")
                if rec:
                    if rec.cookies and not cookie:
                        cookie = rec.cookies
                    if rec.token and not token_value:
                        token_header = rec.token_header or "Authorization"
                        token_value = rec.token
                    if rec.headers:
                        headers.update(rec.headers)

                # 广播 token 注入
                for bcast in bus.high_value():
                    if bcast.get("type") == "universal_token":
                        tok = (bcast.get("payload") or {}).get("token")
                        if tok and not token_value:
                            token_header = token_header or "Authorization"
                            token_value = tok

                sign_prof = pick_profile(task_id, full_url)

                async def _on_auth_failure(**kwargs):
                    return await handle_auth_failure(
                        task_id,
                        url=kwargs.get("url") or full_url,
                        role=kwargs.get("role") or "A",
                        status=kwargs.get("status"),
                        body=kwargs.get("body") or "",
                        config=config,
                        unattended=True,
                    )

                await log(task_id, f"[{worker_id}] ⚡ 验证 {method} {full_url}", "info")
                try:
                    evidence = await yakit_verify_7steps(
                        method=method,
                        url=full_url,
                        headers=headers,
                        body=body if isinstance(body, str) or body is None else str(body),
                        params=params if isinstance(params, dict) else None,
                        cookies=cookie or None,
                        token_header=token_header,
                        token_value=token_value,
                        session_a=sess_a,
                        session_b=sess_b,
                        task_id=task_id,
                        waf_policy=policy,
                        signature_profile=sign_prof,
                        on_auth_failure=_on_auth_failure,
                        config=config,
                    )
                    # 失效标记
                    for ev in evidence:
                        sc = ev.get("status_code")
                        if is_auth_failure(sc, ""):
                            store.mark_invalid(full_url, "A", sc, reason="verify auth failure")
                            break
                    if verify_item is not None:
                        wq.complete_item(
                            verify_item.id,
                            {
                                "method": method,
                                "url": full_url,
                                "evidence": evidence,
                            },
                        )
                except Exception as e:
                    evidence = [{"step": "error", "request": "", "response": str(e), "finding": f"验证异常: {e}"}]
                    if verify_item is not None:
                        wq.fail_item(verify_item.id, str(e), retryable=True, result={"evidence": evidence})
        elif paused:
            await log(task_id, f"[{worker_id}] ⛔ 凭证暂停中，跳过发包验证", "warning")
            evidence = [{"step": "auth_paused", "request": "", "response": store.pause_reason, "finding": "凭证失效暂停，无法验证"}]
        else:
            await log(task_id, f"[{worker_id}] ⚡ 跳过验证 — 未定位可访问 URL", "warning")
            evidence = [{"step": "locate", "request": "", "response": "", "finding": "接口未定位，无法发包"}]

        # 自检
        try:
            check = await run_self_check(
                threat=hit,
                trace=trace if isinstance(trace, dict) else {},
                verify_results=evidence,
                file_path=file_path,
                endpoint=endpoint,
                call_llm_json=call_llm_json,
                system_prompt=SYSTEM_PROMPT,
            )
        except Exception as e:
            check = {
                "verdict": "uncertain",
                "severity": hit.get("severity_guess") or "medium",
                "reason": f"自检异常: {e}",
                "attack_impact": "",
                "fix_suggestion": "",
            }

        verdict = (check or {}).get("verdict") or "uncertain"
        severity = (check or {}).get("severity") or hit.get("severity_guess") or "medium"
        reason = (check or {}).get("reason") or (check or {}).get("attack_impact") or ""
        wy_ref = (check or {}).get("wooyun_reference") or ""
        wy_guide = (check or {}).get("wooyun_guidance") or ""
        if wy_ref and wy_ref not in reason:
            reason = (reason + f" | 乌云对照: {wy_ref}").strip(" |")

        # 非状态码二次收敛：静态 200 不 confirmed
        try:
            from yakit.verifier import classify_response
            staticish = False
            for ev in evidence:
                cls = ev.get("class") or {}
                if cls.get("is_static") and ev.get("status_code") == 200:
                    staticish = True
            if staticish and verdict == "confirmed":
                verdict = "excluded"
                reason = (reason + " | 静态资源 200 不记高危").strip(" |")
        except Exception:
            pass

        finding = {
            "name": hit.get("pattern_name") or "可疑点",
            "severity": severity,
            "file_path": file_path,
            "line_number": int(threat_line) + 1,  # 报告 1-based
            "call_chain": json.dumps(trace, ensure_ascii=False) if not isinstance(trace, str) else trace,
            "api_endpoint": json.dumps(endpoint, ensure_ascii=False),
            "parameters": json.dumps((endpoint or {}).get("params") or {}, ensure_ascii=False),
            "verdict": verdict,
            "yakit_evidence": json.dumps(evidence, ensure_ascii=False),
            "attack_impact": reason,
            "fix_suggestion": ((check or {}).get("fix_suggestion") or "") + (f"\n乌云参考: {wy_guide}" if wy_guide else ""),
            "worker_id": worker_id,
        }
        findings_local.append(finding)

        if verdict == "confirmed":
            tracker.update_counts(confirmed=1)
        elif verdict == "excluded":
            tracker.update_counts(excluded=1)
        else:
            tracker.update_counts(uncertain=1)

        # 广播
        try:
            pubs = publish_from_finding(task_id, finding, worker_id=worker_id)
            if pubs:
                result["high_value"].extend(pubs)
                await log(task_id, f"[{worker_id}] 📡 广播 {len(pubs)} 条高价值发现", "discovery")
        except Exception:
            pass

        icon = "✅" if verdict == "confirmed" else ("⚠️" if verdict == "uncertain" else "❌")
        await log(
            task_id,
            f"[{worker_id}] {icon} {verdict} — {finding['name']} @ {base}:{threat_line} | {reason[:120]}",
            "discovery" if verdict == "confirmed" else "info",
        )

        # 威胁子单元完成
        try:
            if threat_item is not None:
                wq.complete_item(
                    threat_item.id,
                    {
                        "file_path": file_path,
                        "line": threat_line,
                        "pattern_name": hit.get("pattern_name"),
                        "verdict": finding.get("verdict"),
                        "name": finding.get("name"),
                    },
                )
        except Exception:
            pass

        # 回流：hit.line 为 0-based，处理完必须回到 N+1
        line = min(int(threat_line) + 1, total)
        result["lines_audited"] = line
        _persist_file_cursor(task_id, file_path, line, done=False)

        # 协作式暂停：处理完当前威胁后立刻停
        if wq.is_task_paused(task_id):
            result["error"] = "task paused after threat"
            await log(task_id, f"[{worker_id}] ⏸️ 任务暂停，文件进度停在 line={line}", "warning")
            return result

        snap_r = tracker.make(
            file_path=file_path,
            line=min(line + 1, total),  # 展示用 1-based
            total_lines=total,
            lines=lines,
            next_step="回到原位继续扫描",
            worker_id=worker_id,
        )
        tracker.validate_and_commit(snap_r)

    _persist_file_cursor(task_id, file_path, total, done=True)
    result["lines_audited"] = total
    result["findings"] = findings_local
    result["leads"] = leads_local
    result["completed"] = True
    await log(
        task_id,
        f"[{worker_id}] ✔️ 完成 {base} — findings={len(findings_local)} leads={len(leads_local)}",
        "info",
    )
    return result



def _upsert_finding(task_id: int, f: dict) -> bool:
    """写入 finding；已存在则跳过。返回是否新建。"""
    try:
        file_path = f.get("file_path") or ""
        line_number = int(f.get("line_number") or 0)
        name = f.get("name") or "finding"
        exists = Finding.select().where(
            (Finding.task_id == task_id)
            & (Finding.file_path == file_path)
            & (Finding.line_number == line_number)
            & (Finding.name == name)
        ).first()
        if exists:
            return False

        api_endpoint = f.get("api_endpoint") or ""
        if not isinstance(api_endpoint, str):
            api_endpoint = json.dumps(api_endpoint, ensure_ascii=False)

        call_chain = f.get("call_chain") or {}
        if not isinstance(call_chain, str):
            call_chain = json.dumps(call_chain, ensure_ascii=False)

        parameters = f.get("parameters") or {}
        if not isinstance(parameters, str):
            parameters = json.dumps(parameters, ensure_ascii=False)

        yakit_evidence = f.get("yakit_evidence") or []
        if not isinstance(yakit_evidence, str):
            yakit_evidence = json.dumps(yakit_evidence, ensure_ascii=False)

        n = Finding.select().where(Finding.task_id == task_id).count() + 1
        Finding.create(
            task=task_id,
            finding_number=n,
            fingerprint=_finding_fingerprint(
                file_path,
                line_number,
                name,
                str(api_endpoint)[:120],
            ),
            name=name,
            severity=f.get("severity") or "medium",
            file_path=file_path,
            line_number=line_number,
            call_chain=call_chain,
            api_endpoint=api_endpoint,
            parameters=parameters,
            verdict=f.get("verdict") or "uncertain",
            yakit_evidence=yakit_evidence,
            attack_impact=f.get("attack_impact") or "",
            fix_suggestion=f.get("fix_suggestion") or "",
        )
        return True
    except Exception:
        return False



async def run_multi_agent_audit(
    *,
    task_id: int,
    file_paths: list[str],
    cookies: dict[str, str] | None = None,
    sessions: dict | None = None,
    targets: list[str] | None = None,
    log: LogFn | None = None,
    config: dict | None = None,
) -> dict[str, Any]:
    """主 Agent 调度器 — WorkItem 队列 + 可恢复并行审计。

    每个未完成文件对应一个 audit_file WorkItem:
    - done 的永不重做
    - 崩溃后 lease 过期自动 reclaim → pending
    - 任务 paused（LLM 熔断等）时停止领取新 item
    """
    from auditor.preprocess import expand_inventory, inventory_stats
    from auditor.signature import scan_files_for_signatures
    from auditor.discoveries import get_bus
    from auditor.credentials import get_store
    from auditor.waf_policy import build_policy
    from orchestrator import workqueue as wq

    log = log or _default_log
    targets = targets or []
    config = config or {}

    files = expand_inventory([p for p in file_paths if p])
    if not files:
        return {"findings": [], "leads": [], "files_completed": 0, "lines_audited": 0, "workers": 0, "batches": 0}

    stats = inventory_stats(files)
    await log(
        task_id,
        f"📋 文件清单 — files={stats['files']} lines≈{stats['total_lines_est']} large={stats['large_files']} by_ext={stats['by_ext']}",
        "info",
    )

    # 签名全局预扫描（utils 优先）
    default_domain = ""
    if targets:
        try:
            default_domain = urlsplit(targets[0]).hostname or ""
        except Exception:
            default_domain = ""
    try:
        profiles = scan_files_for_signatures(task_id, files[:200], default_domain=default_domain or "*")
        if profiles:
            await log(task_id, f"🔏 预提取签名配置 {len(profiles)} 条 → .xinru/sign_helper.py", "info")
    except Exception as e:
        await log(task_id, f"⚠️ 签名预扫描失败: {e}", "warning")

    store = get_store(task_id)
    policy = build_policy(config)
    await log(
        task_id,
        f"🛡️ WAF策略 authorized={policy.authorized} interval={policy.min_interval_sec}s mutate={policy.mutate_headers} | 凭证valid={len(store.list_valid())} paused={store.paused}",
        "info",
    )

    # ---- 入队 + 回收过期 lease ----
    wq.reclaim_expired(task_id)
    enq = wq.enqueue_audit_files(task_id, files)
    qstats = wq.queue_stats(task_id)
    await log(
        task_id,
        f"📦 WorkItem 入队 audit_file: created={enq.get('created',0)} audited_skip={enq.get('skipped_audited',0)} "
        f"done_skip={enq.get('skipped_done',0)} | queue={qstats}",
        "info",
    )

    workers_n = choose_worker_count(len(files))
    workers_n = max(1, min(workers_n, 8))
    await log(
        task_id,
        f"🧠 可恢复多 Agent 启动 — 文件 {len(files)}，workers={workers_n}，未完成={qstats.get('unfinished',0)}",
        "info",
    )
    bus = get_bus(task_id)
    await log(task_id, f"📡 发现广播通道就绪: {bus.path}", "info")

    try:
        wq.set_phase(task_id, "auditing", status="auditing")
    except Exception:
        pass

    findings_all: list[dict] = []
    leads_all: list[dict] = []
    counters = {"lines_total": 0, "completed": 0, "failed": 0, "claimed": 0}
    lock = asyncio.Lock()
    stop_event = asyncio.Event()

    async def _worker_loop(worker_name: str):
        wid = wq.worker_id(worker_name)
        while not stop_event.is_set():
            if wq.is_task_paused(task_id):
                await log(task_id, f"[{wid}] ⏸️ 任务已暂停，停止领取新 WorkItem", "warning")
                break

            item = wq.claim_next(task_id, wid, item_types=["audit_file"])
            if not item:
                # 可能暂时没有 pending；若仍有 running 则稍等，否则退出
                st = wq.queue_stats(task_id)
                if st.get("pending", 0) == 0 and st.get("running", 0) == 0:
                    break
                await asyncio.sleep(0.5)
                # 再回收一次过期 lease
                wq.reclaim_expired(task_id)
                continue

            async with lock:
                counters["claimed"] += 1
                claim_no = counters["claimed"]

            payload = item.get_payload()
            path = payload.get("file_path") or ""
            base = os.path.basename(path) if path else f"item-{item.id}"
            await log(
                task_id,
                f"[{wid}] ▶️ claim#{claim_no} item={item.id} attempt={item.attempts} file={base}",
                "info",
            )

            # 心跳任务：长审计时续约 lease
            hb_stop = asyncio.Event()

            async def _hb():
                while not hb_stop.is_set():
                    await asyncio.sleep(max(15, int(os.environ.get("XINRU_WORKITEM_LEASE_SEC", "180")) // 3))
                    if hb_stop.is_set():
                        break
                    ok = wq.heartbeat(item.id, wid)
                    if not ok:
                        break

            hb_task = asyncio.create_task(_hb())
            try:
                res = await audit_one_file(
                    task_id=task_id,
                    file_path=path,
                    file_index=claim_no,
                    total_files=len(files),
                    cookies=cookies,
                    sessions=sessions,
                    targets=targets,
                    all_file_paths=files,
                    log=log,
                    worker_id=f"{wid}/F{item.id}",
                    config=config,
                    batch_files=files,
                )
            except Exception as e:
                res = {
                    "worker_id": wid,
                    "file_path": path,
                    "lines_audited": 0,
                    "findings": [],
                    "leads": [],
                    "error": f"{e}\n{traceback.format_exc()[:300]}",
                    "completed": False,
                }
                await log(task_id, f"[{wid}] ❌ 子 Agent 异常 {base}: {e}", "error")
            finally:
                hb_stop.set()
                try:
                    hb_task.cancel()
                except Exception:
                    pass

            # LLM / 任务暂停：当前 item 可重试，不标 failed 永久失败
            if wq.is_task_paused(task_id):
                wq.fail_item(
                    item.id,
                    error=f"task paused during audit: {(res or {}).get('error') or 'paused'}",
                    retryable=True,
                    result={"partial": True, "file_path": path, "lines_audited": int((res or {}).get("lines_audited") or 0)},
                )
                await log(task_id, f"[{wid}] ⏸️ item={item.id} 因任务暂停释放回队列", "warning")
                break

            err = (res or {}).get("error")
            completed = bool((res or {}).get("completed"))
            if completed and not err:
                try:
                    wq.note_llm_success(task_id)
                except Exception:
                    pass
                wq.complete_item(
                    item.id,
                    {
                        "file_path": path,
                        "lines_audited": int((res or {}).get("lines_audited") or 0),
                        "findings": len((res or {}).get("findings") or []),
                        "leads": len((res or {}).get("leads") or []),
                    },
                )
            else:
                # 未完成：可重试（依赖 audit_start_line 续扫）
                err_s = str(err or "audit incomplete")
                # LLM 失败累计；达到阈值会 pause 任务
                if any(k in err_s.lower() for k in (
                    "llm", "openai", "timeout", "429", "503", "502", "504",
                    "balance", "余额", "unauthorized", "401", "402", "json",
                )):
                    try:
                        info = wq.note_llm_failure(task_id, err_s)
                        if info.get("paused"):
                            await log(
                                task_id,
                                f"⏸️ LLM 熔断暂停任务 streak={info.get('streak')} fatal={info.get('fatal')}: {err_s[:180]}",
                                "warning",
                            )
                    except Exception:
                        pass
                else:
                    try:
                        wq.note_llm_success(task_id)
                    except Exception:
                        pass
                wq.fail_item(
                    item.id,
                    error=err_s,
                    retryable=True,
                    result={
                        "file_path": path,
                        "lines_audited": int((res or {}).get("lines_audited") or 0),
                        "completed": completed,
                    },
                )
                async with lock:
                    counters["failed"] += 1

            async with lock:
                findings_all.extend((res or {}).get("findings") or [])
                leads_all.extend((res or {}).get("leads") or [])
                counters["lines_total"] += int((res or {}).get("lines_audited") or 0)
                if completed:
                    counters["completed"] += 1

                for f in (res or {}).get("findings") or []:
                    _upsert_finding(task_id, f)


                try:
                    Task.update(
                        total_lines_audited=max(
                            int(Task.get_by_id(task_id).total_lines_audited or 0),
                            counters["lines_total"],
                        ),
                        total_findings=Finding.select().where(Finding.task_id == task_id).count(),
                        updated_at=datetime.now(),
                    ).where(Task.id == task_id).execute()
                except Exception:
                    pass

    worker_tasks = [
        asyncio.create_task(_worker_loop(f"W{i+1}"))
        for i in range(workers_n)
    ]
    await asyncio.gather(*worker_tasks)
    stop_event.set()

    qstats_end = wq.queue_stats(task_id)
    paused = wq.is_task_paused(task_id)
    await log(
        task_id,
        f"🧠 多 Agent 审计结束 — completed={counters['completed']} claimed={counters['claimed']} "
        f"failed_retryable={counters['failed']} lines={counters['lines_total']} "
        f"findings={len(findings_all)} queue={qstats_end} paused={paused}",
        "warning" if paused else "info",
    )
    return {
        "findings": findings_all,
        "leads": leads_all,
        "files_completed": counters["completed"],
        "lines_audited": counters["lines_total"],
        "workers": workers_n,
        "batches": qstats_end.get("total", 0),
        "broadcasts": len(bus.broadcasts),
        "inventory": stats,
        "queue": qstats_end,
        "paused": paused,
        "claimed": counters["claimed"],
    }
