"""结论自检引擎 — 规则兜底 + LLM 5问"""

from __future__ import annotations

import json
import re
from typing import Any


def _summarize_evidence(verify_results: list[dict] | None) -> str:
    if not verify_results:
        return "无验证数据"
    parts = []
    for ev in verify_results[:12]:
        parts.append(f"- {ev.get('step', '?')}: {ev.get('finding', '?')}")
    return "\n".join(parts)


def _status_from_finding(text: str) -> int | None:
    m = re.search(r"→\s*(\d{3})", text or "")
    if m:
        return int(m.group(1))
    m = re.search(r"\b(\d{3})\b", text or "")
    return int(m.group(1)) if m else None



def evidence_has_exploit_signal(verify_results: list[dict] | None) -> tuple[bool, str]:
    """验证证据是否足以确认“有漏洞”。

    工具不限（Yakit/httpx/curl 均可），关键是出现可利用业务信号。
    """
    verify_results = verify_results or []
    if not verify_results:
        return False, "无验证数据"

    def _is_business_open(v: dict) -> bool:
        cls = v.get("class") if isinstance(v.get("class"), dict) else None
        if cls is not None:
            return bool(cls.get("business_open"))
        finding = str(v.get("finding", ""))
        return ("业务数据可达" in finding) or ("⚠️" in finding and "静态" not in finding)

    signals = []
    for v in verify_results:
        step = str(v.get("step", ""))
        finding = str(v.get("finding", ""))
        if "请求失败" in finding or "验证异常" in finding:
            continue
        if "静态资源" in finding:
            continue
        if _is_business_open(v):
            signals.append(f"{step}:{finding}")
            continue
        if "注入" in step and ("⚠️" in finding or "异常" in finding):
            signals.append(f"{step}:{finding}")
            continue
        if ("越权" in step or "交叉" in step or "B对象" in step) and ("⚠️" in finding or _is_business_open(v)):
            signals.append(f"{step}:{finding}")
    if signals:
        return True, "；".join(signals[:6])
    return False, "验证未出现可利用业务信号"


def finalize_verdict(
    result: dict[str, Any] | None,
    *,
    verify_results: list[dict] | None = None,
    threat: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """铁律：验证后最终只能是 confirmed(有) / excluded(没有)。

    - 有可利用验证信号 → confirmed
    - 否则 → excluded
    - uncertain / 其他值一律收敛
    """
    result = dict(result or {})
    verify_results = verify_results or []
    threat = threat or {}
    verdict = str(result.get("verdict") or "").strip().lower()
    has_exploit, exploit_reason = evidence_has_exploit_signal(verify_results)

    # 静态资源等已 excluded 保持
    if verdict == "excluded" and not has_exploit:
        result["verdict"] = "excluded"
        result.setdefault("reason", "已排除")
        return result

    if has_exploit:
        result["verdict"] = "confirmed"
        if verdict != "confirmed":
            result["reason"] = (
                (result.get("reason") or "") + f" | finalized: exploit_evidence ({exploit_reason})"
            ).strip(" |")
        return result

    # 无利用证据：一律没有
    result["verdict"] = "excluded"
    if verdict in {"", "uncertain", "confirmed"}:
        extra = "finalized: no exploit evidence after verification → excluded"
        if not verify_results:
            extra = "finalized: missing verification evidence → excluded"
        result["reason"] = ((result.get("reason") or "") + " | " + extra).strip(" |")
        # 硬编码密钥但打不穿接口：降为信息级排除，不当正式漏洞
        pname = str(threat.get("pattern_name") or threat.get("pattern") or "")
        if "硬编码" in pname or str(threat.get("pattern") or "").startswith("A1"):
            result["severity"] = "info"
            result["attack_impact"] = result.get("attack_impact") or "发现硬编码线索，但验证未证明可利用影响"
            result["fix_suggestion"] = result.get("fix_suggestion") or "轮换并移除前端密钥；当前未验证到可利用链路"
    return result


def rule_based_self_check(
    *,
    threat: dict[str, Any],
    trace: dict[str, Any] | None,
    verify_results: list[dict] | None,
    endpoint: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """无人值守兜底：没有 LLM 也能基于证据给 verdict。"""
    threat = threat or {}
    trace = trace or {}
    endpoint = endpoint or (trace.get("api_endpoint") if isinstance(trace.get("api_endpoint"), dict) else {}) or {}
    verify_results = verify_results or []

    findings = " | ".join(str(v.get("finding", "")) for v in verify_results)
    statuses = []
    for v in verify_results:
        st = _status_from_finding(str(v.get("finding", "")))
        if st is not None:
            statuses.append(st)

    # 语义级证据：优先 class 字段，避免静态 200 误报
    def _is_business_open(v: dict) -> bool:
        cls = v.get("class") if isinstance(v.get("class"), dict) else None
        if cls is not None:
            return bool(cls.get("business_open"))
        finding = str(v.get("finding", ""))
        return ("200" in finding and "静态" not in finding and "业务数据可达" in finding) or (
            "200" in finding and "⚠️" in finding and "静态" not in finding
        )

    no_auth_open = any("无认证" in str(v.get("step", "")) and _is_business_open(v) for v in verify_results)
    dual_idor = any(("交叉" in str(v.get("step", "")) or "越权" in str(v.get("step", "")) or "B对象" in str(v.get("step", ""))) and ("⚠️" in str(v.get("finding", "")) or _is_business_open(v)) for v in verify_results)
    param_weak = any(("空参数" in str(v.get("step", "")) or "假参数" in str(v.get("step", ""))) and _is_business_open(v) for v in verify_results)
    static_only = bool(verify_results) and all(
        (isinstance(v.get("class"), dict) and v.get("class", {}).get("is_static"))
        or "静态资源" in str(v.get("finding", ""))
        for v in verify_results if v.get("finding")
    )
    inject_hit = any("注入" in str(v.get("step", "")) and ("⚠️" in str(v.get("finding", "")) or "异常" in str(v.get("finding", ""))) for v in verify_results)
    all_fail = bool(verify_results) and all("请求失败" in str(v.get("finding", "")) or "验证异常" in str(v.get("finding", "")) for v in verify_results)
    only_auth_block = bool(statuses) and all(s in (401, 403) for s in statuses)

    locatable = bool(endpoint.get("full_url") or (endpoint.get("domain") not in (None, "", "待定位") and endpoint.get("path") not in (None, "", "待定位")))
    if static_only:
        return {
            "verdict": "excluded",
            "severity": "info",
            "attack_impact": "静态资源可达，不构成业务漏洞",
            "fix_suggestion": "无需修复或仅做资产收敛",
            "reason": "验证命中均为静态资源 200",
            "answers": {
                "auth_carrier": "无",
                "attacker_can_satisfy": False,
                "no_skipped_steps": True,
                "simpler_explanation": "静态文件",
                "chainable": False,
            },
        }

    pattern = str(threat.get("pattern") or "")
    pattern_name = str(threat.get("pattern_name") or "未知威胁")

    # 硬编码密钥：仅当验证证明可利用才 confirmed；否则 excluded
    if pattern.startswith("A1") or "硬编码" in pattern_name:
        if no_auth_open or param_weak:
            return {
                "verdict": "confirmed",
                "severity": "high",
                "attack_impact": "硬编码凭据可被提取并用于伪造请求/签名",
                "fix_suggestion": "移除前端硬编码密钥，改为服务端保管并轮换",
                "reason": "源码硬编码 + 验证显示接口保护弱",
                "answers": {
                    "auth_carrier": "可能依赖硬编码 secret/token",
                    "attacker_can_satisfy": True,
                    "no_skipped_steps": True,
                    "simpler_explanation": "无",
                    "chainable": True,
                },
            }
        return {
            "verdict": "excluded",
            "severity": "info",
            "attack_impact": "前端暴露密钥/token 线索，但验证未证明可利用影响",
            "fix_suggestion": "移除前端硬编码密钥并轮换；未形成可利用链路前不记正式漏洞",
            "reason": "硬编码线索存在，但无接口利用验证成功",
            "answers": {
                "auth_carrier": "硬编码凭据",
                "attacker_can_satisfy": False,
                "no_skipped_steps": bool(verify_results),
                "simpler_explanation": "密钥暴露线索，未验证利用",
                "chainable": False,
            },
        }

    if not locatable:
        return {
            "verdict": "excluded",
            "severity": threat.get("severity_guess") or "low",
            "attack_impact": "尚未定位到可复现接口，无法确认漏洞",
            "fix_suggestion": "补充接口定位后再验证；当前不记正式漏洞",
            "reason": "endpoint 未定位，验证无法完成",
            "answers": {
                "auth_carrier": "未知",
                "attacker_can_satisfy": False,
                "no_skipped_steps": False,
                "simpler_explanation": "仅源码可疑，未形成可打点",
                "chainable": False,
            },
        }

    if all_fail:
        return {
            "verdict": "excluded",
            "severity": threat.get("severity_guess") or "low",
            "attack_impact": "验证请求失败，无法确认可利用性",
            "fix_suggestion": "检查网络/域名/证书后重测；当前不记正式漏洞",
            "reason": "全部验证请求失败，按无漏洞收敛",
            "answers": {
                "auth_carrier": "未知",
                "attacker_can_satisfy": False,
                "no_skipped_steps": False,
                "simpler_explanation": "网络问题或 endpoint 错误",
                "chainable": False,
            },
        }

    if only_auth_block and not no_auth_open:
        return {
            "verdict": "excluded",
            "severity": "info",
            "attack_impact": "接口当前返回 401/403，未证明可未授权访问",
            "fix_suggestion": "保持鉴权，并确保错误信息不泄露",
            "reason": "验证显示鉴权生效",
            "answers": {
                "auth_carrier": "Token/Cookie（返回401/403）",
                "attacker_can_satisfy": False,
                "no_skipped_steps": True,
                "simpler_explanation": "正常鉴权失败",
                "chainable": False,
            },
        }

    if no_auth_open or param_weak or inject_hit or dual_idor:
        severity = "high" if (no_auth_open or inject_hit or dual_idor) else "medium"
        return {
            "verdict": "confirmed",
            "severity": severity,
            "attack_impact": findings[:300] or "接口保护不足，攻击者可直接探测/篡改参数",
            "fix_suggestion": "补齐鉴权、参数校验、对象级授权与输出编码",
            "reason": "Yakit/HTTP 验证出现可利用信号",
            "answers": {
                "auth_carrier": "弱/无" if no_auth_open else "有认证但参数校验弱",
                "attacker_can_satisfy": True,
                "no_skipped_steps": True,
                "simpler_explanation": "需排除健康检查/公共接口误报",
                "chainable": True,
            },
        }

    return {
        "verdict": "excluded",
        "severity": threat.get("severity_guess") or "low",
        "attack_impact": "存在可疑代码，但验证未证明可利用",
        "fix_suggestion": "保持现有防护；若业务敏感可补充鉴权与参数校验",
        "reason": "证据不足，验证未确认漏洞",
        "answers": {
            "auth_carrier": "未知/混合",
            "attacker_can_satisfy": False,
            "no_skipped_steps": bool(verify_results),
            "simpler_explanation": "可能是正常业务代码",
            "chainable": False,
        },
    }


def _with_wooyun(result, threat, endpoint, verify_results):
    """xinru: Yakit 验证后必须过乌云对照锚点。"""
    try:
        from auditor.wooyun_kb import lookup_wooyun, apply_wooyun_constraints, format_wooyun_for_prompt
        wooyun = lookup_wooyun(
            threat or {},
            name=str((threat or {}).get("pattern_name") or ""),
            endpoint=endpoint or {},
            evidence=verify_results or [],
        )
        out = apply_wooyun_constraints(result or {}, wooyun, threat=threat or {})
        out["wooyun"] = {
            "domain": wooyun.get("domain"),
            "reference": wooyun.get("reference"),
            "case_style": wooyun.get("case_style"),
            "guidance": format_wooyun_for_prompt(wooyun)[:1200],
            "available": wooyun.get("available"),
        }
        return out
    except Exception as e:
        result = dict(result or {})
        result["reason"] = (str(result.get("reason") or "") + f" | wooyun_failed: {e}").strip(" |")
        return result


async def run_self_check(
    *,
    threat: dict[str, Any],
    trace: dict[str, Any] | None,
    verify_results: list[dict] | None,
    file_path: str,
    endpoint: dict[str, Any] | None = None,
    call_llm_json=None,
    system_prompt: str = "",
) -> dict[str, Any]:
    import asyncio
    from auditor.threat_patterns import SELF_CHECK_PROMPT

    base = rule_based_self_check(
        threat=threat,
        trace=trace,
        verify_results=verify_results,
        endpoint=endpoint,
    )
    if not call_llm_json:
        return _with_wooyun(finalize_verdict(base, verify_results=verify_results, threat=threat), threat, endpoint, verify_results)

    try:
        # 乌云对照上下文注入
        try:
            from auditor.wooyun_kb import lookup_wooyun, format_wooyun_for_prompt
            _wy = lookup_wooyun(threat, endpoint=endpoint or {}, evidence=verify_results or [])
            _wy_text = format_wooyun_for_prompt(_wy)
        except Exception:
            _wy_text = ""
        prompt = SELF_CHECK_PROMPT.format(
            finding_name=threat.get("pattern_name", "未知"),
            file_path=file_path,
            line_number=threat.get("line", 0),
            pattern=threat.get("pattern", "?"),
            call_chain=json.dumps(trace or {}, ensure_ascii=False)[:1500],
            api_endpoint=json.dumps(endpoint or (trace or {}).get("api_endpoint") or {}, ensure_ascii=False)[:800],
            yakit_results=_summarize_evidence(verify_results),
        )
        if _wy_text:
            prompt = prompt + "\n\n【乌云/wooyun-legacy 对照锚点】\n" + _wy_text + "\n请按上述确认要求/排除条件约束 verdict，禁止仅凭 200 确认。\n"
        result = await asyncio.wait_for(
            asyncio.to_thread(call_llm_json, system_prompt, prompt),
            timeout=90,
        )
        if not isinstance(result, dict):
            return _with_wooyun(finalize_verdict(base, verify_results=verify_results, threat=threat), threat, endpoint, verify_results)
        # 防止 LLM 在证据很弱时胡乱 confirmed：规则是 excluded 时不被 LLM 抬到 confirmed
        if base.get("verdict") == "excluded" and result.get("verdict") == "confirmed":
            # 规则已排除时，不允许 LLM 直接抬升；最终仍走 finalize 用验证证据裁决
            result["verdict"] = "excluded"
            result["reason"] = (result.get("reason") or "") + " | overridden: rule excluded"
        result.setdefault("severity", base.get("severity"))
        result.setdefault("attack_impact", base.get("attack_impact"))
        result.setdefault("fix_suggestion", base.get("fix_suggestion"))
        result.setdefault("answers", base.get("answers"))
        result = finalize_verdict(result, verify_results=verify_results, threat=threat)
        return _with_wooyun(result, threat, endpoint, verify_results)
    except Exception as e:
        base["reason"] = f"{base.get('reason', '')} | llm_failed: {e}"
        base = finalize_verdict(base, verify_results=verify_results, threat=threat)
        return _with_wooyun(base, threat, endpoint, verify_results)
