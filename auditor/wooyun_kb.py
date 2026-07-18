"""WooYun / wooyun-legacy 知识库对照

xinru 第四步要求：Yakit 验证 + 乌云对照 后才能定漏洞。
本模块把 ~/.codex/skills/wooyun-legacy 的领域方法论接到 Agent 判定链。

不是“搜案例标题玩具”，而是：
1. 按威胁类型映射到 6 大领域
2. 提取该领域的判定原则 / 测试清单 / 高危模式
3. 给 self_check 与结论输出提供锚点，避免只看 200 乱 confirmed
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any


def _skill_root() -> Path:
    env = os.environ.get("WOOYUN_SKILL_DIR") or os.environ.get("XINRU_WOOYUN_DIR")
    if env:
        return Path(env).expanduser().resolve()
    # 默认 codex skills 路径
    return Path.home().joinpath(".codex", "skills", "wooyun-legacy").resolve()


DOMAIN_FILES = {
    "authentication": "references/authentication-domain.md",
    "authorization": "references/authorization-domain.md",
    "financial": "references/financial-domain.md",
    "information": "references/information-domain.md",
    "logic_flow": "references/logic-flow-domain.md",
    "configuration": "references/configuration-domain.md",
}


# pattern / 名称关键词 → 领域
_PATTERN_DOMAIN = {
    "A1": "information",       # 硬编码凭据
    "A2": "authorization",     # URL 拼接 / IDOR 线索
    "A3": "authorization",
    "A4": "authorization",     # 无认证/弱认证
    "A5": "authentication",    # 签名/加密
    "A6": "information",       # 输入直传/渲染 → 也常关联 XSS，先归信息/逻辑
    "A7": "configuration",     # 上传下载
    "A8": "logic_flow",        # 跳转
    "B1": "financial",         # 价格数量
    "B2": "authorization",     # 越权
    "B3": "logic_flow",
    "B4": "logic_flow",
    "B5": "logic_flow",
    "E1": "configuration",
    "E2": "configuration",
    "E3": "configuration",
}

_NAME_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"越权|IDOR|未授权|弱认证|无认证|任意用户|水平|垂直", re.I), "authorization"),
    (re.compile(r"价格|金额|支付|订单|优惠|数量|余额|积分", re.I), "financial"),
    (re.compile(r"硬编码|密钥|secret|token|密码|泄露|敏感|key", re.I), "information"),
    (re.compile(r"登录|认证|session|jwt|oauth|签名|hmac|重置", re.I), "authentication"),
    (re.compile(r"状态机|步骤|流程|竞态|跳步|验证码", re.I), "logic_flow"),
    (re.compile(r"上传|下载|配置|swagger|debug|actuator|备份", re.I), "configuration"),
]


def map_domain(threat: dict[str, Any] | None = None, name: str = "") -> str:
    threat = threat or {}
    pattern = str(threat.get("pattern") or "")
    for key, domain in _PATTERN_DOMAIN.items():
        if pattern.upper().startswith(key):
            return domain
    text = " ".join([
        str(threat.get("pattern_name") or ""),
        str(threat.get("description") or ""),
        name or "",
    ])
    for cre, domain in _NAME_RULES:
        if cre.search(text):
            return domain
    return "authorization"


@lru_cache(maxsize=16)
def _read_domain_file(domain: str) -> str:
    root = _skill_root()
    rel = DOMAIN_FILES.get(domain)
    if not rel:
        return ""
    path = root / rel
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _extract_sections(md: str, max_chars: int = 2400) -> dict[str, str]:
    """粗提取概述/原则/关键参数/判定相关段落。"""
    if not md:
        return {"overview": "", "principles": "", "checklist": ""}

    overview = ""
    m = re.search(r"##\s*概述\s*\n([\s\S]*?)(?:\n##\s|\Z)", md)
    if m:
        overview = m.group(1).strip()

    principles = []
    for line in md.splitlines():
        if "核心原则" in line or line.strip().startswith("**核心原则"):
            principles.append(line.strip())
        if "扫描器无法" in line or "不唯状态码" in line:
            principles.append(line.strip())
    # 关键参数
    for m in re.finditer(r"\*\*关键参数[^*]*\*\*[：:]\s*(.+)", md):
        principles.append("关键参数: " + m.group(1).strip())

    checklist = []
    for line in md.splitlines():
        s = line.strip()
        if s.startswith("- [ ]") or s.startswith("* [ ]") or re.match(r"^\d+\.\s", s):
            checklist.append(s)
        if len(checklist) >= 18:
            break

    def clip(text: str) -> str:
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        return text[:max_chars]

    return {
        "overview": clip(overview),
        "principles": clip("\n".join(dict.fromkeys(principles))),
        "checklist": clip("\n".join(checklist)),
    }


# 领域级定级锚点（来自 wooyun skill 高危占比与方法论，用于约束乱 confirmed）
_DOMAIN_ANCHORS = {
    "authorization": {
        "high_ratio": 0.62,
        "confirm_requires": [
            "证明访问到他人/更高权限资源的真实业务数据",
            "不能仅因接口 200/静态资源可访问就确认",
            "优先双账号交叉：A 访问 B 的对象",
        ],
        "exclude_if": [
            "仅第三方库/文档/许可证链接",
            "仅公共静态资源(js/css)无业务数据",
            "响应无他人敏感字段且无写成功证据",
        ],
        "case_style": "WooYun 越权/IDOR 类：顺序 ID + 无归属校验 → 可遍历他人证件/订单",
    },
    "financial": {
        "high_ratio": 0.74,
        "confirm_requires": [
            "金额/数量/价格等字段客户端可控且服务端未复核",
            "需要看到下单/支付/改价后的真实业务结果变化",
            "单看前端变量名不够",
        ],
        "exclude_if": [
            "只是展示价格文本",
            "后端重算价格且篡改无效",
        ],
        "case_style": "WooYun 金额/订单篡改类：改 price/amount 后订单金额变化",
    },
    "information": {
        "high_ratio": 0.65,
        "confirm_requires": [
            "泄露内容具备可利用性（凭据/PII/可进一步攻击）",
            "硬编码密钥需确认不是示例值，并尽量证明可用于请求",
        ],
        "exclude_if": [
            "无敏感信息的版本号/路径噪音",
            "公开文档或前端展示文案",
        ],
        "case_style": "WooYun 信息泄露类：源码/配置/密钥泄露成为后续攻击催化剂",
    },
    "authentication": {
        "high_ratio": 0.70,
        "confirm_requires": [
            "认证可绕过或凭证可伪造，并实际进入受保护功能",
            "签名/校验若可被假签名通过，才可确认",
        ],
        "exclude_if": [
            "仅有登录入口暴露",
            "假签名/无 token 均失败且无旁路",
        ],
        "case_style": "WooYun 认证类：重置密码/会话固定/签名不校验",
    },
    "logic_flow": {
        "high_ratio": 0.70,
        "confirm_requires": [
            "能强制非法状态迁移或跳步，并产生业务结果",
        ],
        "exclude_if": [
            "纯前端 UI 状态，不影响服务端状态",
        ],
        "case_style": "WooYun 逻辑流类：未支付直接发货、跳过审批",
    },
    "configuration": {
        "high_ratio": 0.72,
        "confirm_requires": [
            "错误配置导致未授权访问、调试入口、对象存储可写/可读等真实影响",
        ],
        "exclude_if": [
            "仅 banner/版本信息且无利用链",
        ],
        "case_style": "WooYun 配置类：swagger/debug/备份/对象存储权限过宽",
    },
}


def lookup_wooyun(
    threat: dict[str, Any] | None = None,
    *,
    name: str = "",
    endpoint: dict[str, Any] | None = None,
    evidence: list[dict] | None = None,
) -> dict[str, Any]:
    """返回乌云对照结果，供 self_check / 报告引用。"""
    threat = threat or {}
    endpoint = endpoint or {}
    evidence = evidence or []
    domain = map_domain(threat, name=name or str(threat.get("pattern_name") or ""))
    md = _read_domain_file(domain)
    sections = _extract_sections(md)
    anchor = _DOMAIN_ANCHORS.get(domain, _DOMAIN_ANCHORS["authorization"])
    root = _skill_root()
    available = (root / "SKILL.md").is_file()

    # 证据摘要，帮助后续规则
    findings = " | ".join(str(x.get("finding") or "") for x in evidence[:12])
    locatable = bool(endpoint.get("locatable") or (endpoint.get("full_url") or "").startswith("http"))
    looks_static = False
    url = str(endpoint.get("full_url") or endpoint.get("path") or "")
    if re.search(r"\.(js|css|map|png|jpg|jpeg|gif|svg|ico|woff2?)($|\?)", url, re.I):
        looks_static = True
    if re.search(r"jquery\.org|api\.jquery|w3\.org|github\.com|cdn\.", url, re.I):
        looks_static = True

    guidance = {
        "domain": domain,
        "domain_file": DOMAIN_FILES.get(domain, ""),
        "skill_root": str(root),
        "available": available,
        "high_risk_ratio": anchor.get("high_ratio"),
        "confirm_requires": anchor.get("confirm_requires", []),
        "exclude_if": anchor.get("exclude_if", []),
        "case_style": anchor.get("case_style", ""),
        "overview": sections.get("overview", ""),
        "principles": sections.get("principles", ""),
        "checklist": sections.get("checklist", ""),
        "evidence_digest": findings[:500],
        "locatable": locatable,
        "looks_static": looks_static,
        "reference": f"wooyun-legacy:{domain}",
    }
    return guidance


def apply_wooyun_constraints(
    base_verdict: dict[str, Any],
    wooyun: dict[str, Any],
    *,
    threat: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """用乌云锚点约束 verdict，防止静态资源/无业务数据被 confirmed。"""
    out = dict(base_verdict or {})
    threat = threat or {}
    verdict = str(out.get("verdict") or "uncertain")
    reason = str(out.get("reason") or "")

    notes = []
    if not wooyun.get("available"):
        notes.append("wooyun skill 未加载，仅用内置锚点")

    # 静态资源 / 第三方文档：强制降级
    if wooyun.get("looks_static") and verdict == "confirmed":
        verdict = "excluded"
        notes.append("乌云对照：静态资源/第三方链接不具备业务越权或敏感利用意义")
        out["severity"] = "info"
        out["attack_impact"] = "无实际业务影响"
        out["fix_suggestion"] = "无需按漏洞修复；可忽略第三方库噪声"

    # 未定位 endpoint 却 confirmed：降为 uncertain
    if not wooyun.get("locatable") and verdict == "confirmed":
        pattern_name = str(threat.get("pattern_name") or "")
        if "硬编码" not in pattern_name and not str(threat.get("pattern") or "").startswith("A1"):
            verdict = "uncertain"
            notes.append("乌云对照：接口未定位前不能确认业务漏洞")

    # 授权域 confirmed 但证据里没有他人数据/越权信号，降 uncertain
    if wooyun.get("domain") == "authorization" and verdict == "confirmed":
        digest = (wooyun.get("evidence_digest") or "") + reason
        if not re.search(r"他人|越权|IDOR|敏感|订单|手机|身份证|user_id|owner", digest, re.I):
            # 若只有“无认证 200”也不足
            if re.search(r"无认证.*200|200（⚠️ 无保护）", digest):
                verdict = "uncertain"
                notes.append("乌云对照：仅无认证200不足以确认越权/未授权，需业务数据或可操作证据")

    # 金融域：没有“结果变化”证据，confirmed 降级
    if wooyun.get("domain") == "financial" and verdict == "confirmed":
        digest = (wooyun.get("evidence_digest") or "") + reason
        if not re.search(r"金额|price|amount|订单|支付|变更|成功修改|写成功", digest, re.I):
            verdict = "uncertain"
            notes.append("乌云对照：价格/金额类需证明服务端业务结果被篡改")

    out["verdict"] = verdict
    if notes:
        out["reason"] = (reason + " | " if reason else "") + "；".join(notes)
        out["wooyun_notes"] = notes
    out["wooyun_reference"] = wooyun.get("reference")
    out["wooyun_domain"] = wooyun.get("domain")
    out["wooyun_case_style"] = wooyun.get("case_style")
    # 给报告用的简短对照文本
    req = "；".join(wooyun.get("confirm_requires") or [])
    out["wooyun_guidance"] = f"[{wooyun.get('domain')}] {wooyun.get('case_style') or ''} 确认要求: {req}"
    return out


def format_wooyun_for_prompt(wooyun: dict[str, Any]) -> str:
    if not wooyun:
        return "(no wooyun guidance)"
    parts = [
        f"领域: {wooyun.get('domain')}",
        f"参考: {wooyun.get('reference')}",
        f"案例风格: {wooyun.get('case_style')}",
        "确认要求:",
        *[f"- {x}" for x in (wooyun.get("confirm_requires") or [])],
        "应排除:",
        *[f"- {x}" for x in (wooyun.get("exclude_if") or [])],
    ]
    if wooyun.get("principles"):
        parts.append("原则摘录:\n" + str(wooyun.get("principles"))[:800])
    if wooyun.get("checklist"):
        parts.append("测试清单摘录:\n" + str(wooyun.get("checklist"))[:800])
    return "\n".join(parts)
