"""xinru 审计主循环核心 — 真·逐行扫描 / 快速预筛 / LLM 复核 / 回流约束"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from auditor.threat_patterns import QUICK_PATTERNS, _BUSINESS_CONTEXT, make_scan_prompt


# 业务类模式：同窗口内需要请求/传参语境，降低噪音
_BUSINESS_PATTERNS = {"B1", "B2", "B3", "B4", "B5"}
_NOISE_FILE_HINTS = (
    "node_modules",
    "vendor",
    "jquery",
    "react-dom",
    "vue.runtime",
    "chunk-vendors",
    "polyfill",
    "webpack",
)


@dataclass
class ScanHit:
    line: int
    pattern: str
    pattern_name: str
    description: str
    severity_guess: str
    snippet: str = ""
    lead: dict | None = None

    def to_threat(self) -> dict[str, Any]:
        payload = {
            "line": self.line,
            "pattern": self.pattern,
            "pattern_name": self.pattern_name,
            "description": self.description,
            "severity_guess": self.severity_guess,
            "snippet": self.snippet,
        }
        if self.lead:
            payload["_lead"] = self.lead
        return payload


def line_fingerprint(text: str, n: int = 24) -> str:
    cleaned = re.sub(r"\s+", " ", (text or "").strip())
    return cleaned[:n]


def content_hash(text: str) -> str:
    return hashlib.sha1((text or "").encode("utf-8", errors="replace")).hexdigest()[:16]


def is_noise_file(path: str) -> bool:
    lower = (path or "").lower()
    return any(x in lower for x in _NOISE_FILE_HINTS)


def _extract_url_lead(line_text: str, line_num: int) -> dict | None:
    match = re.search(r"""https?://([^\s'"`\\]+)|wss?://([^\s'"`\\]+)""", line_text, re.I)
    if not match:
        return None
    raw = match.group(0).rstrip(").,;]}>")
    try:
        parsed = urlparse(raw)
    except Exception:
        return None
    if not parsed.netloc:
        return None
    host = parsed.netloc.lower()
    ignored = {
        "github.com",
        "raw.githubusercontent.com",
        "npmjs.com",
        "www.npmjs.com",
        "w3.org",
        "www.w3.org",
        "schema.org",
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "googleapis.com",
        "gstatic.com",
    }
    if any(host == d or host.endswith("." + d) for d in ignored):
        return None
    return {
        "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}",
        "reason": f"第 {line_num + 1 if False else line_num} 行发现外部/内部 URL {parsed.netloc}",
        "source_line": line_num,
    }


def quick_scan_lines(
    content: str,
    start_line: int = 0,
    end_line: int | None = None,
    file_path: str = "",
) -> list[dict[str, Any]]:
    """对 [start_line, end_line) 做正则预筛，返回按行排序的威胁候选。"""
    lines = content.split("\n")
    total = len(lines)
    if end_line is None:
        end_line = total
    start_line = max(0, min(start_line, total))
    end_line = max(start_line, min(end_line, total))

    # 给业务模式一点窗口上下文
    window_start = max(0, start_line - 3)
    window_end = min(total, end_line + 3)
    window_text = "\n".join(lines[window_start:window_end])
    has_business_context = bool(_BUSINESS_CONTEXT.search(window_text))

    hits: list[ScanHit] = []
    seen: set[tuple[int, str]] = set()

    for idx in range(start_line, end_line):
        text = lines[idx]
        stripped = text.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            # 注释里仍可能有密钥，单独放宽 A1
            if not re.search(r"(?i)(key|secret|token|password)\s*[:=]", stripped):
                continue

        for rule in QUICK_PATTERNS:
            pattern = rule["pattern"]
            if pattern in _BUSINESS_PATTERNS and not has_business_context and not is_noise_file(file_path):
                # 业务模式无请求语境时降噪；配置文件例外
                lower_path = (file_path or "").lower()
                if not any(x in lower_path for x in ("config", "api", "service", "request")):
                    continue

            if not rule["regex"].search(stripped):
                continue

            key = (idx, pattern)
            if key in seen:
                continue
            seen.add(key)

            lead = None
            if rule.get("extract_lead"):
                lead = _extract_url_lead(stripped, idx)

            hits.append(
                ScanHit(
                    line=idx,
                    pattern=pattern,
                    pattern_name=rule["pattern_name"],
                    description=f"{rule['pattern_name']}: {stripped[:120]}",
                    severity_guess=rule["severity_guess"],
                    snippet=stripped[:240],
                    lead=lead,
                )
            )

    # 同一行多模式：优先保留更高危
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    by_line: dict[int, list[ScanHit]] = {}
    for hit in hits:
        by_line.setdefault(hit.line, []).append(hit)

    ordered: list[dict[str, Any]] = []
    for line_no in sorted(by_line):
        group = sorted(by_line[line_no], key=lambda h: severity_rank.get(h.severity_guess, 9))
        # 同一行最多保留 2 个不同模式，避免死循环式重复
        for item in group[:2]:
            ordered.append(item.to_threat())
    return ordered


def pick_next_unhandled(
    hits: list[dict[str, Any]],
    handled: set[str] | None = None,
) -> dict[str, Any] | None:
    """从候选中挑第一个未处理威胁。"""
    handled = handled or set()
    for hit in hits:
        key = f"{hit.get('line')}:{hit.get('pattern')}:{hit.get('pattern_name')}"
        if key in handled:
            continue
        # lead-only A4 可记录线索，但仍可作为威胁进入追溯（弱认证接口）
        return hit
    return None


def threat_key(threat: dict[str, Any]) -> str:
    return f"{threat.get('line')}:{threat.get('pattern')}:{threat.get('pattern_name')}"


async def llm_rescan_snippet(
    content: str,
    file_path: str,
    start_line: int,
    end_line: int,
    call_llm_json,
    system_prompt: str,
) -> list[dict[str, Any]]:
    """对一段代码做 LLM 复核扫描。失败返回空列表。"""
    import asyncio

    lines = content.split("\n")
    snippet = "\n".join(lines[start_line:end_line])
    if not snippet.strip():
        return []

    prompt = make_scan_prompt(snippet, file_path, start_line)
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(call_llm_json, system_prompt, prompt),
            timeout=75,
        )
    except Exception:
        return []

    threats = []
    if isinstance(result, dict):
        threats = result.get("threats") or []
    if not isinstance(threats, list):
        return []

    cleaned: list[dict[str, Any]] = []
    for item in threats:
        if not isinstance(item, dict):
            continue
        try:
            line = int(item.get("line", start_line))
        except Exception:
            line = start_line
        # LLM 可能返回 1-based，纠正到片段范围
        if line < start_line and line >= 1:
            # 可能是 1-based 全局行号
            line = line - 1
        if line < start_line or line >= end_line:
            # 容错：贴到片段起始
            line = start_line
        cleaned.append(
            {
                "line": line,
                "pattern": str(item.get("pattern") or "A3"),
                "pattern_name": str(item.get("pattern_name") or "LLM可疑点"),
                "description": str(item.get("description") or "LLM 标记可疑"),
                "severity_guess": str(item.get("severity_guess") or "medium"),
                "snippet": lines[line][:240] if 0 <= line < len(lines) else "",
                "suggested_endpoint": item.get("suggested_endpoint") or "",
            }
        )
    return cleaned


def advance_after_threat(current_line: int, threat_line: int | None = None) -> int:
    """回流硬约束：处理完威胁后，至少推进到威胁行的下一行。"""
    base = threat_line if threat_line is not None else current_line
    return max(int(base), int(current_line)) + 1


def build_return_marker(file_path: str, next_line: int, threat_id: str | int | None = None) -> dict:
    """等价于 pending_return，但内化为状态，不依赖外部 hook。"""
    return {
        "file": file_path,
        "line": next_line,
        "threat_id": threat_id,
        "fingerprint_required": True,
    }


def validate_return_position(
    expected_file: str,
    expected_line: int,
    actual_file: str,
    actual_line: int,
    expected_fp: str | None = None,
    actual_line_text: str | None = None,
) -> tuple[bool, str]:
    if expected_file and actual_file and expected_file != actual_file:
        return False, f"回流文件不匹配: expect={expected_file} actual={actual_file}"
    if actual_line != expected_line:
        return False, f"回流行号不匹配: expect={expected_line} actual={actual_line}"
    if expected_fp and actual_line_text is not None:
        if line_fingerprint(actual_line_text) != expected_fp:
            # 文件变化时不硬失败，只警告
            return True, "行指纹变化（文件可能已更新），继续"
    return True, "ok"
