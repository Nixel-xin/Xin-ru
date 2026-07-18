"""LLM 调用封装 — xinru Agent 的推理大脑

默认使用 Codex 同款 Grok 配置：
- OpenAI-compatible Chat Completions
- base: https://www.fastaitoken.com/v1
- model: grok-4.5

也兼容旧的 Anthropic / 百智网关（LLM_PROVIDER=anthropic）。
"""

from __future__ import annotations

import json
import time
import os
import re
from typing import Any

import httpx

# ============================================================
# 配置
# ============================================================

_PROVIDER = (os.environ.get("LLM_PROVIDER") or "openai").strip().lower()
_MODEL = os.environ.get("LLM_MODEL") or os.environ.get("ANTHROPIC_MODEL") or "grok-4.5"
_OPENAI_BASE = (
    os.environ.get("OPENAI_BASE_URL")
    or os.environ.get("LLM_BASE_URL")
    or "https://www.fastaitoken.com/v1"
).rstrip("/")
_OPENAI_KEY = (
    os.environ.get("OPENAI_API_KEY")
    or os.environ.get("LLM_API_KEY")
    or os.environ.get("ANTHROPIC_AUTH_TOKEN")
    or ""
)
_ANTHROPIC_BASE = os.environ.get(
    "ANTHROPIC_BASE_URL",
    "https://ai-api-gateway.app.baizhi.cloud/api/anthropic",
)
_ANTHROPIC_KEY = os.environ.get("ANTHROPIC_AUTH_TOKEN") or ""
_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "120"))
# 0 = 兼容旧行为无限重试；>0 时达到上限后抛错，便于上层 pause/resume
_MAX_RETRIES = int(os.environ.get("XINRU_LLM_MAX_RETRIES", "8"))


def _is_fatal_llm_message(message: str) -> bool:
    m = (message or "").lower()
    keys = (
        "401", "402",
        "insufficient balance", "余额不足", "invalid api key",
        "unauthorized", "authentication failed",
        "model not found", "permission denied",
    )
    return any(k in m for k in keys)


# Cloudflare / 部分网关会拦默认 Python UA（error 1010）
_UA = os.environ.get(
    "LLM_USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
)

# 系统角色
SYSTEM_PROMPT = """你是一名专业的白盒渗透测试工程师。核心信念：**源码里一定有漏洞，逐行追就能找到**。

你的职责是逐行阅读 JavaScript 源码，发现安全漏洞。你必须：
1. 每行代码对照威胁模式判断是否可疑
2. 发现可疑后立即追溯完整调用链
3. 定位到精确的 API 接口（域名+路径+方法+参数+Header）
4. 验证漏洞真伪，不自欺欺人
5. 绝不跳步，必须回到原位继续

你做结论时，必须过5个自检问题，不允许看到200 OK就写"公开可访问"。"""

JSON_SYSTEM_PROMPT = """你是严格的 JSON 生成器。
规则：
1. 只输出一个合法 JSON 对象或数组
2. 不要输出 markdown、代码块、解释、思考过程
3. 不要输出除 JSON 以外的任何字符
4. 字符串必须用双引号
"""


def _openai_chat(
    system: str,
    user: str,
    *,
    temperature: float,
    max_tokens: int,
    force_json: bool = False,
) -> str:
    if not _OPENAI_KEY:
        raise RuntimeError("OPENAI_API_KEY / LLM_API_KEY 未配置")

    url = f"{_OPENAI_BASE}/chat/completions"
    payload: dict[str, Any] = {
        "model": _MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if force_json:
        payload["response_format"] = {"type": "json_object"}

    headers = {
        "Authorization": f"Bearer {_OPENAI_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": _UA,
    }

    # 大模型调用失败：只重试，不改上层业务逻辑。
    # 503/429 等多来自中转网关，必须一直重试直到成功。
    attempt = 0
    dropped_response_format = False
    while True:
        attempt += 1
        try:
            with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
                resp = client.post(url, headers=headers, json=payload)
                if (
                    force_json
                    and not dropped_response_format
                    and resp.status_code >= 400
                    and "response_format" in payload
                ):
                    payload.pop("response_format", None)
                    dropped_response_format = True
                    print(f"[llm] drop response_format after HTTP {resp.status_code}, retry", flush=True)
                    continue
                if resp.status_code >= 400:
                    raise RuntimeError(
                        f"OpenAI-compatible LLM error {resp.status_code}: {resp.text[:500]}"
                    )
                data = resp.json()

            # 标准 chat.completion
            choices = data.get("choices") or []
            if choices:
                msg = choices[0].get("message") or {}
                content = msg.get("content")
                if isinstance(content, str) and content.strip():
                    if attempt > 1:
                        print(f"[llm] recovered after {attempt} attempts", flush=True)
                    return content
                if isinstance(content, list):
                    parts = []
                    for block in content:
                        if isinstance(block, dict) and block.get("type") in ("text", "output_text"):
                            parts.append(block.get("text") or "")
                        elif isinstance(block, str):
                            parts.append(block)
                    if parts:
                        if attempt > 1:
                            print(f"[llm] recovered after {attempt} attempts", flush=True)
                        return "\n".join(parts)

            if isinstance(data.get("output_text"), str) and data["output_text"].strip():
                if attempt > 1:
                    print(f"[llm] recovered after {attempt} attempts", flush=True)
                return data["output_text"]
            output = data.get("output")
            if isinstance(output, list):
                texts = []
                for item in output:
                    if not isinstance(item, dict):
                        continue
                    for c in item.get("content") or []:
                        if isinstance(c, dict) and c.get("type") in ("output_text", "text"):
                            texts.append(c.get("text") or "")
                if texts:
                    if attempt > 1:
                        print(f"[llm] recovered after {attempt} attempts", flush=True)
                    return "\n".join(texts)

            raise ValueError(f"LLM 返回无法解析: {json.dumps(data, ensure_ascii=False)[:500]}")
        except Exception as e:
            msg = str(e)
            if _is_fatal_llm_message(msg):
                print(f"[llm] fatal error, no more retries: {e}", flush=True)
                raise
            msg_l = msg.lower()
            if "429" in msg_l or "rate" in msg_l:
                sleep_s = min(60.0, 3.0 * attempt)
            elif "503" in msg_l or "502" in msg_l or "504" in msg_l or "temporar" in msg_l:
                sleep_s = min(60.0, 2.0 * attempt)
            else:
                sleep_s = min(30.0, 1.0 * attempt)
            if _MAX_RETRIES > 0 and attempt >= _MAX_RETRIES:
                print(f"[llm] giving up after {attempt} attempts: {e}", flush=True)
                raise
            print(f"[llm] call failed attempt={attempt}: {e}; retry in {sleep_s:.1f}s", flush=True)
            time.sleep(sleep_s)


def _anthropic_chat(system: str, user: str, *, temperature: float, max_tokens: int) -> str:
    from anthropic import Anthropic

    client = Anthropic(api_key=_ANTHROPIC_KEY, base_url=_ANTHROPIC_BASE)
    resp = client.messages.create(
        model=_MODEL,
        system=system,
        messages=[{"role": "user", "content": user}],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    text_blocks = [b for b in resp.content if hasattr(b, "text")]
    if text_blocks:
        return text_blocks[-1].text
    return str(resp.content[0])


def call_llm(
    system: str,
    user: str,
    *,
    temperature: float = 0.3,
    max_tokens: int = 4096,
    force_json: bool = False,
) -> str:
    """底层 LLM 调用。"""
    provider = _PROVIDER
    if provider in {"openai", "grok", "fastaitoken", "compatible"}:
        return _openai_chat(
            system,
            user,
            temperature=temperature,
            max_tokens=max_tokens,
            force_json=force_json,
        )
    if provider in {"anthropic", "baizhi"}:
        return _anthropic_chat(system, user, temperature=temperature, max_tokens=max_tokens)
    # 默认 openai
    return _openai_chat(
        system,
        user,
        temperature=temperature,
        max_tokens=max_tokens,
        force_json=force_json,
    )


def _strip_code_fences(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json|JSON)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def extract_json_object(text: str) -> Any:
    """从模型输出中尽量提取 JSON（对象或数组）。"""
    raw = _strip_code_fences(text)
    if not raw:
        raise ValueError("空响应")

    # 1) 直接解析
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # 2) 去掉常见前缀/后缀自然语言
    cleaned = re.sub(r"^[^{\[]+", "", raw, count=1)
    cleaned = re.sub(r"[^}\]]+$", "", cleaned, count=1)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # 3) 从第一个 { 或 [ 做括号匹配
    starts = [i for i, ch in enumerate(raw) if ch in "{["]
    for start in starts:
        opener = raw[start]
        closer = "}" if opener == "{" else "]"
        depth = 0
        in_str = False
        escape = False
        for i in range(start, len(raw)):
            ch = raw[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
                continue
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    candidate = raw[start : i + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        break
    raise ValueError(f"LLM 未返回有效 JSON: {raw[:500]}")


def call_llm_json(
    system: str,
    user: str,
    *,
    temperature: float = 0.2,
    max_tokens: int = 4096,
    retries: int = 2,  # 保留参数兼容，但调用失败会一直重试
) -> dict[str, Any] | list[Any]:
    """调用 LLM 并强制返回 JSON。

    规则（按操作者要求）:
    - 大模型调用失败 / JSON 无效 → 一直重试，重新调用
    - 不改变上层业务逻辑
    """
    last_err: Exception | None = None
    base_system = (system or "").strip() or JSON_SYSTEM_PROMPT
    attempt = 0
    while True:
        attempt += 1
        if attempt == 1:
            full_system = (
                base_system
                + "\n\n你只输出 JSON。不要输出其他内容。不要用 markdown 代码块包裹。不要输出思考过程。"
            )
            prompt = user
        else:
            full_system = JSON_SYSTEM_PROMPT
            prompt = (
                "上次输出不是合法 JSON 或调用失败。现在严格只输出一个 JSON 对象，不要解释。\n\n"
                f"原始任务:\n{user}\n\n"
                f"上次错误: {last_err}"
            )
        try:
            text_out = call_llm(
                full_system,
                prompt,
                temperature=temperature if attempt == 1 else 0.0,
                max_tokens=max_tokens,
                force_json=True,
            )
            data = extract_json_object(text_out)
            if isinstance(data, (dict, list)):
                if attempt > 1:
                    print(f"[llm_json] recovered after {attempt} attempts", flush=True)
                return data
            raise ValueError(f"JSON 顶层类型不支持: {type(data)}")
        except Exception as e:
            last_err = e
            if _is_fatal_llm_message(str(e)):
                print(f"[llm_json] fatal error, no more retries: {e}", flush=True)
                raise
            # call_llm 内部已对 503/429 做等待；这里对 JSON 解析失败做短等待
            sleep_s = min(20.0, 1.0 * attempt)
            if _MAX_RETRIES > 0 and attempt >= max(_MAX_RETRIES, 3):
                print(f"[llm_json] giving up after {attempt} attempts: {e}", flush=True)
                raise
            print(f"[llm_json] failed attempt={attempt}: {e}; retry in {sleep_s:.1f}s", flush=True)
            time.sleep(sleep_s)


def llm_info() -> dict[str, str]:
    return {
        "provider": _PROVIDER,
        "model": _MODEL,
        "base_url": _OPENAI_BASE if _PROVIDER not in {"anthropic", "baizhi"} else _ANTHROPIC_BASE,
        "key_configured": "yes" if (_OPENAI_KEY or _ANTHROPIC_KEY) else "no",
    }
