"""签名型认证提取与复现

xinru 第零步类型 2:
- 从 JS 中提取 HMAC/MD5/SHA 签名拼装
- 生成 .xinru/sign_helper.py
- 验证时支持无签名 / 假签名 / 真签名 三态
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit, parse_qsl

from auditor.credentials import work_dir_for_task


_SIGN_HINT_RE = re.compile(
    r"(?i)(sign|signature|hmac|md5|sha256|sha1|nonce|timestamp|appkey|app_key|secret|accesskey|access_key)"
)
_KEY_LITERAL_RE = re.compile(
    r"""(?i)(?:secret|app[_-]?secret|app[_-]?key|access[_-]?key|sign[_-]?key|api[_-]?key)\s*[:=]\s*['"]([^'"]{4,120})['"]"""
)
_FUNC_HINT_RE = re.compile(
    r"""(?is)function\s+(\w*(?:sign|hmac|md5|sha)\w*)\s*\([^)]*\)\s*\{.{0,800}?\}"""
    r"""|(?:const|let|var)\s+(\w*(?:sign|hmac|md5|sha)\w*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{.{0,800}?\}"""
)


@dataclass
class SignatureProfile:
    domain: str = "*"
    alg: str = "unknown"  # md5|sha1|sha256|hmac-sha256|hmac-md5|unknown
    key: str = ""
    key_source: str = ""
    param_order: list[str] = field(default_factory=list)
    sign_param: str = "sign"
    nonce_param: str = "nonce"
    ts_param: str = "timestamp"
    header_name: str = ""
    helper_path: str = ""
    notes: str = ""
    confidence: float = 0.0


def _host(url_or_domain: str) -> str:
    try:
        if "://" in (url_or_domain or ""):
            return (urlsplit(url_or_domain).hostname or "*").lower()
        return (url_or_domain or "*").lower() or "*"
    except Exception:
        return "*"


def detect_alg(snippet: str) -> str:
    s = (snippet or "").lower()
    if "hmac" in s and "sha256" in s:
        return "hmac-sha256"
    if "hmac" in s and "md5" in s:
        return "hmac-md5"
    if "sha256" in s:
        return "sha256"
    if "sha1" in s:
        return "sha1"
    if "md5" in s:
        return "md5"
    if "hmac" in s:
        return "hmac-sha256"
    return "unknown"


def extract_keys(content: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for m in _KEY_LITERAL_RE.finditer(content or ""):
        val = m.group(1).strip()
        if val and val not in {v for _, v in out}:
            # 跳过明显占位
            if re.fullmatch(r"(your|xxx|todo|null|undefined|example).*", val, re.I):
                continue
            out.append((m.group(0)[:80], val))
    return out


def extract_signature_profiles(
    content: str,
    *,
    file_path: str = "",
    domain: str = "*",
) -> list[SignatureProfile]:
    """从单文件提取签名配置线索。"""
    if not content or not _SIGN_HINT_RE.search(content):
        return []

    keys = extract_keys(content)
    funcs = [m.group(0) for m in _FUNC_HINT_RE.finditer(content)]
    alg = detect_alg(content)
    if funcs:
        alg = detect_alg("\n".join(funcs[:3])) or alg

    profiles: list[SignatureProfile] = []
    if not keys and alg == "unknown" and not funcs:
        return []

    key = keys[0][1] if keys else ""
    conf = 0.3
    if key:
        conf += 0.4
    if alg != "unknown":
        conf += 0.2
    if funcs:
        conf += 0.1

    # 参数顺序启发式
    order: list[str] = []
    for name in ("appId", "app_id", "appKey", "app_key", "timestamp", "nonce", "data", "body"):
        if re.search(rf"(?i)\b{re.escape(name)}\b", content):
            order.append(name)

    header = ""
    hm = re.search(r"""(?i)headers?\[['\"](x-?sign(?:ature)?)['\"]\]|['\"](x-?sign(?:ature)?)['\"]\s*:""", content)
    if hm:
        header = hm.group(1) or hm.group(2) or ""

    profiles.append(
        SignatureProfile(
            domain=domain or "*",
            alg=alg,
            key=key,
            key_source=keys[0][0] if keys else (file_path or ""),
            param_order=order,
            sign_param="sign",
            header_name=header,
            notes=f"from {file_path}; funcs={len(funcs)}; keys={len(keys)}",
            confidence=min(conf, 0.99),
        )
    )
    return profiles


def compute_signature(alg: str, key: str, raw: str) -> str:
    data = (raw or "").encode("utf-8", errors="replace")
    k = (key or "").encode("utf-8", errors="replace")
    a = (alg or "md5").lower()
    if a in ("md5",):
        return hashlib.md5(data).hexdigest()
    if a in ("sha1",):
        return hashlib.sha1(data).hexdigest()
    if a in ("sha256",):
        return hashlib.sha256(data).hexdigest()
    if a in ("hmac-md5", "hmac_md5"):
        return hmac.new(k, data, hashlib.md5).hexdigest()
    if a in ("hmac-sha1", "hmac_sha1"):
        return hmac.new(k, data, hashlib.sha1).hexdigest()
    if a in ("hmac-sha256", "hmac_sha256", "hmac"):
        return hmac.new(k, data, hashlib.sha256).hexdigest()
    # fallback
    return hashlib.md5(data + k).hexdigest()


def build_sign_payload(
    profile: SignatureProfile,
    *,
    params: dict[str, Any] | None = None,
    body: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """按 profile 组装待签字符串与附加参数。"""
    p = dict(params or {})
    now = str(int(time.time()))
    nonce = hashlib.md5(f"{now}-{time.time_ns()}".encode()).hexdigest()[:16]
    if profile.ts_param and profile.ts_param not in p:
        p[profile.ts_param] = now
    if profile.nonce_param and profile.nonce_param not in p:
        p[profile.nonce_param] = nonce

    order = profile.param_order or sorted(p.keys())
    parts = []
    for k in order:
        if k in p and k != profile.sign_param:
            parts.append(f"{k}={p[k]}")
    # 未列入 order 的剩余参数
    for k in sorted(p.keys()):
        if k not in order and k != profile.sign_param:
            parts.append(f"{k}={p[k]}")
    if body:
        parts.append(f"body={body}")
    if profile.key and profile.alg.startswith("md5") and "key" not in {x.split("=", 1)[0] for x in parts}:
        # 常见 md5(params+key)
        raw = "&".join(parts) + profile.key
    else:
        raw = "&".join(parts)
    return raw, p


def apply_signature(
    profile: SignatureProfile,
    *,
    method: str = "GET",
    url: str = "",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    params: dict[str, Any] | None = None,
    mode: str = "true",  # true|fake|none
) -> dict[str, Any]:
    """返回改写后的 headers/body/params/sign。"""
    headers = dict(headers or {})
    params = dict(params or {})
    # URL query 并入 params
    try:
        q = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        for k, v in q.items():
            params.setdefault(k, v)
    except Exception:
        pass

    if mode == "none":
        headers.pop(profile.header_name, None) if profile.header_name else None
        params.pop(profile.sign_param, None)
        return {
            "headers": headers,
            "params": params,
            "body": body,
            "sign": "",
            "mode": mode,
            "raw": "",
        }

    raw, params2 = build_sign_payload(profile, params=params, body=body)
    if mode == "fake":
        sig = "0" * 32
    else:
        sig = compute_signature(profile.alg, profile.key, raw)

    if profile.header_name:
        headers[profile.header_name] = sig
    else:
        params2[profile.sign_param or "sign"] = sig

    # GET 时把 sign 放 query 更常见
    out_body = body
    if method.upper() in ("POST", "PUT", "PATCH") and body and not profile.header_name:
        # 尝试 json body 注入
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                obj[profile.sign_param or "sign"] = sig
                out_body = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            pass

    return {
        "headers": headers,
        "params": params2,
        "body": out_body,
        "sign": sig,
        "mode": mode,
        "raw": raw,
        "alg": profile.alg,
    }


def write_sign_helper(task_id: int, profiles: list[SignatureProfile]) -> Path:
    """写出可复用的 sign_helper.py 与 profiles.json。"""
    root = work_dir_for_task(task_id)
    root.mkdir(parents=True, exist_ok=True)
    helper = root / "sign_helper.py"
    meta = root / "signature_profiles.json"

    payload = [asdict(p) for p in profiles]
    meta.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    helper.write_text(
        '''"""Auto-generated xinru signature helper. Do not edit by hand."""
from __future__ import annotations
import hashlib, hmac, json, time
from pathlib import Path

_PROFILES = json.loads(Path(__file__).with_name("signature_profiles.json").read_text(encoding="utf-8"))

def list_profiles():
    return list(_PROFILES)

def _compute(alg: str, key: str, raw: str) -> str:
    data = (raw or "").encode("utf-8", errors="replace")
    k = (key or "").encode("utf-8", errors="replace")
    a = (alg or "md5").lower()
    if a == "md5":
        return hashlib.md5(data).hexdigest()
    if a == "sha1":
        return hashlib.sha1(data).hexdigest()
    if a == "sha256":
        return hashlib.sha256(data).hexdigest()
    if a in ("hmac-md5",):
        return hmac.new(k, data, hashlib.md5).hexdigest()
    if a in ("hmac-sha1",):
        return hmac.new(k, data, hashlib.sha1).hexdigest()
    if a in ("hmac-sha256", "hmac"):
        return hmac.new(k, data, hashlib.sha256).hexdigest()
    return hashlib.md5(data + k).hexdigest()

def sign_for_domain(domain: str, params: dict | None = None, body: str | None = None) -> dict:
    params = dict(params or {})
    prof = None
    for p in _PROFILES:
        if p.get("domain") in ("*", domain) or domain.endswith(p.get("domain") or ""):
            prof = p
            break
    if not prof:
        prof = _PROFILES[0] if _PROFILES else {"alg": "md5", "key": "", "sign_param": "sign", "ts_param": "timestamp", "nonce_param": "nonce", "param_order": []}
    now = str(int(time.time()))
    if prof.get("ts_param"):
        params.setdefault(prof["ts_param"], now)
    if prof.get("nonce_param"):
        params.setdefault(prof["nonce_param"], hashlib.md5(now.encode()).hexdigest()[:16])
    order = prof.get("param_order") or sorted(params.keys())
    parts = [f"{k}={params[k]}" for k in order if k in params and k != prof.get("sign_param")]
    for k in sorted(params.keys()):
        if k not in order and k != prof.get("sign_param"):
            parts.append(f"{k}={params[k]}")
    if body:
        parts.append(f"body={body}")
    raw = "&".join(parts)
    if (prof.get("alg") or "").startswith("md5") and prof.get("key"):
        raw2 = raw + prof.get("key")
    else:
        raw2 = raw
    sig = _compute(prof.get("alg") or "md5", prof.get("key") or "", raw2)
    out = dict(params)
    out[prof.get("sign_param") or "sign"] = sig
    return {"sign": sig, "params": out, "raw": raw2, "profile": prof}
''',
        encoding="utf-8",
    )
    for p in profiles:
        p.helper_path = str(helper)
    meta.write_text(json.dumps([asdict(p) for p in profiles], ensure_ascii=False, indent=2), encoding="utf-8")
    return helper


def load_profiles(task_id: int) -> list[SignatureProfile]:
    path = work_dir_for_task(task_id) / "signature_profiles.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    out: list[SignatureProfile] = []
    for item in data or []:
        if not isinstance(item, dict):
            continue
        out.append(
            SignatureProfile(
                domain=item.get("domain") or "*",
                alg=item.get("alg") or "unknown",
                key=item.get("key") or "",
                key_source=item.get("key_source") or "",
                param_order=list(item.get("param_order") or []),
                sign_param=item.get("sign_param") or "sign",
                nonce_param=item.get("nonce_param") or "nonce",
                ts_param=item.get("ts_param") or "timestamp",
                header_name=item.get("header_name") or "",
                helper_path=item.get("helper_path") or "",
                notes=item.get("notes") or "",
                confidence=float(item.get("confidence") or 0),
            )
        )
    return out


def pick_profile(task_id: int, url_or_domain: str) -> SignatureProfile | None:
    host = _host(url_or_domain)
    profiles = load_profiles(task_id)
    if not profiles:
        return None
    for p in profiles:
        if p.domain in ("*", host) or host.endswith("." + p.domain) or p.domain.endswith("." + host):
            return p
    return profiles[0]


def scan_files_for_signatures(task_id: int, file_paths: list[str], default_domain: str = "*") -> list[SignatureProfile]:
    all_profiles: list[SignatureProfile] = []
    seen_keys: set[str] = set()
    for fp in file_paths:
        try:
            text = Path(fp).read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for prof in extract_signature_profiles(text, file_path=fp, domain=default_domain or "*"):
            key = f"{prof.domain}|{prof.alg}|{prof.key}|{prof.header_name}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            all_profiles.append(prof)
    if all_profiles:
        write_sign_helper(task_id, all_profiles)
    return all_profiles
