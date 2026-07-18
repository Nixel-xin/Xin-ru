"""xinru 威胁模式库 — 技术型 / 业务逻辑 / 二阶 / 框架 / 现代攻击面"""

from __future__ import annotations

import re
from typing import Any


# ============================================================
# 文件关注点（不是跳过策略：全量扫描，仅影响排序）
# ============================================================

FILE_PRIORITY_MAP = {
    "config": 1,
    ".env": 1,
    "secret": 1,
    "basisconfig": 1,
    "api": 2,
    "module": 2,
    "service": 2,
    "request": 3,
    "http": 3,
    "axios": 3,
    "encrypt": 3,
    "sign": 3,
    "auth": 3,
    "page": 4,
    "view": 4,
    "route": 4,
    "component": 5,
    "store": 5,
    "util": 6,
    "helper": 6,
    "hook": 6,
}


# ============================================================
# 威胁模式定义 — 扫描 prompt 与人工可读检查清单
# ============================================================

THREAT_PATTERNS = """
## 威胁模式检查清单（每读一行，对照以下模式判断是否可疑）

### A. 技术型
A1 硬编码凭据: key/secret/password/token/APPSECRET/API_KEY/accessKey
A2 URL/路径拼接: base+param / `/users/${id}` / path+"?key="+v
A3 动态参数入请求: request({data:params}) / fetch body / wx.request data
A4 无认证/弱认证: 新域名/端口/路径且无 Authorization/token
A5 签名/加密: MD5/SHA/HMAC + 硬编码 key / hexdigest / toUpperCase
A6 用户输入直传/渲染: decodeURIComponent / innerHTML / eval / document.write
A7 文件上传/下载: uploadFile / download path 可控 / OSS SAS / presigned
A8 重定向/跳转: location.href / navigateTo / redirect(userInput)

### B. 业务逻辑型
B1 价格/数量篡改: totalPrice/amount/price/discount/quantity 前端可控
B2 越权操作: userId/orderId/memberId 等对象标识可替换
B3 状态机绕过: step/status/stage 可跳步
B4 竞态条件: 领券/抽奖/提现/扣库存等一次性操作
B5 时间窗: expire/timestamp/trial 可篡改

### C. 二阶漏洞
C1 存储型 XSS: 输入入库 + 另一处未转义渲染
C2 存储型注入: 输入后用于 SQL/命令/CSV 导出

### D. 框架特异性
D1 React: dangerouslySetInnerHTML / href={userInput}
D2 Vue: v-html / :href / $refs.innerHTML
D3 小程序: web-view src / navigateTo url / 子包独立密钥

### E. 现代攻击面
E1 GraphQL: introspection / batch / aliasing
E2 WebSocket: new WebSocket / 鉴权缺失
E3 JWT/OAuth: 本地改 claim / 弱校验 / redirect_uri 可控
"""


# 快速正则预筛：覆盖 xinru 主模式，避免每行都调 LLM
QUICK_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern": "A1",
        "pattern_name": "硬编码凭据",
        "severity_guess": "high",
        "regex": re.compile(
            r"""(?i)(?:key|secret|password|passwd|token|appsecret|app_key|api[_-]?key|dkt_secret|access[_-]?key|private[_-]?key|client_secret|sessiontoken)\s*[:=]\s*['\"][^'\"]{6,}['\"]"""
        ),
    },
    {
        "pattern": "A2",
        "pattern_name": "URL/路径拼接",
        "severity_guess": "medium",
        "regex": re.compile(
            r"""(?i)(?:url|path|href|src|endpoint|api)\s*=\s*.*(?:\+|`[^`]*\$\{)|\+ ?['\"]/|['\"]/[^'\"]*['\"]\s*\+"""
        ),
    },
    {
        "pattern": "A3",
        "pattern_name": "动态参数传入API",
        "severity_guess": "medium",
        "regex": re.compile(
            r"""(?i)(?:wx\.request|uni\.request|axios|fetch|request|http\.(?:get|post|put|delete|patch))\s*\(|(?:data|params|body)\s*:\s*(?:params|data|payload|form|query|values)\b"""
        ),
    },
    {
        "pattern": "A4",
        "pattern_name": "无认证/弱认证接口线索",
        "severity_guess": "medium",
        "regex": re.compile(
            r"""(?i)https?://[a-z0-9.-]+(?::\d+)?/[^\s'\"`]*"""
        ),
        "extract_lead": True,
    },
    {
        "pattern": "A5",
        "pattern_name": "签名/加密逻辑",
        "severity_guess": "medium",
        "regex": re.compile(
            r"""(?i)(?:md5|sha256|sha1|hmac|crypto\.create(?:h|H)mac|hexdigest|createHash|btoa|atob)\s*\("""
        ),
    },
    {
        "pattern": "A6",
        "pattern_name": "用户输入直传/危险渲染",
        "severity_guess": "high",
        "regex": re.compile(
            r"""(?i)(?:innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write|eval\s*\(|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]|decodeURIComponent\s*\()"""
        ),
    },
    {
        "pattern": "A7",
        "pattern_name": "文件上传/下载",
        "severity_guess": "high",
        "regex": re.compile(
            r"""(?i)(?:upload(?:file)?|download(?:file)?|multipart/form-data|presigned|sasToken|OSSAccessKey|x-oss-|putObject|getObject)"""
        ),
    },
    {
        "pattern": "A8",
        "pattern_name": "开放重定向/跳转",
        "severity_guess": "medium",
        "regex": re.compile(
            r"""(?i)(?:location\.(?:href|assign|replace)\s*=|window\.open\s*\(|navigateTo\s*\(|redirect\s*\(|router\.(?:push|replace)\s*\()"""
        ),
    },
    {
        "pattern": "B1",
        "pattern_name": "价格/数量篡改",
        "severity_guess": "high",
        "regex": re.compile(
            r"""(?i)\b(?:totalPrice|amount|price|payAmount|discount|quantity|qty|couponAmount|fee)\b"""
        ),
    },
    {
        "pattern": "B2",
        "pattern_name": "越权对象标识",
        "severity_guess": "high",
        "regex": re.compile(
            r"""(?i)\b(?:userId|user_id|uid|orderId|order_id|memberId|member_id|accountId|customerId|tenantId|orgId)\b"""
        ),
    },
    {
        "pattern": "B3",
        "pattern_name": "状态机/步骤参数",
        "severity_guess": "medium",
        "regex": re.compile(
            r"""(?i)\b(?:step|stage|status|state|workflow|approve|approval)\b\s*[:=]"""
        ),
    },
    {
        "pattern": "B4",
        "pattern_name": "一次性操作/竞态面",
        "severity_guess": "medium",
        "regex": re.compile(
            r"""(?i)\b(?:receiveCoupon|claim|lottery|withdraw|redeem|seckill|flashSale|inventory|stock)\b"""
        ),
    },
    {
        "pattern": "B5",
        "pattern_name": "时间窗参数",
        "severity_guess": "medium",
        "regex": re.compile(
            r"""(?i)\b(?:expire(?:At|Time)?|timestamp|ts|trial|validUntil|deadline)\b\s*[:=]"""
        ),
    },
    {
        "pattern": "D1",
        "pattern_name": "React危险渲染",
        "severity_guess": "high",
        "regex": re.compile(r"""dangerouslySetInnerHTML\s*="""),
    },
    {
        "pattern": "D2",
        "pattern_name": "Vue危险渲染",
        "severity_guess": "high",
        "regex": re.compile(r"""(?i)v-html\s*=|\$refs\.[A-Za-z0-9_]+\.innerHTML\s*="""),
    },
    {
        "pattern": "E1",
        "pattern_name": "GraphQL攻击面",
        "severity_guess": "medium",
        "regex": re.compile(r"""(?i)graphql|/gql\b|__schema|introspection"""),
    },
    {
        "pattern": "E2",
        "pattern_name": "WebSocket攻击面",
        "severity_guess": "medium",
        "regex": re.compile(r"""(?i)new\s+WebSocket\s*\(|wss?://"""),
    },
    {
        "pattern": "E3",
        "pattern_name": "JWT/OAuth面",
        "severity_guess": "medium",
        "regex": re.compile(
            r"""(?i)\b(?:jwt|jsonwebtoken|access_token|id_token|refresh_token|redirect_uri|client_id)\b"""
        ),
    },
]


# 业务关键字命中时，要求同段出现“请求/提交/传参”语境，减少噪音
_BUSINESS_CONTEXT = re.compile(
    r"""(?i)(?:request|axios|fetch|post|put|delete|submit|params|data\s*:|body\s*:|query)"""
)


def make_scan_prompt(code_snippet: str, file_path: str, line_start: int) -> str:
    """构造逐行扫描 prompt"""
    lines = code_snippet.split("\n")
    numbered = "\n".join(f"  {line_start + i}: {line}" for i, line in enumerate(lines))
    return f"""正在审计文件: {file_path}

当前代码片段（第 {line_start} 行起）:
{numbered}

{THREAT_PATTERNS}

---
请逐行分析以上代码。规则：
1. 先标威胁，不要直接宣布漏洞
2. 只报告真正可疑、值得追溯验证的点
3. 忽略明显第三方库噪音（除非含硬编码密钥/内部域名）
4. 若无可疑，返回 {{"threats": []}}

返回 JSON:
{{
  "threats": [
    {{
      "line": <行号>,
      "pattern": "<如 A1/B2/E3>",
      "pattern_name": "<威胁名>",
      "description": "<为什么可疑，参数/数据从哪来>",
      "severity_guess": "<critical|high|medium|low>",
      "suggested_endpoint": "<若能看出接口则给出，否则空字符串>"
    }}
  ]
}}"""


CALL_CHAIN_PROMPT = """你正在追溯一个可疑代码点的完整调用链。必须回答以下 5 个问题：

1. 谁调用它？（逐级向上追溯到入口）
2. 参数从哪来？（URL参数 / 用户输入 / API响应 / localStorage / 硬编码 / Cookie）
3. 数据怎么流？（来源 → 中间函数 → 最终 sink）
4. 定位到哪个接口？（域名 + 路径 + 方法 + 参数 + Header）
5. 有什么防护？（JWT / 签名 / 白名单 / 服务端校验 / 无防护）

已知上下文:
- 文件: {file_path}
- 行号: {line_number}
- 威胁: {pattern_name}
- 当前行: {current_line}
- 上下文:
{context}
- 跨文件搜索命中:
{search_hits}

返回 JSON:
{{
  "callers": [{{"file": "...", "function": "...", "line": 0}}],
  "param_source": "...",
  "data_flow": "...",
  "api_endpoint": {{
    "method": "GET|POST|PUT|DELETE|PATCH",
    "domain": "host 或完整 origin",
    "path": "/api/...",
    "params": {{}},
    "headers": {{}},
    "full_url": "https://..."
  }},
  "defenses": ["..."],
  "attacker_controllable": true,
  "notes": "..."
}}"""


SELF_CHECK_PROMPT = """在输出漏洞结论前，必须回答 5 个自检问题。诚实，不要自欺欺人。

漏洞信息:
- 名称: {finding_name}
- 文件: {file_path}:{line_number}
- 威胁模式: {pattern}
- 调用链: {call_chain}
- 接口: {api_endpoint}
- Yakit 验证结果: {yakit_results}

自检问题:
1. 认证载体是什么？Cookie / Header / 签名 / 无？
2. 利用条件攻击者能独立满足吗？
3. 有没有跳过中间环节？每一步都有实际验证吗？
4. 有没有更简单的无害解释（假阳性）？
5. 能否与其他发现组合成攻击链？

判定标准:
- confirmed: 有实际请求/响应证据证明可利用，且攻击者条件可独立满足
- excluded: 有防护/不可利用/明显误报
- uncertain: 工具限制、接口未定位、网络失败、证据不足

只返回 JSON:
{{
  "answers": {{
    "auth_carrier": "...",
    "attacker_can_satisfy": true,
    "no_skipped_steps": true,
    "simpler_explanation": "...",
    "chainable": false
  }},
  "verdict": "confirmed|excluded|uncertain",
  "severity": "critical|high|medium|low|info",
  "attack_impact": "攻击者实际能做什么",
  "fix_suggestion": "具体修复建议",
  "reason": "判定理由"
}}"""


ATTACK_CHAIN_PROMPT = """以下是已确认/可疑漏洞列表。请判断是否存在可串联攻击链。

漏洞列表:
{findings_json}

规则:
1. 仅在 A 的输出可作为 B 的输入/前提时建立链路
2. 不要硬凑
3. 给出端到端步骤

返回 JSON:
{{
  "chains": [
    {{
      "name": "链名称",
      "finding_numbers": [1, 2],
      "steps": ["步骤1", "步骤2"],
      "impact": "最终影响",
      "feasible": true
    }}
  ]
}}"""
