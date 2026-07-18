"""HTML 漏洞报告生成器

输出符合 xinru 结论格式的独立 HTML 文件，包含:
- 漏洞概览表
- 每个漏洞的完整详情（调用链/接口/7步验证证据/自检结果）
- Yakit 可导入的原始 HTTP 请求包
- 攻击链端到端验证结果
"""

import json
import os
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


async def generate_html_report(task_id: int) -> str:
    """生成 HTML 报告文件，返回文件路径"""
    from storage.models import Task, Finding, AttackChain, ProgressLog, CollectedFile

    task = Task.get_by_id(task_id)
    findings = list(Finding.select().where(Finding.task_id == task_id).order_by(Finding.finding_number))
    chains = list(AttackChain.select().where(AttackChain.task_id == task_id).order_by(AttackChain.chain_number))
    files = list(CollectedFile.select().where(CollectedFile.task_id == task_id))
    logs = list(ProgressLog.select().where(ProgressLog.task_id == task_id).order_by(ProgressLog.id))

    targets = json.loads(task.target)
    config = task.get_config()

    # 按严重级别排序
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    confirmed = [f for f in findings if f.verdict == "confirmed"]
    suspected = [f for f in findings if f.verdict == "uncertain"]
    excluded = [f for f in findings if f.verdict == "excluded"]

    html = _build_html(task, targets, config, findings, confirmed, suspected, excluded, chains, files, logs)

    # 写入文件（支持容器挂载 REPORTS_DIR）
    report_dir = Path(os.environ.get("REPORTS_DIR", str(BASE_DIR / "reports"))).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"task_{task_id}_report.html"
    report_path.write_text(html, encoding="utf-8")

    return str(report_path)


def _build_html(task, targets, config, findings, confirmed, suspected, excluded, chains, files, logs) -> str:
    """构建完整 HTML 报告"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>xinru 渗透测试审计报告 — 任务 #{task.id}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1100px; margin: 0 auto; padding: 20px; background: #f5f5f5; color: #333; }}
  h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
  h2 {{ color: #16213e; margin-top: 30px; border-bottom: 2px solid #0f3460; padding-bottom: 6px; }}
  h3 {{ color: #533483; }}
  .meta {{ background: #fff; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #0f3460; }}
  .meta table {{ width: 100%; border-collapse: collapse; }}
  .meta td {{ padding: 4px 8px; font-size: 14px; }}
  .meta td:first-child {{ font-weight: 600; width: 140px; color: #555; }}

  .overview {{ background: #fff; padding: 15px; border-radius: 8px; margin: 15px 0; }}
  .overview table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .overview th {{ background: #1a1a2e; color: #fff; padding: 8px 10px; text-align: left; }}
  .overview td {{ padding: 6px 10px; border-bottom: 1px solid #eee; }}
  .overview tr:hover {{ background: #f8f8ff; }}

  .finding {{ background: #fff; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 5px solid #ccc; }}
  .finding.critical {{ border-left-color: #e94560; }}
  .finding.high {{ border-left-color: #ff6b6b; }}
  .finding.medium {{ border-left-color: #ffa502; }}
  .finding.low {{ border-left-color: #2ed573; }}

  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: 700; color: #fff; }}
  .badge-critical {{ background: #e94560; }}
  .badge-high {{ background: #ff6b6b; }}
  .badge-medium {{ background: #ffa502; }}
  .badge-low {{ background: #2ed573; }}
  .badge-confirmed {{ background: #e94560; }}
  .badge-uncertain {{ background: #ffa502; }}
  .badge-excluded {{ background: #999; }}

  .packet {{ background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; font-size: 12px; line-height: 1.5; margin: 10px 0; white-space: pre-wrap; word-break: break-all; }}
  .packet-label {{ font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }}

  .chain {{ background: #fff; padding: 20px; border-radius: 8px; margin: 20px 0; border: 2px dashed #533483; }}
  .chain-arrow {{ color: #533483; font-weight: bold; font-size: 18px; margin: 0 10px; }}

  .call-flow {{ background: #f0f0f8; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; margin: 10px 0; }}
  .summary {{ display: flex; gap: 15px; flex-wrap: wrap; }}
  .summary-card {{ background: #fff; padding: 15px 20px; border-radius: 8px; text-align: center; min-width: 120px; }}
  .summary-card .num {{ font-size: 36px; font-weight: 800; }}
  .summary-card .label {{ font-size: 12px; color: #888; }}

  .toc {{ background: #fff; padding: 15px 20px; border-radius: 8px; margin: 15px 0; }}
  .toc a {{ color: #0f3460; text-decoration: none; }}
  .toc a:hover {{ text-decoration: underline; }}

  .evidence-table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin: 10px 0; }}
  .evidence-table th {{ background: #333; color: #fff; padding: 6px 8px; }}
  .evidence-table td {{ padding: 4px 8px; border-bottom: 1px solid #ddd; vertical-align: top; }}
  .evidence-table .step {{ font-weight: 600; white-space: nowrap; }}

  footer {{ margin-top: 40px; padding-top: 15px; border-top: 1px solid #ddd; font-size: 12px; color: #999; text-align: center; }}
  @media print {{ body {{ background: #fff; }} .finding, .chain {{ break-inside: avoid; }} }}
</style>
</head>
<body>

<h1>🛡️ xinru 渗透测试审计报告</h1>

<div class="meta">
  <table>
    <tr><td>任务编号</td><td>#{task.id}</td></tr>
    <tr><td>目标</td><td>{', '.join(targets)}</td></tr>
    <tr><td>创建时间</td><td>{task.created_at.strftime('%Y-%m-%d %H:%M:%S') if task.created_at else '—'}</td></tr>
    <tr><td>完成时间</td><td>{task.completed_at.strftime('%Y-%m-%d %H:%M:%S') if task.completed_at else '—'}</td></tr>
    <tr><td>收集文件数</td><td>{task.total_files_collected}</td></tr>
    <tr><td>审计行数</td><td>{task.total_lines_audited}</td></tr>
    <tr><td>发现漏洞数</td><td>{task.total_findings}</td></tr>
    <tr><td>认证方式</td><td>{'有凭证' if config.get('credentials') or config.get('cookies') else '无认证模式'}</td></tr>
    <tr><td>报告生成时间</td><td>{now}</td></tr>
  </table>
</div>

<h2>📊 漏洞概览</h2>
<div class="summary">
  <div class="summary-card"><div class="num" style="color:#e94560;">{len(confirmed)}</div><div class="label">✅ 已确认</div></div>
  <div class="summary-card"><div class="num" style="color:#ffa502;">{len(suspected)}</div><div class="label">⚠️ 待验证</div></div>
  <div class="summary-card"><div class="num" style="color:#999;">{len(excluded)}</div><div class="label">❌ 已排除</div></div>
  <div class="summary-card"><div class="num">{len(files)}</div><div class="label">📁 收集文件</div></div>
  <div class="summary-card"><div class="num">{task.total_lines_audited}</div><div class="label">🔍 审计行数</div></div>
</div>

<div class="overview">
  <table>
    <tr><th>#</th><th>严重级别</th><th>漏洞名称</th><th>文件</th><th>判定</th></tr>
    {_findings_table(findings)}
  </table>
</div>

<h2>🔍 漏洞详情</h2>
{_findings_detail(findings)}

<h2>⛓️ 攻击链端到端验证</h2>
{_chains_detail(chains)}

<h2>⏱️ 执行日志</h2>
<div style="background:#fff;padding:15px;border-radius:8px;font-size:12px;max-height:300px;overflow-y:auto;">
{_logs_html(logs)}
</div>

<footer>
  xinru Agent — JavaScript 源码安全审计 | 报告生成于 {now}
</footer>

</body>
</html>"""


def _SEV_LABEL(severity: str) -> str:
    """严重级别中文标签（独立定义，不依赖模型类，避免作用域问题）"""
    return {
        "critical": "🔴 严重", "high": "🔴 高危",
        "medium": "🟡 中危", "low": "🟢 低危", "info": "ℹ️ 信息",
    }.get(severity, severity)


def _findings_table(findings) -> str:
    if not findings:
        return '<tr><td colspan="5" style="text-align:center;color:#999;">未发现漏洞</td></tr>'
    rows = []
    for f in findings:
        sev_badge = f'<span class="badge badge-{f.severity}">{_SEV_LABEL(f.severity)}</span>'
        verdict_label = {"confirmed": "✅ 已确认", "excluded": "❌ 已排除", "uncertain": "⚠️ 待验证"}.get(f.verdict, f.verdict)
        verdict_badge = f'<span class="badge badge-{f.verdict}">{verdict_label}</span>'
        rows.append(f"<tr><td>{f.finding_number}</td><td>{sev_badge}</td><td><a href='#finding-{f.finding_number}'>{_escape(f.name)}</a></td><td style='font-size:11px;'>{_escape(f.file_path)}:{f.line_number}</td><td>{verdict_badge}</td></tr>")
    return "\n".join(rows)


def _findings_detail(findings) -> str:
    if not findings:
        return "<p style='color:#999;'>无漏洞详情。</p>"

    sections = []
    for f in findings:
        try:
            call_chain = json.loads(f.call_chain) if f.call_chain else {}
        except json.JSONDecodeError:
            call_chain = {"callers": [], "data_flow": f.call_chain}

        try:
            api = json.loads(f.api_endpoint) if f.api_endpoint else {}
        except json.JSONDecodeError:
            api = {"method": "?", "domain": "?", "path": "?"}

        try:
            evidence_list = json.loads(f.yakit_evidence) if f.yakit_evidence else []
        except json.JSONDecodeError:
            evidence_list = []

        sev_badge = f'<span class="badge badge-{f.severity}">{_SEV_LABEL(f.severity)}</span>'

        callers_html = ""
        if call_chain.get("callers"):
            callers_html = " → ".join(
                f"{c.get('file', '?')}:{c.get('function', '?')}()" for c in call_chain["callers"]
            )

        api_str = f"{api.get('method', '?')} https://{api.get('domain', '?')}{api.get('path', '?')}"

        sections.append(f"""
<div class="finding {f.severity}" id="finding-{f.finding_number}">
  <h3>[线索 #{f.finding_number}] {_escape(f.name)} {sev_badge}</h3>

  <div class="meta">
    <table>
      <tr><td>文件</td><td><code>{_escape(f.file_path)}:{f.line_number}</code></td></tr>
      <tr><td>判定</td><td>{f.verdict}</td></tr>
      <tr><td>接口</td><td><code>{_escape(api_str)}</code></td></tr>
    </table>
  </div>

  <h4>📞 调用链</h4>
  <div class="call-flow">{_escape(callers_html) or '（调用链信息不完整）'}</div>
  <p><strong>参数来源:</strong> {_escape(call_chain.get('param_source', '?') if isinstance(call_chain, dict) else str(call_chain))}</p>
  <p><strong>数据流:</strong> {_escape(call_chain.get('data_flow', '?') if isinstance(call_chain, dict) else '')}</p>
  <p><strong>防护:</strong> {', '.join(call_chain.get('defenses', [])) if isinstance(call_chain, dict) and call_chain.get('defenses') else '未知'}</p>

  <h4>📦 接口参数</h4>
  <div class="packet"><div class="packet-label">请求参数</div>{_escape(f.parameters)}</div>

  <h4>⚡ Yakit 验证证据</h4>
  {_evidence_html(evidence_list)}

  <h4>💥 攻击影响</h4>
  <p>{_escape(f.attack_impact or '未评估')}</p>

  <h4>🔧 修复建议</h4>
  <p>{_escape(f.fix_suggestion or '未提供')}</p>
</div>
""")

    return "\n".join(sections)


def _evidence_html(evidence_list: list) -> str:
    if not evidence_list:
        return "<p style='color:#999;'>无验证证据。</p>"

    html_parts = []
    for i, ev in enumerate(evidence_list):
        step = ev.get("step", f"步骤{i+1}")
        finding = ev.get("finding", "")
        req = ev.get("request", "")
        resp = ev.get("response", "")

        html_parts.append(f"""
<div style="margin: 15px 0;">
  <strong>📝 {step}</strong> — <em>{_escape(finding)}</em>

  <div class="packet-label" style="margin-top:8px;">▼ 请求包 (可直接复制到 Yakit HTTP Fuzzer 重放)</div>
  <div class="packet">{_escape(req)}</div>

  <div class="packet-label">▼ 响应包</div>
  <div class="packet">{_escape(resp)}</div>
</div>
""")

    return "\n".join(html_parts)


def _chains_detail(chains) -> str:
    if not chains:
        return "<p style='color:#999;'>未发现可组合的攻击链。</p>"

    sections = []
    for ch in chains:
        try:
            steps = json.loads(ch.steps) if ch.steps else []
        except json.JSONDecodeError:
            steps = []

        sections.append(f"""
<div class="chain">
  <h3>[攻击链 #{ch.chain_number}] {_escape(ch.name)}</h3>
  <p><strong>涉及漏洞:</strong> {_escape(ch.involved_findings)}</p>

  <h4>📋 攻击步骤</h4>
  {_chain_steps_html(steps)}

  <h4>🎯 最终验证</h4>
  <p>{_escape(ch.final_verification)}</p>
</div>
""")

    return "\n".join(sections)


def _chain_steps_html(steps: list) -> str:
    if not steps:
        return "<p>无详细步骤。</p>"

    parts = []
    for s in steps:
        if isinstance(s, dict):
            parts.append(f"""
<div style="margin:10px 0;">
  <strong>{_escape(s.get('description', '?'))}</strong>
  <div class="packet">{_escape(s.get('request', ''))}</div>
  <div class="packet-label">▼ 响应</div>
  <div class="packet">{_escape(s.get('response', ''))}</div>
</div>
""")

    return "\n".join(parts) if parts else "<p>无详细步骤。</p>"


def _logs_html(logs) -> str:
    lines = []
    for log in logs:
        icon = {"error": "❌", "warning": "⚠️", "discovery": "🔍", "action_required": "⚡"}.get(log.log_type, "•")
        lines.append(f'<div style="margin:2px 0;">{icon} <span style="color:#888;">[{log.created_at.strftime("%H:%M:%S") if log.created_at else ""}]</span> {_escape(log.message)}</div>')
    return "\n".join(lines)


def _escape(s: str) -> str:
    """HTML 转义"""
    if not s:
        return ""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
