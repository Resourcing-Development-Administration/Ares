from __future__ import annotations
import json
import html
from engine.core.models import ScanReport
from engine.core.cvss import exploitability_plain_language

SEV_COLOR = {
    "critical": "#7f1d1d", "high": "#b91c1c", "medium": "#b45309",
    "low": "#1d4ed8", "info": "#374151",
}


FRAMEWORK_COLOR = {
    "OWASP-MCP": "#0369a1", "OWASP-LLM": "#7c3aed", "OWASP-API": "#0891b2",
    "ATLAS": "#b91c1c", "AGENTIC": "#4d7c0f",
}


def _framework_badges(f) -> str:
    if not f.frameworks:
        return ""
    chips = "".join(
        f'<a href="{t["url"]}" target="_blank" class="fw-chip" '
        f'style="background:{FRAMEWORK_COLOR.get(t["framework"], "#374151")}" '
        f'title="{_esc(t["framework"])}">{_esc((t["id"] + " ") if t["id"] else "")}{_esc(t["name"])}</a>'
        for t in f.frameworks
    )
    return f'<div class="fw-badges">{chips}</div>'


def _esc(x) -> str:
    if not isinstance(x, str):
        try:
            x = json.dumps(x, indent=2, ensure_ascii=False, default=str)
        except Exception:
            x = str(x)
    return html.escape(x)


_POLICY_COLOR = {"BLOCK": "#7f1d1d", "CONDITIONAL": "#b45309", "ALLOW": "#065f46"}


def _score_stat(report: ScanReport) -> str:
    if not report.score:
        return ""
    s = report.score
    color = {"A": "#065f46", "B": "#1d4ed8", "C": "#b45309", "D": "#b45309", "F": "#7f1d1d"}.get(s["grade"], "#374151")
    return f'<div class="stat"><b style="color:{color}">{s["score"]}/100 ({s["grade"]})</b>score de exposición</div>'


def _policy_banner(report: ScanReport) -> str:
    if not report.policy_verdict:
        return ""
    v = report.policy_verdict
    color = _POLICY_COLOR.get(v["overall"], "#374151")
    return (
        f'<div class="card" style="border-color:{color}; border-width:2px;">'
        f'<h3 style="color:{color}">Veredicto de policy ({v["environment"]}): {v["overall"]}</h3>'
        f'<p class="desc">{len(v["by_finding"])} hallazgo(s) evaluado(s) contra policy.yaml. '
        f'"BLOCK" = no apto para {v["environment"]} tal como está; "CONDITIONAL" = requiere revisión manual; '
        f'"ALLOW" = sin objeciones de policy.</p></div>'
    )


def _baseline_block(report: ScanReport) -> str:
    if not report.baseline_diff:
        return ""
    b = report.baseline_diff
    def _list(items, empty):
        if not items:
            return f'<pre>{empty}</pre>'
        return '<pre>' + _esc("\n".join(f"{i['severity'].upper()} · {i['test_id']} · {i['target']}: {i['title']}" for i in items)) + '</pre>'
    return (
        f'<div class="card">'
        f'<h3>Comparación contra baseline</h3>'
        f'<p class="desc">{_esc(b["summary"])} (baseline: {_esc(b["baseline_source"])})</p>'
        f'<details open><summary>🆕 Nuevos ({len(b["new"])})</summary>{_list(b["new"], "—")}</details>'
        f'<details><summary>✅ Resueltos ({len(b["resolved"])})</summary>{_list(b["resolved"], "—")}</details>'
        f'<details><summary>➖ Persisten ({len(b["persisting"])})</summary>{_list(b["persisting"], "—")}</details>'
        f'</div>'
    )


def _auth_impact_block(report: ScanReport) -> str:
    if not report.auth_impact:
        return ""
    a = report.auth_impact
    return (
        f'<div class="card">'
        f'<h3>Impacto de autenticación</h3>'
        f'<p class="desc">{_esc(a["summary"])}</p>'
        f'<details><summary>Mitigados por auth ({len(a["mitigated_by_auth"])})</summary>'
        f'<pre>{_esc(chr(10).join(a["mitigated_by_auth"]) or "—")}</pre></details>'
        f'<details><summary>NO mitigados por auth ({len(a["not_mitigated_by_auth"])})</summary>'
        f'<pre>{_esc(chr(10).join(a["not_mitigated_by_auth"]) or "—")}</pre></details>'
        f'</div>'
    )


_POLICY_CHIP_COLOR = {"BLOCK": "#7f1d1d", "CONDITIONAL": "#b45309", "ALLOW": "#065f46"}
_IMPACT_COLOR = {"low": "#065f46", "medium": "#b45309", "high": "#7f1d1d"}


def _risk_panel(f, policy_by_finding: dict) -> str:
    if f.passed:
        return ""
    r = f.risk
    expl = exploitability_plain_language(r["cvss_vector"])
    biz_chips = "".join(
        f'<span class="biz-chip" style="background:{_IMPACT_COLOR.get(v, "#374151")}">{k}: {v}</span>'
        for k, v in r["business_impact"].items()
    )
    policy_verdict = policy_by_finding.get(f.id)
    policy_chip = (
        f'<span class="policy-chip" style="background:{_POLICY_CHIP_COLOR.get(policy_verdict, "#374151")}">'
        f'implementación: {policy_verdict}</span>' if policy_verdict else ""
    )
    aivss = r.get("aivss")
    aivss_block = ""
    if aivss:
        af = aivss["agentic_factors"]
        aivss_block = f"""
        <div><b>AIVSS {aivss['score']}/10 <span style="color:#9ca3af;font-weight:normal">(aproximación, complementa el rating de arriba)</span></b>
          <ul>
            <li>Factores agénticos: autonomía {af['autonomy']}, uso de herramientas {af['tool_use']}, no-determinismo {af['nondeterminism']}</li>
            <li>Threat multiplier: {aivss['threat_multiplier']} (confidence del finding) · mitigation factor: {aivss['mitigation_factor']}</li>
          </ul>
          <p class="desc" style="font-size:.75rem">{_esc(aivss['note'])}</p>
        </div>"""
    return f"""
    <details class="risk-panel">
      <summary>Riesgo — CVSS {r['cvss_score']} ({r['cvss_severity']}) · rating {r['risk_rating']} (OWASP){f" · AIVSS {aivss['score']}" if aivss else ""} · remediación: {r['remediation_effort']} {policy_chip}</summary>
      <div class="risk-grid">
        <div><b>Vector CVSS v3.1</b><code>{_esc(r['cvss_vector'])}</code></div>
        <div><b>Facilidad de explotación</b>
          <ul>
            <li>Vector de ataque: {expl['attack_vector']}</li>
            <li>Complejidad: {expl['attack_complexity']}</li>
            <li>Privilegios requeridos: {expl['privileges_required']}</li>
            <li>Interacción de usuario: {expl['user_interaction']}</li>
          </ul>
        </div>
        <div><b>Impacto al negocio (OWASP Risk Rating)</b><div class="biz-chips">{biz_chips}</div></div>
        <div><b>Esfuerzo de remediación: {r['remediation_effort']}</b><p class="desc">{_esc(r['remediation_effort_rationale'])}</p></div>
        {aivss_block}
      </div>
    </details>
    """


def render_html(report: ScanReport) -> str:
    summary = report.summary()
    findings = sorted(report.findings, key=lambda f: (f.passed, f.severity.value))
    policy_by_finding = {}
    if report.policy_verdict:
        policy_by_finding = {bf["finding_id"]: bf["verdict"] for bf in report.policy_verdict.get("by_finding", [])}

    rows = []
    for f in findings:
        badge = "PASS" if f.passed else "FINDING"
        badge_color = "#065f46" if f.passed else SEV_COLOR.get(f.severity.value, "#374151")
        suppressed_badge = (
            f'<span class="badge" style="background:#374151" title="{_esc(f.suppressed_reason or "")}">SUPRIMIDO</span>'
            if f.suppressed else ""
        )
        rows.append(f"""
        <div class="card{' suppressed' if f.suppressed else ''}" data-sev="{f.severity.value}" data-cat="{f.category.value}" data-passed="{str(f.passed).lower()}" data-suppressed="{str(f.suppressed).lower()}">
          <div class="card-head">
            <span class="badge" style="background:{badge_color}">{badge} · {f.severity.value.upper()}</span>
            {suppressed_badge}
            <span class="conf-badge conf-{f.confidence}" title="{'hecho observado directamente' if f.confidence == 'verified' else 'señal heurística, revisar manualmente'}">{f.confidence}</span>
            <span class="cat">{f.category.value}</span>
            <span class="target">target: {_esc(f.target)}</span>
          </div>
          <h3>{_esc(f.title)}</h3>
          {_framework_badges(f)}
          <p class="desc">{_esc(f.description)}</p>
          {f'<p class="desc" style="color:#9ca3af"><b>Suprimido:</b> {_esc(f.suppressed_reason)} — no cuenta para score/policy, pero sigue acá para auditoría.</p>' if f.suppressed else ""}
          {_risk_panel(f, policy_by_finding)}
          <details>
            <summary>Evidencia (request / response)</summary>
            <pre>REQUEST:
{_esc(f.evidence.request)}

RESPONSE:
{_esc(f.evidence.response)}

NOTES: {_esc(f.evidence.notes)}</pre>
          </details>
          {"<p class='remediation'><b>Remediación:</b> " + _esc(f.remediation) + "</p>" if f.remediation else ""}
          <div class="meta">test_id: {f.test_id} · id: {f.id} · {f.timestamp}</div>
        </div>
        """)

    errors_html = "".join(f"<li>{_esc(e)}</li>" for e in report.errors) or "<li>Ninguno</li>"

    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>Reporte MCP Red Team — {_esc(report.target_name)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; background:#0b0f14; color:#e5e7eb; margin:0; padding:2rem; }}
  h1 {{ font-size:1.5rem; }}
  .summary {{ display:flex; gap:1rem; flex-wrap:wrap; margin:1rem 0 2rem; }}
  .stat {{ background:#111827; border:1px solid #1f2937; border-radius:8px; padding:.75rem 1.25rem; }}
  .stat b {{ font-size:1.4rem; display:block; }}
  .filters {{ margin-bottom:1rem; display:flex; gap:.5rem; flex-wrap:wrap; }}
  .filters button {{ background:#1f2937; color:#e5e7eb; border:1px solid #374151; border-radius:6px; padding:.4rem .8rem; cursor:pointer; }}
  .filters button.active {{ background:#374151; }}
  .card {{ background:#111827; border:1px solid #1f2937; border-radius:10px; padding:1rem 1.25rem; margin-bottom:.75rem; }}
  .card.suppressed {{ opacity:.55; }}
  .card-head {{ display:flex; gap:.6rem; align-items:center; margin-bottom:.4rem; font-size:.75rem; }}
  .badge {{ color:white; padding:.15rem .5rem; border-radius:4px; font-weight:600; }}
  .cat {{ color:#9ca3af; text-transform:uppercase; letter-spacing:.05em; }}
  .target {{ color:#9ca3af; margin-left:auto; }}
  .desc {{ color:#d1d5db; }}
  pre {{ background:#030712; padding:.75rem; border-radius:6px; overflow-x:auto; font-size:.8rem; white-space:pre-wrap; word-break:break-word; }}
  .remediation {{ color:#a7f3d0; font-size:.9rem; }}
  .meta {{ color:#4b5563; font-size:.7rem; margin-top:.5rem; }}
  details summary {{ cursor:pointer; color:#93c5fd; margin:.5rem 0; }}
  .fw-badges {{ margin:.3rem 0 .5rem; display:flex; gap:.4rem; flex-wrap:wrap; }}
  .fw-chip {{ color:white; font-size:.68rem; padding:.15rem .5rem; border-radius:999px; text-decoration:none; }}
  .conf-badge {{ font-size:.68rem; padding:.1rem .5rem; border-radius:4px; text-transform:uppercase; letter-spacing:.03em; }}
  .conf-verified {{ background:#064e3b; color:#6ee7b7; }}
  .conf-heuristic {{ background:#3f2d05; color:#fbbf24; }}
  .risk-panel {{ margin:.6rem 0; background:#0b0f14; border:1px solid #1f2937; border-radius:8px; padding:.4rem .8rem; }}
  .risk-panel summary {{ font-size:.8rem; }}
  .risk-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:.8rem; margin-top:.6rem; font-size:.82rem; }}
  .risk-grid code {{ display:block; background:#030712; padding:.3rem .5rem; border-radius:4px; margin-top:.2rem; word-break:break-all; }}
  .risk-grid ul {{ margin:.3rem 0 0; padding-left:1.1rem; color:#d1d5db; }}
  .biz-chips {{ display:flex; gap:.3rem; flex-wrap:wrap; margin-top:.3rem; }}
  .biz-chip {{ color:white; font-size:.68rem; padding:.1rem .45rem; border-radius:4px; }}
  .policy-chip {{ color:white; font-size:.68rem; padding:.1rem .5rem; border-radius:4px; margin-left:.5rem; }}
</style></head>
<body>
  <h1>🛡️ Reporte MCP Red Team</h1>
  <p>Target: <b>{_esc(report.target_name)}</b> · Scan ID: {report.scan_id} · {report.started_at} → {report.finished_at}</p>

  <div class="summary">
    <div class="stat"><b>{summary['total_tests_run']}</b>tests ejecutados</div>
    <div class="stat"><b>{summary['confirmed_findings']}</b>hallazgos confirmados</div>
    <div class="stat"><b style="color:{SEV_COLOR['critical']}">{summary['by_severity']['critical']}</b>critical</div>
    <div class="stat"><b style="color:{SEV_COLOR['high']}">{summary['by_severity']['high']}</b>high</div>
    <div class="stat"><b style="color:{SEV_COLOR['medium']}">{summary['by_severity']['medium']}</b>medium</div>
    <div class="stat"><b style="color:{SEV_COLOR['low']}">{summary['by_severity']['low']}</b>low</div>
    {f'<div class="stat"><b style="color:#6b7280">{summary["suppressed_findings"]}</b>suprimidos (no gatean score/policy)</div>' if summary.get('suppressed_findings') else ''}
    {_score_stat(report)}
  </div>

  {_policy_banner(report)}
  {_baseline_block(report)}
  {_auth_impact_block(report)}

  <details><summary>Errores/skips durante el scan</summary><ul>{errors_html}</ul></details>

  <div class="filters">
    <button onclick="filt('all')" class="active">Todos</button>
    <button onclick="filt('findings')">Solo hallazgos</button>
    <button onclick="filt('critical')">Critical</button>
    <button onclick="filt('high')">High</button>
    <button onclick="filt('medium')">Medium</button>
    <button onclick="filt('low')">Low</button>
    <button onclick="filt('suppressed')">Suprimidos</button>
  </div>

  <div id="cards">
    {''.join(rows)}
  </div>

<script>
function filt(mode) {{
  document.querySelectorAll('.card').forEach(c => {{
    let show = true;
    if (mode === 'findings') show = c.dataset.passed === 'false' && c.dataset.suppressed === 'false';
    else if (mode === 'suppressed') show = c.dataset.suppressed === 'true';
    else if (mode !== 'all') show = c.dataset.sev === mode && c.dataset.passed === 'false' && c.dataset.suppressed === 'false';
    c.style.display = show ? 'block' : 'none';
  }});
  document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
}}
</script>
</body></html>"""


def save_html_report(report: ScanReport, path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(report))
