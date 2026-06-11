"""
Professional HTML audit report generator.
Produces a self-contained single-file HTML report — no internet connection needed.
"""
from datetime import datetime
from typing import List
from ..engine import AuditResult
from ..rules.base import Finding, Severity


_SEV_CSS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#06b6d4",
    "INFO": "#6b7280",
}

_IMPACT_CSS = {
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#06b6d4",
    "INFO": "#6b7280",
}


def _sev_badge(sev: str, css_map=None) -> str:
    if css_map is None:
        css_map = _SEV_CSS
    color = css_map.get(sev, "#6b7280")
    return f'<span class="badge" style="background:{color}">{sev}</span>'


def _findings_rows(findings: List[Finding], css_map=None) -> str:
    if not findings:
        return '<tr><td colspan="5" class="empty">No findings</td></tr>'
    rows = []
    for f in findings:
        l2 = '<span class="l2-tag">L2</span>' if f.l2_specific else ""
        rows.append(
            f"<tr onclick=\"toggle('{f.rule_id}')\" style=\"cursor:pointer\">"
            f"<td><code>{f.rule_id}</code></td>"
            f"<td>{_sev_badge(f.severity.name, css_map)}</td>"
            f"<td>{f.title} {l2}</td>"
            f"<td>{f.line_str()}</td>"
            f"<td>▾</td>"
            f"</tr>"
            f"<tr id=\"{f.rule_id}\" class=\"detail-row\" style=\"display:none\">"
            f"<td colspan=\"5\">"
            f"<div class=\"detail\">"
            f"<p><strong>Description:</strong><br>{f.description.replace(chr(10), '<br>')}</p>"
            f"<p><strong>Recommendation:</strong><br>{f.recommendation.replace(chr(10), '<br>')}</p>"
            + (f"<pre><code>{f.code_snippet[:300]}</code></pre>" if f.code_snippet else "")
            + "</div></td></tr>"
        )
    return "\n".join(rows)


def _score_ring(score: int) -> str:
    color = "#22c55e" if score >= 80 else "#eab308" if score >= 50 else "#ef4444"
    r = 36
    circumference = 2 * 3.14159 * r
    dash = circumference * score / 100
    gap = circumference - dash
    return f"""
    <svg viewBox="0 0 100 100" width="90" height="90">
      <circle cx="50" cy="50" r="{r}" fill="none" stroke="#1e293b" stroke-width="10"/>
      <circle cx="50" cy="50" r="{r}" fill="none" stroke="{color}" stroke-width="10"
        stroke-dasharray="{dash:.1f} {gap:.1f}"
        stroke-dashoffset="{circumference * 0.25:.1f}"
        stroke-linecap="round"/>
      <text x="50" y="55" text-anchor="middle" fill="{color}"
        font-size="20" font-weight="bold">{score}</text>
    </svg>"""


def generate_html(result: AuditResult, output_path: str):
    counts = result.severity_counts()
    risk = result.risk_level()
    risk_color = {
        "CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
        "LOW": "#06b6d4", "SAFE": "#22c55e",
    }[risk]
    compliance_score = result.compliance_score()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    n_lines = len(result.parsed.lines)
    pragma = result.parsed.pragma or "unknown"
    n_contracts = len(result.parsed.contracts)
    contract_names = ", ".join(c.name for c in result.parsed.contracts) or "—"

    vuln_rows = _findings_rows(result.security_findings, _SEV_CSS)
    gas_rows = _findings_rows(result.gas_findings, _IMPACT_CSS)
    comp_rows = _findings_rows(result.compliance_findings, _SEV_CSS)

    gas_high = sum(1 for f in result.gas_findings if f.severity.value >= 3)
    mantle_issues = sum(1 for f in result.all_findings() if f.mantle_specific)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mantle Audit Report — {result.source_file}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #3b82f6;
    --border: #334155;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}

  /* Header */
  .header {{ background: linear-gradient(135deg, #1e3a5f 0%, #1e293b 100%); border: 1px solid #334155; border-radius: 12px; padding: 32px; margin-bottom: 28px; }}
  .header-top {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 24px; flex-wrap: wrap; }}
  .brand {{ display: flex; align-items: center; gap: 12px; }}
  .brand-icon {{ width: 42px; height: 42px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 22px; }}
  .brand-name {{ font-size: 20px; font-weight: 700; color: #f1f5f9; }}
  .brand-sub {{ font-size: 12px; color: var(--muted); }}
  .meta {{ font-size: 12px; color: var(--muted); text-align: right; }}
  .meta strong {{ color: var(--text); }}

  /* Risk banner */
  .risk-banner {{ margin-top: 24px; padding: 16px 20px; border-radius: 8px; border-left: 4px solid {risk_color}; background: rgba(255,255,255,0.04); display: flex; align-items: center; gap: 16px; }}
  .risk-label {{ font-size: 28px; font-weight: 800; color: {risk_color}; }}
  .risk-sub {{ font-size: 13px; color: var(--muted); }}

  /* Cards grid */
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 28px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; }}
  .card-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-bottom: 6px; }}
  .card-value {{ font-size: 26px; font-weight: 700; }}
  .card-sub {{ font-size: 11px; color: var(--muted); margin-top: 4px; }}

  /* Sections */
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 24px; overflow: hidden; }}
  .section-header {{ padding: 18px 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 12px; }}
  .section-title {{ font-size: 16px; font-weight: 600; }}
  .section-count {{ background: var(--surface2); color: var(--muted); padding: 2px 10px; border-radius: 20px; font-size: 12px; }}

  /* Table */
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; padding: 10px 16px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); background: var(--surface2); border-bottom: 1px solid var(--border); }}
  td {{ padding: 10px 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
  tr:last-child > td {{ border-bottom: none; }}
  tr:hover > td {{ background: rgba(255,255,255,0.03); }}
  .empty {{ text-align: center; color: #22c55e; padding: 24px; }}

  /* Badges */
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; color: #fff; }}
  .l2-tag {{ background: #7c3aed; color: #fff; font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 4px; margin-left: 6px; }}

  /* Detail rows */
  .detail-row {{ background: rgba(59, 130, 246, 0.04); }}
  .detail {{ padding: 16px 20px; font-size: 13px; }}
  .detail p {{ margin-bottom: 10px; }}
  pre {{ background: #0d1117; padding: 12px 16px; border-radius: 6px; overflow-x: auto; font-size: 12px; color: #79c0ff; margin-top: 8px; border: 1px solid #30363d; }}

  /* Compliance */
  .compliance-row {{ display: flex; align-items: center; gap: 28px; padding: 24px; }}
  .compliance-text {{ flex: 1; }}
  .compliance-status {{ font-size: 18px; font-weight: 700; margin-bottom: 6px; }}
  .compliance-sub {{ font-size: 13px; color: var(--muted); }}

  /* Footer */
  .footer {{ text-align: center; color: var(--muted); font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); }}
  .footer strong {{ color: #3b82f6; }}
  code {{ font-family: 'Courier New', monospace; font-size: 12px; background: rgba(255,255,255,0.08); padding: 1px 5px; border-radius: 4px; }}

  @media print {{
    body {{ background: #fff; color: #000; }}
    .detail-row {{ display: table-row !important; }}
  }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="header-top">
      <div class="brand">
        <div class="brand-icon">⬡</div>
        <div>
          <div class="brand-name">Mantle Audit Assistant</div>
          <div class="brand-sub">AI DevTools · Track 5 · Mantle Turing Test Hackathon 2026</div>
        </div>
      </div>
      <div class="meta">
        <div><strong>File:</strong> {result.source_file}</div>
        <div><strong>Date:</strong> {now}</div>
        <div><strong>Pragma:</strong> {pragma}</div>
        <div><strong>Contracts:</strong> {contract_names}</div>
        <div><strong>Lines:</strong> {n_lines}</div>
      </div>
    </div>
    <div class="risk-banner">
      <div>
        <div class="risk-label">{risk}</div>
        <div class="risk-sub">Overall Security Risk Level</div>
      </div>
      <div style="color:var(--muted); font-size:13px;">
        <span style="color:#ef4444; font-weight:700">{counts['CRITICAL']} Critical</span> &nbsp;·&nbsp;
        <span style="color:#f97316">{counts['HIGH']} High</span> &nbsp;·&nbsp;
        <span style="color:#eab308">{counts['MEDIUM']} Medium</span> &nbsp;·&nbsp;
        <span style="color:#06b6d4">{counts['LOW']} Low</span>
      </div>
    </div>
  </div>

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card">
      <div class="card-label">Security Issues</div>
      <div class="card-value" style="color:{risk_color}">{len(result.security_findings)}</div>
      <div class="card-sub">{counts['CRITICAL']}C · {counts['HIGH']}H · {counts['MEDIUM']}M</div>
    </div>
    <div class="card">
      <div class="card-label">Gas Optimizations</div>
      <div class="card-value" style="color:#eab308">{len(result.gas_findings)}</div>
      <div class="card-sub">{gas_high} high/medium impact</div>
    </div>
    <div class="card">
      <div class="card-label">ERC-8004 Score</div>
      <div class="card-value" style="color:{'#22c55e' if compliance_score >= 80 else '#eab308' if compliance_score >= 50 else '#ef4444'}">{compliance_score}%</div>
      <div class="card-sub">{len(result.compliance_findings)} compliance issues</div>
    </div>
    <div class="card">
      <div class="card-label">Mantle L2 Issues</div>
      <div class="card-value" style="color:#8b5cf6">{mantle_issues}</div>
      <div class="card-sub">L2-specific findings</div>
    </div>
    <div class="card">
      <div class="card-label">Source Lines</div>
      <div class="card-value" style="color:var(--accent)">{n_lines}</div>
      <div class="card-sub">{n_contracts} contract(s)</div>
    </div>
  </div>

  <!-- Security Section -->
  <div class="section">
    <div class="section-header">
      <span style="font-size:18px">🔐</span>
      <span class="section-title">Security Vulnerabilities</span>
      <span class="section-count">{len(result.security_findings)} findings</span>
    </div>
    <table>
      <thead><tr>
        <th>ID</th><th>Severity</th><th>Title</th><th>Line(s)</th><th></th>
      </tr></thead>
      <tbody>{vuln_rows}</tbody>
    </table>
  </div>

  <!-- Gas Section -->
  <div class="section">
    <div class="section-header">
      <span style="font-size:18px">⛽</span>
      <span class="section-title">Gas Optimization — Mantle L2</span>
      <span class="section-count">{len(result.gas_findings)} opportunities</span>
    </div>
    <table>
      <thead><tr>
        <th>ID</th><th>Impact</th><th>Title</th><th>Line(s)</th><th></th>
      </tr></thead>
      <tbody>{gas_rows}</tbody>
    </table>
  </div>

  <!-- ERC-8004 Section -->
  <div class="section">
    <div class="section-header">
      <span style="font-size:18px">🤖</span>
      <span class="section-title">ERC-8004 Agent Identity Compliance</span>
      <span class="section-count">{len(result.compliance_findings)} issues</span>
    </div>
    <div class="compliance-row">
      {_score_ring(compliance_score)}
      <div class="compliance-text">
        <div class="compliance-status" style="color:{'#22c55e' if compliance_score >= 80 else '#eab308' if compliance_score >= 50 else '#ef4444'}">
          {'COMPLIANT' if compliance_score >= 80 else 'PARTIALLY COMPLIANT' if compliance_score >= 50 else 'NON-COMPLIANT'}
        </div>
        <div class="compliance-sub">
          {compliance_score}/100 · {len(result.compliance_findings)} issues across Identity, Reputation, and Validation registries
        </div>
      </div>
    </div>
    <table>
      <thead><tr>
        <th>ID</th><th>Severity</th><th>Requirement</th><th>Line(s)</th><th></th>
      </tr></thead>
      <tbody>{comp_rows}</tbody>
    </table>
  </div>

  <!-- Footer -->
  <div class="footer">
    <strong>Mantle Smart Contract Audit Assistant</strong> &nbsp;·&nbsp;
    Track 5: AI DevTools &nbsp;·&nbsp; Mantle Turing Test Hackathon 2026<br>
    <span style="color:#6b7280">Static analysis engine · Fully local · No API required</span>
  </div>

</div>

<script>
function toggle(id) {{
  const el = document.getElementById(id);
  if (el) el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
}}
</script>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
