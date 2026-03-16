#!/usr/bin/env python3
"""
Donjon Platform - Interactive Report Generator
Generates a self-contained HTML report with all data baked in.
Can be saved as a standalone .html file and opened in any browser.
"""

import json
import hashlib
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List

try:
    from .evidence import get_evidence_manager
    from .paths import paths
except ImportError:
    from evidence import get_evidence_manager
    from paths import paths


def _build_evidence_chain(findings: List[Dict]) -> List[Dict]:
    """Build SHA-256 evidence chain from findings."""
    chain = []
    prev_hash = "0" * 64
    for f in findings:
        payload = json.dumps({
            "finding_id": f.get("finding_id", ""), "title": f.get("title", ""),
            "severity": f.get("severity", ""), "affected_asset": f.get("affected_asset", ""),
            "prev_hash": prev_hash,
        }, sort_keys=True)
        current_hash = hashlib.sha256(payload.encode()).hexdigest()
        chain.append({"finding_id": f.get("finding_id", ""), "title": f.get("title", ""),
                       "hash": current_hash, "prev_hash": prev_hash})
        prev_hash = current_hash
    return chain


def _collect_data(session_id: str) -> Dict:
    """Collect all report data from evidence manager."""
    em = get_evidence_manager()
    summary = em.get_session_summary(session_id)
    findings = em.get_findings_for_session(session_id)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
    compliance = {}
    for f in findings:
        eid = f.get("evidence_id")
        if not eid:
            continue
        with sqlite3.connect(em.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM control_mappings WHERE evidence_id = ?", (eid,)
            ).fetchall()
            for row in rows:
                fw = row["framework"]
                if fw not in compliance:
                    compliance[fw] = []
                compliance[fw].append({
                    "control_id": row["control_id"],
                    "control_name": row["control_name"] or "",
                    "control_family": row["control_family"] or "",
                    "finding_title": f.get("title", ""),
                })
    return {
        "session_id": session_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session": summary.get("session", {}),
        "findings": findings, "severity_counts": severity_counts,
        "compliance": compliance,
        "evidence_chain": _build_evidence_chain(findings),
        "total_findings": len(findings),
        "evidence_count": summary.get("evidence_count", 0),
    }


def _css() -> str:
    """Complete CSS for dark/light themes."""
    return (
        "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n"
        ":root{--bg:#111827;--surface:#1F2937;--surface-alt:#283548;--text:#F9FAFB;"
        "--text-muted:#9CA3AF;--accent:#6366F1;--accent-hover:#818CF8;--border:#374151;"
        "--radius:8px;--critical:#EF4444;--high:#F97316;--medium:#EAB308;--low:#22C55E;"
        "--info:#3B82F6;--font-ui:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"
        "--font-data:'Consolas','Courier New',monospace;--shadow:0 2px 12px rgba(0,0,0,0.4)}\n"
        "[data-theme='light']{--bg:#F3F4F6;--surface:#FFFFFF;--surface-alt:#E5E7EB;"
        "--text:#111827;--text-muted:#6B7280;--accent:#4F46E5;--accent-hover:#6366F1;"
        "--border:#D1D5DB;--critical:#DC2626;--high:#EA580C;--medium:#CA8A04;"
        "--low:#16A34A;--info:#2563EB;--shadow:0 2px 12px rgba(0,0,0,0.1)}\n"
        "html{font-size:14px}"
        "body{font-family:var(--font-ui);background:var(--bg);color:var(--text);line-height:1.6}\n"
        ".report{max-width:1100px;margin:0 auto;padding:32px 24px}\n"
        ".report-header{background:var(--surface);border:1px solid var(--border);"
        "border-radius:var(--radius);padding:28px 32px;margin-bottom:24px}\n"
        ".report-header h1{font-size:1.6rem;margin-bottom:4px}\n"
        ".report-header .meta{font-size:0.82rem;color:var(--text-muted)}\n"
        ".report-header .meta span{margin-right:20px}\n"
        ".theme-toggle{position:fixed;top:16px;right:16px;z-index:100;padding:8px 16px;"
        "background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);"
        "color:var(--text);cursor:pointer;font-size:0.82rem;font-family:var(--font-ui)}\n"
        ".theme-toggle:hover{border-color:var(--accent)}\n"
        ".section{background:var(--surface);border:1px solid var(--border);"
        "border-radius:var(--radius);padding:24px 28px;margin-bottom:20px}\n"
        ".section h2{font-size:1.2rem;margin-bottom:16px;padding-bottom:10px;"
        "border-bottom:2px solid var(--accent)}\n"
        ".exec-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));"
        "gap:14px;margin-bottom:16px}\n"
        ".exec-stat{background:var(--surface-alt);border-radius:var(--radius);"
        "padding:14px 16px;text-align:center}\n"
        ".exec-stat .val{font-size:1.8rem;font-weight:700;font-family:var(--font-data)}\n"
        ".exec-stat .lbl{font-size:0.75rem;color:var(--text-muted);"
        "text-transform:uppercase;letter-spacing:0.04em;margin-top:2px}\n"
        ".filter-bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}\n"
        ".filter-btn{padding:6px 14px;border:1px solid var(--border);border-radius:var(--radius);"
        "background:var(--surface-alt);color:var(--text);cursor:pointer;"
        "font-size:0.82rem;font-family:var(--font-ui)}\n"
        ".filter-btn:hover{border-color:var(--accent)}\n"
        ".filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}\n"
        ".findings-table{width:100%;border-collapse:collapse;font-size:0.85rem}\n"
        ".findings-table th{text-align:left;padding:10px 12px;border-bottom:2px solid var(--border);"
        "color:var(--text-muted);font-size:0.75rem;text-transform:uppercase;letter-spacing:0.04em}\n"
        ".findings-table td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}\n"
        ".findings-table tr:hover{background:var(--surface-alt)}\n"
        ".sev-badge{display:inline-block;padding:2px 8px;border-radius:4px;"
        "font-size:0.72rem;font-weight:600;text-transform:uppercase}\n"
        ".sev-CRITICAL{background:rgba(239,68,68,0.15);color:var(--critical)}\n"
        ".sev-HIGH{background:rgba(249,115,22,0.15);color:var(--high)}\n"
        ".sev-MEDIUM{background:rgba(234,179,8,0.15);color:var(--medium)}\n"
        ".sev-LOW{background:rgba(34,197,94,0.15);color:var(--low)}\n"
        ".sev-INFO{background:rgba(59,130,246,0.15);color:var(--info)}\n"
        ".finding-hidden{display:none}\n"
        ".accordion-item{border:1px solid var(--border);border-radius:var(--radius);"
        "margin-bottom:8px;overflow:hidden}\n"
        ".accordion-header{padding:12px 16px;background:var(--surface-alt);cursor:pointer;"
        "font-weight:600;font-size:0.9rem;display:flex;justify-content:space-between;align-items:center}\n"
        ".accordion-header:hover{background:var(--border)}\n"
        ".accordion-header .arrow{transition:transform 0.2s}\n"
        ".accordion-item.open .arrow{transform:rotate(90deg)}\n"
        ".accordion-body{padding:0 16px;max-height:0;overflow:hidden;"
        "transition:max-height 0.3s,padding 0.3s}\n"
        ".accordion-item.open .accordion-body{max-height:2000px;padding:16px}\n"
        ".control-list{list-style:none}\n"
        ".control-list li{padding:6px 0;border-bottom:1px solid var(--border);font-size:0.85rem}\n"
        ".control-list li:last-child{border-bottom:none}\n"
        ".control-id{font-family:var(--font-data);font-weight:600;color:var(--accent)}\n"
        ".risk-bar-container{display:flex;height:28px;border-radius:var(--radius);"
        "overflow:hidden;margin-bottom:12px}\n"
        ".risk-segment{display:flex;align-items:center;justify-content:center;"
        "font-size:0.72rem;font-weight:600;color:#fff;min-width:30px}\n"
        ".checklist{list-style:none}\n"
        ".checklist li{padding:8px 0;border-bottom:1px solid var(--border);"
        "font-size:0.85rem;display:flex;align-items:flex-start;gap:10px}\n"
        ".checklist li:last-child{border-bottom:none}\n"
        ".check-box{width:18px;height:18px;border:2px solid var(--border);"
        "border-radius:3px;flex-shrink:0;cursor:pointer;margin-top:1px}\n"
        ".check-box.checked{background:var(--accent);border-color:var(--accent)}\n"
        ".chain-table{width:100%;border-collapse:collapse;font-family:var(--font-data);font-size:0.78rem}\n"
        ".chain-table th{text-align:left;padding:8px;border-bottom:2px solid var(--border);"
        "color:var(--text-muted);font-size:0.72rem;text-transform:uppercase}\n"
        ".chain-table td{padding:8px;border-bottom:1px solid var(--border);word-break:break-all}\n"
        "@media print{.theme-toggle,.filter-bar{display:none}"
        "body{background:#fff;color:#111}.section{break-inside:avoid;border:1px solid #ddd}}\n"
        ".skip-link{position:absolute;top:-40px;left:0;padding:8px 16px;"
        "background:var(--accent);color:#fff;z-index:200}\n"
        ".skip-link:focus{top:0}\n"
    )


def _js() -> str:
    """Inline JavaScript for interactivity."""
    return (
        "function toggleTheme(){var h=document.documentElement,"
        "c=h.getAttribute('data-theme')||'dark',n=c==='dark'?'light':'dark';"
        "h.setAttribute('data-theme',n);"
        "document.getElementById('themeBtn').textContent="
        "n==='dark'?'Switch to Light':'Switch to Dark'}\n"
        "var activeFilter='ALL';\n"
        "function filterFindings(s){activeFilter=s;"
        "var b=document.querySelectorAll('.filter-btn');"
        "for(var i=0;i<b.length;i++)b[i].classList.toggle('active',b[i].getAttribute('data-sev')===s);"
        "var r=document.querySelectorAll('.finding-row');"
        "for(var j=0;j<r.length;j++){if(s==='ALL'||r[j].getAttribute('data-sev')===s)"
        "{r[j].classList.remove('finding-hidden')}else{r[j].classList.add('finding-hidden')}}"
        "var v=document.querySelectorAll('.finding-row:not(.finding-hidden)');"
        "document.getElementById('visibleCount').textContent=v.length+' of '+r.length+' findings'}\n"
        "function toggleAccordion(el){el.parentElement.classList.toggle('open')}\n"
        "function toggleCheck(el){el.classList.toggle('checked');"
        "el.setAttribute('aria-checked',el.classList.contains('checked'))}\n"
        "document.addEventListener('DOMContentLoaded',function(){filterFindings('ALL')});\n"
    )


def _esc(text) -> str:
    """Escape HTML entities."""
    return (str(text or "").replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _build_exec_summary(data: Dict) -> str:
    """Build executive summary section."""
    sc = data["severity_counts"]
    session = data.get("session", {})
    html = '<div class="section" id="executive-summary">\n<h2>Executive Summary</h2>\n'
    html += '<div class="exec-stats">\n'
    for val, label, color in [
        (str(data["total_findings"]), "Total Findings", "var(--text)"),
        (str(sc["CRITICAL"]), "Critical", "var(--critical)"),
        (str(sc["HIGH"]), "High", "var(--high)"),
        (str(sc["MEDIUM"]), "Medium", "var(--medium)"),
        (str(sc["LOW"]), "Low", "var(--low)"),
        (str(sc["INFO"]), "Info", "var(--info)"),
    ]:
        html += '<div class="exec-stat"><div class="val" style="color:' + color + '">'
        html += val + '</div><div class="lbl">' + label + '</div></div>\n'
    html += '</div>\n'
    html += '<p style="font-size:0.85rem;color:var(--text-muted);margin-top:12px">'
    html += '<strong>Session:</strong> ' + _esc(data["session_id"])
    html += ' &bull; <strong>Type:</strong> ' + _esc(session.get("scan_type", "N/A"))
    html += ' &bull; <strong>Targets:</strong> ' + _esc(session.get("target_networks", "N/A"))
    html += ' &bull; <strong>Start:</strong> ' + _esc(session.get("start_time", "N/A"))
    html += ' &bull; <strong>End:</strong> ' + _esc(session.get("end_time", "N/A"))
    html += '</p>\n</div>\n'
    return html


def _build_findings_table(findings: List[Dict]) -> str:
    """Build findings table with severity filter buttons."""
    html = '<div class="section" id="findings">\n<h2>Findings</h2>\n'
    html += '<div class="filter-bar" role="toolbar" aria-label="Filter findings by severity">\n'
    for sev in ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        active = " active" if sev == "ALL" else ""
        html += '<button class="filter-btn' + active + '" data-sev="' + sev + '"'
        html += ' onclick="filterFindings(\'' + sev + '\')">' + sev + '</button>\n'
    html += '</div>\n'
    html += '<p id="visibleCount" style="font-size:0.78rem;color:var(--text-muted);margin-bottom:10px">'
    html += str(len(findings)) + ' of ' + str(len(findings)) + ' findings</p>\n'
    html += '<div style="overflow-x:auto"><table class="findings-table" role="table">\n'
    html += '<thead><tr><th scope="col">Severity</th><th scope="col">Title</th>'
    html += '<th scope="col">Asset</th><th scope="col">CVSS</th>'
    html += '<th scope="col">CVEs</th><th scope="col">Status</th></tr></thead>\n<tbody>\n'
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        cves_raw = f.get("cve_ids", "[]")
        if isinstance(cves_raw, str):
            try:
                cves = json.loads(cves_raw)
            except (json.JSONDecodeError, TypeError):
                cves = []
        else:
            cves = cves_raw or []
        cve_str = ", ".join(cves) if cves else "-"
        html += '<tr class="finding-row" data-sev="' + sev + '">'
        html += '<td><span class="sev-badge sev-' + sev + '">' + sev + '</span></td>'
        html += '<td>' + _esc(f.get("title", "")) + '</td>'
        html += '<td style="font-family:var(--font-data)">' + _esc(f.get("affected_asset", "-")) + '</td>'
        html += '<td style="font-family:var(--font-data)">' + str(f.get("cvss_score") or 0) + '</td>'
        html += '<td style="font-family:var(--font-data);font-size:0.78rem">' + _esc(cve_str) + '</td>'
        html += '<td>' + _esc(f.get("status", "open")) + '</td></tr>\n'
    html += '</tbody></table></div>\n</div>\n'
    return html


def _build_compliance(compliance: Dict) -> str:
    """Build compliance mapping accordion."""
    html = '<div class="section" id="compliance">\n<h2>Compliance Mapping</h2>\n'
    if not compliance:
        html += '<p style="color:var(--text-muted)">No compliance mappings for this session.</p>\n</div>\n'
        return html
    for framework, controls in sorted(compliance.items()):
        html += '<div class="accordion-item">\n'
        html += '<div class="accordion-header" onclick="toggleAccordion(this)"'
        html += ' role="button" tabindex="0" aria-expanded="false"'
        html += ' onkeydown="if(event.key===\'Enter\')toggleAccordion(this)">'
        html += '<span>' + _esc(framework) + ' (' + str(len(controls)) + ' controls)</span>'
        html += '<span class="arrow">&#9654;</span></div>\n'
        html += '<div class="accordion-body"><ul class="control-list">\n'
        for c in controls:
            html += '<li><span class="control-id">' + _esc(c["control_id"]) + '</span>'
            if c.get("control_name"):
                html += ' &mdash; ' + _esc(c["control_name"])
            if c.get("finding_title"):
                html += ' <span style="color:var(--text-muted);font-size:0.78rem">'
                html += '(Finding: ' + _esc(c["finding_title"]) + ')</span>'
            html += '</li>\n'
        html += '</ul></div>\n</div>\n'
    html += '</div>\n'
    return html


def _build_risk_summary(data: Dict) -> str:
    """Build visual risk summary with stacked bar."""
    sc = data["severity_counts"]
    total = max(data["total_findings"], 1)
    html = '<div class="section" id="risk-summary">\n<h2>Risk Summary</h2>\n'
    html += '<div class="risk-bar-container">\n'
    for sev, var in [("CRITICAL", "--critical"), ("HIGH", "--high"),
                     ("MEDIUM", "--medium"), ("LOW", "--low"), ("INFO", "--info")]:
        count = sc.get(sev, 0)
        if count == 0:
            continue
        pct = max(count / total * 100, 5)
        html += '<div class="risk-segment" style="width:' + str(round(pct, 1))
        html += '%;background:var(' + var + ')">' + str(count) + '</div>\n'
    html += '</div>\n'
    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    score = sum(sc.get(s, 0) * w for s, w in weights.items())
    max_possible = total * 10
    html += '<p style="font-size:0.9rem;margin-top:8px"><strong>Weighted Risk Score:</strong> '
    html += '<span style="font-family:var(--font-data);font-size:1.1rem;font-weight:700">'
    html += str(score) + '</span> / ' + str(max_possible)
    html += ' (' + str(round(score / max(max_possible, 1) * 100)) + '%)</p>\n</div>\n'
    return html


def _build_remediation(findings: List[Dict]) -> str:
    """Build remediation checklist."""
    items = [f for f in findings if f.get("remediation")]
    html = '<div class="section" id="remediation">\n<h2>Remediation Checklist</h2>\n'
    if not items:
        html += '<p style="color:var(--text-muted)">No remediation actions recorded.</p>\n</div>\n'
        return html
    html += '<ul class="checklist">\n'
    for f in items:
        sev = (f.get("severity") or "INFO").upper()
        html += '<li><div class="check-box" onclick="toggleCheck(this)"'
        html += ' role="checkbox" aria-checked="false" tabindex="0"'
        html += ' onkeydown="if(event.key===\'Enter\'||event.key===\' \')toggleCheck(this)"'
        html += '></div><div><span class="sev-badge sev-' + sev + '">' + sev + '</span> '
        html += '<strong>' + _esc(f.get("title", "")) + '</strong><br>'
        html += '<span style="color:var(--text-muted);font-size:0.82rem">'
        html += _esc(f["remediation"]) + '</span></div></li>\n'
    html += '</ul>\n</div>\n'
    return html


def _build_chain_section(chain: List[Dict]) -> str:
    """Build SHA-256 evidence chain table."""
    html = '<div class="section" id="evidence-chain">\n<h2>SHA-256 Evidence Chain</h2>\n'
    html += '<p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:12px">'
    html += 'Each finding is cryptographically chained. Tampering invalidates subsequent hashes.</p>\n'
    if not chain:
        html += '<p style="color:var(--text-muted)">No evidence chain entries.</p>\n</div>\n'
        return html
    html += '<div style="overflow-x:auto"><table class="chain-table" role="table">\n'
    html += '<thead><tr><th scope="col">#</th><th scope="col">Finding ID</th>'
    html += '<th scope="col">Title</th><th scope="col">SHA-256 Hash</th></tr></thead>\n<tbody>\n'
    for idx, entry in enumerate(chain, 1):
        html += '<tr><td>' + str(idx) + '</td>'
        html += '<td>' + _esc(entry["finding_id"]) + '</td>'
        html += '<td style="font-family:var(--font-ui)">' + _esc(entry["title"]) + '</td>'
        html += '<td style="font-size:0.7rem">' + _esc(entry["hash"]) + '</td></tr>\n'
    html += '</tbody></table></div>\n</div>\n'
    return html


def generate(session_id: str) -> str:
    """
    Generate a self-contained interactive HTML report for the given session.

    All data is baked inline -- no fetch calls, no external resources.
    Writes to data/results/{session_id}/report.html and returns the HTML string.
    """
    data = _collect_data(session_id)
    css = _css()
    js = _js()

    body = '<a class="skip-link" href="#executive-summary">Skip to report</a>\n'
    body += '<button class="theme-toggle" id="themeBtn" onclick="toggleTheme()"'
    body += ' aria-label="Toggle dark/light theme">Switch to Light</button>\n'
    body += '<div class="report">\n'
    body += '<div class="report-header">\n'
    body += '<h1>Donjon Platform &mdash; Security Assessment Report</h1>\n'
    body += '<div class="meta">'
    body += '<span><strong>Session:</strong> ' + _esc(data["session_id"]) + '</span>'
    body += '<span><strong>Generated:</strong> ' + _esc(data["generated_at"]) + '</span>'
    body += '<span><strong>Findings:</strong> ' + str(data["total_findings"]) + '</span>'
    body += '<span><strong>Evidence:</strong> ' + str(data["evidence_count"]) + '</span>'
    body += '</div>\n</div>\n'
    body += _build_exec_summary(data)
    body += _build_findings_table(data["findings"])
    body += _build_compliance(data["compliance"])
    body += _build_risk_summary(data)
    body += _build_remediation(data["findings"])
    body += _build_chain_section(data["evidence_chain"])
    body += '<div style="text-align:center;padding:24px;font-size:0.78rem;color:var(--text-muted)">'
    body += 'Generated by Donjon Platform &bull; ' + _esc(data["generated_at"])
    body += ' &bull; Session ' + _esc(data["session_id"]) + '</div>\n</div>\n'

    html = ('<!DOCTYPE html>\n<html lang="en" data-theme="dark">\n<head>\n'
            '<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            '<title>Donjon Report - ' + _esc(session_id) + '</title>\n'
            '<style>\n' + css + '</style>\n</head>\n<body>\n'
            + body
            + '<script>\n' + js + '</script>\n</body>\n</html>')

    output_dir = paths.results / session_id
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.html").write_text(html, encoding="utf-8")
    return html
