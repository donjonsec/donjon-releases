#!/usr/bin/env python3
"""
Donjon Platform - MSSP Bulk Scans Tab (HTML)
Managed tier: fetches bulk scan jobs and status.
All CSS/JS inline for air-gap operation.
"""


def generate_mssp_bulk_html() -> str:
    """Return the bulk-scans tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.bs-panel {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  margin-bottom: 20px;'
        '}'
        '.bs-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  margin-bottom: 12px;'
        '}'
        '.bs-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.bs-table th {'
        '  text-align: left;'
        '  padding: 8px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.bs-table td {'
        '  padding: 8px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
        '.bs-status {'
        '  display: inline-block;'
        '  padding: 2px 8px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.bs-status-running { background: rgba(59,130,246,0.15); color: #3b82f6; }'
        '.bs-status-completed { background: rgba(34,197,94,0.15); color: #22c55e; }'
        '.bs-status-failed { background: rgba(239,68,68,0.15); color: #ef4444; }'
        '.bs-status-queued { background: rgba(234,179,8,0.15); color: #eab308; }'
        '.bs-status-default { background: rgba(107,114,128,0.15); color: #6B7280; }'
        '.bs-progress {'
        '  width: 100%;'
        '  height: 6px;'
        '  background: var(--border);'
        '  border-radius: 3px;'
        '  overflow: hidden;'
        '  min-width: 80px;'
        '}'
        '.bs-progress-bar {'
        '  height: 100%;'
        '  background: var(--accent);'
        '  border-radius: 3px;'
        '  transition: width 0.3s;'
        '}'
        '.bs-upgrade {'
        '  text-align: center;'
        '  padding: 60px 20px;'
        '  color: var(--text-muted);'
        '}'
        '.bs-upgrade-title {'
        '  font-size: 1.2rem;'
        '  font-weight: 700;'
        '  color: var(--text);'
        '  margin-bottom: 8px;'
        '}'
    )
    parts.append('</style>')

    parts.append(
        '<div id="bsContent">'
        '<div class="bs-panel">'
        '<div class="bs-title">Bulk Scan Jobs</div>'
        '<table class="bs-table">'
        '<thead><tr><th>Job ID</th><th>Clients</th><th>Scan Type</th><th>Progress</th><th>Findings</th><th>Status</th><th>Started</th></tr></thead>'
        '<tbody id="bsBody">'
        '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
        '</div>'
    )

    parts.append('<script>')
    parts.append('''(function(){
    function statusClass(s) {
        s = (s || "").toLowerCase();
        if (s === "running" || s === "in_progress") return "bs-status-running";
        if (s === "completed" || s === "done" || s === "success") return "bs-status-completed";
        if (s === "failed" || s === "error") return "bs-status-failed";
        if (s === "queued" || s === "pending") return "bs-status-queued";
        return "bs-status-default";
    }

    document.addEventListener("tabload", function(e) {
        if (!e.detail || e.detail.tab !== "bulk-scans") return;

        var token = localStorage.getItem("donjon_token");
        var headers = {"Content-Type": "application/json"};
        if (token) headers["Authorization"] = "Bearer " + token;

        fetch("/api/v1/mssp/bulk-scan", {headers: headers}).then(function(r) {
            if (r.status === 403) throw {upgrade: true};
            if (!r.ok) throw new Error("API " + r.status);
            return r.json();
        }).then(function(data) {
            var jobs = Array.isArray(data) ? data : (data.jobs || data.scans || []);
            var body = document.getElementById("bsBody");
            if (jobs.length === 0) {
                body.innerHTML = '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;">No bulk scan jobs found.</td></tr>';
                return;
            }
            body.innerHTML = "";
            jobs.forEach(function(j) {
                var tr = document.createElement("tr");
                var status = j.status || "queued";
                var pct = j.progress || j.percent_complete || 0;
                var clients = j.client_count || j.clients || 0;
                var started = j.started_at || j.created_at || "-";
                if (started !== "-" && started.length > 19) started = started.substring(0, 19).replace("T", " ");
                tr.innerHTML =
                    '<td style="font-family:var(--font-data);font-size:0.8rem;">' + (j.id || j.job_id || "-") + '</td>' +
                    '<td style="font-family:var(--font-data);">' + clients + '</td>' +
                    '<td>' + (j.scan_type || j.type || "Full") + '</td>' +
                    '<td><div class="bs-progress"><div class="bs-progress-bar" style="width:' + pct + '%;"></div></div>' +
                    '<span style="font-size:0.75rem;color:var(--text-muted);">' + pct + '%</span></td>' +
                    '<td style="font-family:var(--font-data);">' + (j.findings || j.finding_count || 0) + '</td>' +
                    '<td><span class="bs-status ' + statusClass(status) + '">' + status + '</span></td>' +
                    '<td style="font-family:var(--font-data);font-size:0.8rem;color:var(--text-muted);">' + started + '</td>';
                body.appendChild(tr);
            });
        }).catch(function(err) {
            if (err && err.upgrade) {
                document.getElementById("bsContent").innerHTML =
                    '<div class="bs-upgrade"><div class="bs-upgrade-title">Managed Feature</div>' +
                    'Bulk scanning requires a Managed license.<br>' +
                    'Contact sales or upgrade your license to access this feature.</div>';
                return;
            }
            document.getElementById("bsBody").innerHTML =
                '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;">Failed to load bulk scan jobs.</td></tr>';
        });
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
