#!/usr/bin/env python3
"""
Donjon Platform - MSSP Reports Tab (HTML)
Managed tier: fetches cross-client report rollups.
All CSS/JS inline for air-gap operation.
"""


def generate_mssp_reports_html() -> str:
    """Return the reports tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.mr-panel {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  margin-bottom: 20px;'
        '}'
        '.mr-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  margin-bottom: 12px;'
        '}'
        '.mr-summary {'
        '  display: grid;'
        '  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));'
        '  gap: 12px;'
        '  margin-bottom: 20px;'
        '}'
        '.mr-sum-card {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 16px;'
        '  text-align: center;'
        '}'
        '.mr-sum-val {'
        '  font-size: 1.8rem;'
        '  font-weight: 700;'
        '  font-family: var(--font-data);'
        '}'
        '.mr-sum-label {'
        '  font-size: 0.75rem;'
        '  color: var(--text-muted);'
        '  text-transform: uppercase;'
        '  margin-top: 4px;'
        '}'
        '.mr-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.mr-table th {'
        '  text-align: left;'
        '  padding: 8px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.mr-table td {'
        '  padding: 8px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
        '.mr-sev {'
        '  display: inline-block;'
        '  padding: 2px 8px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.mr-sev-critical { background: rgba(220,38,38,0.15); color: #dc2626; }'
        '.mr-sev-high { background: rgba(234,88,12,0.15); color: #ea580c; }'
        '.mr-sev-medium { background: rgba(234,179,8,0.15); color: #eab308; }'
        '.mr-sev-low { background: rgba(59,130,246,0.15); color: #3b82f6; }'
        '.mr-upgrade {'
        '  text-align: center;'
        '  padding: 60px 20px;'
        '  color: var(--text-muted);'
        '}'
        '.mr-upgrade-title {'
        '  font-size: 1.2rem;'
        '  font-weight: 700;'
        '  color: var(--text);'
        '  margin-bottom: 8px;'
        '}'
    )
    parts.append('</style>')

    parts.append(
        '<div id="mrContent">'
        '<div class="mr-summary" id="mrSummary"></div>'
        '<div class="mr-panel">'
        '<div class="mr-title">Cross-Client Report Rollup</div>'
        '<table class="mr-table">'
        '<thead><tr><th>Client</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th><th>Risk Score</th></tr></thead>'
        '<tbody id="mrBody">'
        '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
        '</div>'
    )

    parts.append('<script>')
    parts.append('''(function(){
    document.addEventListener("tabload", function(e) {
        if (!e.detail || e.detail.tab !== "reports") return;

        var token = localStorage.getItem("donjon_token");
        var headers = {"Content-Type": "application/json"};
        if (token) headers["Authorization"] = "Bearer " + token;

        fetch("/api/v1/mssp/reports/rollup", {headers: headers}).then(function(r) {
            if (r.status === 403) throw {upgrade: true};
            if (!r.ok) throw new Error("API " + r.status);
            return r.json();
        }).then(function(data) {
            var clients = data.clients || data.rollup || [];
            var summary = data.summary || data.totals || {};
            var summaryEl = document.getElementById("mrSummary");
            var body = document.getElementById("mrBody");

            // Summary cards
            var totalClients = clients.length || summary.client_count || 0;
            var totalCrit = summary.critical || 0;
            var totalHigh = summary.high || 0;
            var totalFindings = summary.total || summary.total_findings || 0;

            summaryEl.innerHTML =
                '<div class="mr-sum-card"><div class="mr-sum-val">' + totalClients + '</div><div class="mr-sum-label">Clients</div></div>' +
                '<div class="mr-sum-card"><div class="mr-sum-val" style="color:var(--critical);">' + totalCrit + '</div><div class="mr-sum-label">Critical</div></div>' +
                '<div class="mr-sum-card"><div class="mr-sum-val" style="color:var(--high);">' + totalHigh + '</div><div class="mr-sum-label">High</div></div>' +
                '<div class="mr-sum-card"><div class="mr-sum-val">' + totalFindings + '</div><div class="mr-sum-label">Total Findings</div></div>';

            if (clients.length === 0) {
                body.innerHTML = '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;">No report data available.</td></tr>';
                return;
            }
            body.innerHTML = "";
            clients.forEach(function(c) {
                var tr = document.createElement("tr");
                var crit = c.critical || 0;
                var high = c.high || 0;
                var med = c.medium || 0;
                var low = c.low || 0;
                var total = c.total || (crit + high + med + low);
                var risk = c.risk_score || c.score || "-";
                tr.innerHTML =
                    '<td>' + (c.name || c.client || "-") + '</td>' +
                    '<td><span class="mr-sev mr-sev-critical">' + crit + '</span></td>' +
                    '<td><span class="mr-sev mr-sev-high">' + high + '</span></td>' +
                    '<td><span class="mr-sev mr-sev-medium">' + med + '</span></td>' +
                    '<td><span class="mr-sev mr-sev-low">' + low + '</span></td>' +
                    '<td style="font-family:var(--font-data);font-weight:600;">' + total + '</td>' +
                    '<td style="font-family:var(--font-data);font-weight:600;">' + risk + '</td>';
                body.appendChild(tr);
            });
        }).catch(function(err) {
            if (err && err.upgrade) {
                document.getElementById("mrContent").innerHTML =
                    '<div class="mr-upgrade"><div class="mr-upgrade-title">Managed Feature</div>' +
                    'Cross-client reporting requires a Managed license.<br>' +
                    'Contact sales or upgrade your license to access this feature.</div>';
                return;
            }
            document.getElementById("mrBody").innerHTML =
                '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;">Failed to load report data.</td></tr>';
        });
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
