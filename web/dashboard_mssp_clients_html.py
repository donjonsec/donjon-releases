#!/usr/bin/env python3
"""
Donjon Platform - MSSP Clients Tab (HTML)
Managed tier: fetches client list for MSSP operations.
All CSS/JS inline for air-gap operation.
"""


def generate_mssp_clients_html() -> str:
    """Return the clients tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.mc-panel {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  margin-bottom: 20px;'
        '}'
        '.mc-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  margin-bottom: 12px;'
        '}'
        '.mc-stats {'
        '  display: grid;'
        '  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));'
        '  gap: 12px;'
        '  margin-bottom: 20px;'
        '}'
        '.mc-stat-card {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 16px;'
        '  text-align: center;'
        '}'
        '.mc-stat-val {'
        '  font-size: 1.8rem;'
        '  font-weight: 700;'
        '  font-family: var(--font-data);'
        '}'
        '.mc-stat-label {'
        '  font-size: 0.75rem;'
        '  color: var(--text-muted);'
        '  text-transform: uppercase;'
        '  margin-top: 4px;'
        '}'
        '.mc-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.mc-table th {'
        '  text-align: left;'
        '  padding: 8px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.mc-table td {'
        '  padding: 8px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
        '.mc-badge {'
        '  display: inline-block;'
        '  padding: 2px 8px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.mc-badge-active { background: rgba(34,197,94,0.15); color: #22c55e; }'
        '.mc-badge-inactive { background: rgba(239,68,68,0.15); color: #ef4444; }'
        '.mc-upgrade {'
        '  text-align: center;'
        '  padding: 60px 20px;'
        '  color: var(--text-muted);'
        '}'
        '.mc-upgrade-title {'
        '  font-size: 1.2rem;'
        '  font-weight: 700;'
        '  color: var(--text);'
        '  margin-bottom: 8px;'
        '}'
    )
    parts.append('</style>')

    parts.append(
        '<div id="mcContent">'
        '<div class="mc-stats" id="mcStats"></div>'
        '<div class="mc-panel">'
        '<div class="mc-title">Client Organizations</div>'
        '<table class="mc-table">'
        '<thead><tr><th>Client</th><th>Contact</th><th>Assets</th><th>Open Findings</th><th>Last Scan</th><th>Status</th></tr></thead>'
        '<tbody id="mcBody">'
        '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
        '</div>'
    )

    parts.append('<script>')
    parts.append('''(function(){
    document.addEventListener("tabload", function(e) {
        if (!e.detail || e.detail.tab !== "clients") return;

        var token = localStorage.getItem("donjon_token");
        var headers = {"Content-Type": "application/json"};
        if (token) headers["Authorization"] = "Bearer " + token;

        fetch("/api/v1/mssp/clients", {headers: headers}).then(function(r) {
            if (r.status === 403) throw {upgrade: true};
            if (!r.ok) throw new Error("API " + r.status);
            return r.json();
        }).then(function(data) {
            var clients = Array.isArray(data) ? data : (data.clients || []);
            var body = document.getElementById("mcBody");
            var statsEl = document.getElementById("mcStats");

            // Summary stats
            var total = clients.length;
            var active = clients.filter(function(c) { return (c.status || "active").toLowerCase() === "active"; }).length;
            var totalAssets = clients.reduce(function(s, c) { return s + (c.asset_count || c.assets || 0); }, 0);
            var totalFindings = clients.reduce(function(s, c) { return s + (c.open_findings || c.findings || 0); }, 0);

            statsEl.innerHTML =
                '<div class="mc-stat-card"><div class="mc-stat-val">' + total + '</div><div class="mc-stat-label">Total Clients</div></div>' +
                '<div class="mc-stat-card"><div class="mc-stat-val" style="color:var(--low);">' + active + '</div><div class="mc-stat-label">Active</div></div>' +
                '<div class="mc-stat-card"><div class="mc-stat-val">' + totalAssets + '</div><div class="mc-stat-label">Total Assets</div></div>' +
                '<div class="mc-stat-card"><div class="mc-stat-val" style="color:' + (totalFindings > 0 ? 'var(--high)' : 'var(--text)') + ';">' + totalFindings + '</div><div class="mc-stat-label">Open Findings</div></div>';

            if (clients.length === 0) {
                body.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">No clients configured.</td></tr>';
                return;
            }
            body.innerHTML = "";
            clients.forEach(function(c) {
                var tr = document.createElement("tr");
                var status = (c.status || "active").toLowerCase();
                var badgeClass = status === "active" ? "mc-badge-active" : "mc-badge-inactive";
                var lastScan = c.last_scan || c.last_scan_at || "-";
                if (lastScan !== "-" && lastScan.length > 10) lastScan = lastScan.substring(0, 10);
                tr.innerHTML =
                    '<td>' + (c.name || c.client_name || c.organization || "-") + '</td>' +
                    '<td>' + (c.contact || c.email || "-") + '</td>' +
                    '<td style="font-family:var(--font-data);">' + (c.asset_count || c.assets || 0) + '</td>' +
                    '<td style="font-family:var(--font-data);">' + (c.open_findings || c.findings || 0) + '</td>' +
                    '<td style="font-family:var(--font-data);font-size:0.8rem;color:var(--text-muted);">' + lastScan + '</td>' +
                    '<td><span class="mc-badge ' + badgeClass + '">' + status + '</span></td>';
                body.appendChild(tr);
            });
        }).catch(function(err) {
            if (err && err.upgrade) {
                document.getElementById("mcContent").innerHTML =
                    '<div class="mc-upgrade"><div class="mc-upgrade-title">Managed Feature</div>' +
                    'MSSP client management requires a Managed license.<br>' +
                    'Contact sales or upgrade your license to access this feature.</div>';
                return;
            }
            document.getElementById("mcBody").innerHTML =
                '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">Failed to load clients.</td></tr>';
        });
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
