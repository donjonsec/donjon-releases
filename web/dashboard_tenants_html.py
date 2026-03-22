#!/usr/bin/env python3
"""
Donjon Platform - Tenants Tab (HTML)
Enterprise tier: fetches tenant list and shows multi-tenancy status.
All CSS/JS inline for air-gap operation.
"""


def generate_tenants_html() -> str:
    """Return the tenants tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.tn-panel {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  margin-bottom: 20px;'
        '}'
        '.tn-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  margin-bottom: 12px;'
        '}'
        '.tn-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.tn-table th {'
        '  text-align: left;'
        '  padding: 8px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.tn-table td {'
        '  padding: 8px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
        '.tn-badge {'
        '  display: inline-block;'
        '  padding: 2px 8px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.tn-badge-active { background: rgba(34,197,94,0.15); color: #22c55e; }'
        '.tn-badge-suspended { background: rgba(234,179,8,0.15); color: #eab308; }'
        '.tn-badge-inactive { background: rgba(239,68,68,0.15); color: #ef4444; }'
        '.tn-stat {'
        '  font-family: var(--font-data);'
        '  font-weight: 600;'
        '}'
        '.tn-upgrade {'
        '  text-align: center;'
        '  padding: 60px 20px;'
        '  color: var(--text-muted);'
        '}'
        '.tn-upgrade-title {'
        '  font-size: 1.2rem;'
        '  font-weight: 700;'
        '  color: var(--text);'
        '  margin-bottom: 8px;'
        '}'
    )
    parts.append('</style>')

    parts.append(
        '<div id="tnContent">'
        '<div class="tn-panel">'
        '<div class="tn-title">Tenants</div>'
        '<table class="tn-table">'
        '<thead><tr><th>Tenant</th><th>Slug</th><th>Users</th><th>Assets</th><th>Status</th><th>Created</th></tr></thead>'
        '<tbody id="tnBody">'
        '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
        '</div>'
    )

    parts.append('<script>')
    parts.append('''(function(){
    document.addEventListener("tabload", function(e) {
        if (!e.detail || e.detail.tab !== "tenants") return;

        var token = localStorage.getItem("donjon_token");
        var headers = {"Content-Type": "application/json"};
        if (token) headers["Authorization"] = "Bearer " + token;

        fetch("/api/v1/tenants", {headers: headers}).then(function(r) {
            if (r.status === 403) throw {upgrade: true};
            if (!r.ok) throw new Error("API " + r.status);
            return r.json();
        }).then(function(data) {
            var tenants = Array.isArray(data) ? data : (data.tenants || []);
            var body = document.getElementById("tnBody");
            if (tenants.length === 0) {
                body.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">No tenants configured.</td></tr>';
                return;
            }
            body.innerHTML = "";
            tenants.forEach(function(t) {
                var tr = document.createElement("tr");
                var status = (t.status || "active").toLowerCase();
                var badgeClass = status === "active" ? "tn-badge-active" :
                    status === "suspended" ? "tn-badge-suspended" : "tn-badge-inactive";
                var created = t.created_at || t.created || "-";
                if (created !== "-") created = created.substring(0, 10);
                tr.innerHTML =
                    '<td>' + (t.name || t.tenant_name || "-") + '</td>' +
                    '<td><code>' + (t.slug || t.id || "-") + '</code></td>' +
                    '<td class="tn-stat">' + (t.user_count || t.users || 0) + '</td>' +
                    '<td class="tn-stat">' + (t.asset_count || t.assets || 0) + '</td>' +
                    '<td><span class="tn-badge ' + badgeClass + '">' + status + '</span></td>' +
                    '<td>' + created + '</td>';
                body.appendChild(tr);
            });
        }).catch(function(err) {
            if (err && err.upgrade) {
                document.getElementById("tnContent").innerHTML =
                    '<div class="tn-upgrade"><div class="tn-upgrade-title">Enterprise Feature</div>' +
                    'Multi-tenancy requires an Enterprise or Managed license.<br>' +
                    'Contact sales or upgrade your license to access this feature.</div>';
                return;
            }
            document.getElementById("tnBody").innerHTML =
                '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">Failed to load tenants.</td></tr>';
        });
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
