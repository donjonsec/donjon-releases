#!/usr/bin/env python3
"""
Donjon Platform - Audit Log Tab (HTML)
Enterprise tier: fetches audit trail entries.
All CSS/JS inline for air-gap operation.
"""


def generate_audit_html() -> str:
    """Return the audit-log tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.al-panel {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  margin-bottom: 20px;'
        '}'
        '.al-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  margin-bottom: 12px;'
        '}'
        '.al-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.al-table th {'
        '  text-align: left;'
        '  padding: 8px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.al-table td {'
        '  padding: 8px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
        '.al-action {'
        '  display: inline-block;'
        '  padding: 2px 8px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.al-action-create { background: rgba(34,197,94,0.15); color: #22c55e; }'
        '.al-action-update { background: rgba(59,130,246,0.15); color: #3b82f6; }'
        '.al-action-delete { background: rgba(239,68,68,0.15); color: #ef4444; }'
        '.al-action-login { background: rgba(99,102,241,0.15); color: var(--accent); }'
        '.al-action-default { background: rgba(107,114,128,0.15); color: #6B7280; }'
        '.al-ts { font-family: var(--font-data); font-size: 0.8rem; color: var(--text-muted); }'
        '.al-upgrade {'
        '  text-align: center;'
        '  padding: 60px 20px;'
        '  color: var(--text-muted);'
        '}'
        '.al-upgrade-title {'
        '  font-size: 1.2rem;'
        '  font-weight: 700;'
        '  color: var(--text);'
        '  margin-bottom: 8px;'
        '}'
    )
    parts.append('</style>')

    parts.append(
        '<div id="alContent">'
        '<div class="al-panel">'
        '<div class="al-title">Audit Trail</div>'
        '<table class="al-table">'
        '<thead><tr><th>Timestamp</th><th>User</th><th>Action</th><th>Resource</th><th>Details</th><th>IP</th></tr></thead>'
        '<tbody id="alBody">'
        '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
        '</div>'
    )

    parts.append('<script>')
    parts.append('''(function(){
    function actionClass(action) {
        var a = (action || "").toLowerCase();
        if (a.indexOf("create") >= 0 || a.indexOf("add") >= 0) return "al-action-create";
        if (a.indexOf("update") >= 0 || a.indexOf("edit") >= 0 || a.indexOf("modify") >= 0) return "al-action-update";
        if (a.indexOf("delete") >= 0 || a.indexOf("remove") >= 0) return "al-action-delete";
        if (a.indexOf("login") >= 0 || a.indexOf("auth") >= 0) return "al-action-login";
        return "al-action-default";
    }

    document.addEventListener("tabload", function(e) {
        if (!e.detail || e.detail.tab !== "audit-log") return;

        var token = localStorage.getItem("donjon_token");
        var headers = {"Content-Type": "application/json"};
        if (token) headers["Authorization"] = "Bearer " + token;

        fetch("/api/v1/audit", {headers: headers}).then(function(r) {
            if (r.status === 403) throw {upgrade: true};
            if (!r.ok) throw new Error("API " + r.status);
            return r.json();
        }).then(function(data) {
            var entries = Array.isArray(data) ? data : (data.entries || data.events || data.audit || []);
            var body = document.getElementById("alBody");
            if (entries.length === 0) {
                body.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">No audit entries recorded.</td></tr>';
                return;
            }
            body.innerHTML = "";
            entries.forEach(function(entry) {
                var tr = document.createElement("tr");
                var ts = entry.timestamp || entry.created_at || entry.time || "-";
                if (ts !== "-" && ts.length > 19) ts = ts.substring(0, 19).replace("T", " ");
                var action = entry.action || entry.event || entry.type || "-";
                var cls = actionClass(action);
                tr.innerHTML =
                    '<td class="al-ts">' + ts + '</td>' +
                    '<td>' + (entry.user || entry.username || entry.actor || "-") + '</td>' +
                    '<td><span class="al-action ' + cls + '">' + action + '</span></td>' +
                    '<td>' + (entry.resource || entry.target || entry.object || "-") + '</td>' +
                    '<td>' + (entry.details || entry.description || entry.message || "-").substring(0, 60) + '</td>' +
                    '<td class="al-ts">' + (entry.ip || entry.ip_address || entry.source_ip || "-") + '</td>';
                body.appendChild(tr);
            });
        }).catch(function(err) {
            if (err && err.upgrade) {
                document.getElementById("alContent").innerHTML =
                    '<div class="al-upgrade"><div class="al-upgrade-title">Enterprise Feature</div>' +
                    'Audit logging requires an Enterprise or Managed license.<br>' +
                    'Contact sales or upgrade your license to access this feature.</div>';
                return;
            }
            document.getElementById("alBody").innerHTML =
                '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">Failed to load audit log.</td></tr>';
        });
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
