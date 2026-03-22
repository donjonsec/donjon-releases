#!/usr/bin/env python3
"""
Donjon Platform - MSSP Metering Tab (HTML)
Managed tier: fetches usage/metering data for billing.
All CSS/JS inline for air-gap operation.
"""


def generate_mssp_metering_html() -> str:
    """Return the metering tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.mt-panel {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  margin-bottom: 20px;'
        '}'
        '.mt-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  margin-bottom: 12px;'
        '}'
        '.mt-summary {'
        '  display: grid;'
        '  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));'
        '  gap: 12px;'
        '  margin-bottom: 20px;'
        '}'
        '.mt-sum-card {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 16px;'
        '  text-align: center;'
        '}'
        '.mt-sum-val {'
        '  font-size: 1.8rem;'
        '  font-weight: 700;'
        '  font-family: var(--font-data);'
        '}'
        '.mt-sum-label {'
        '  font-size: 0.75rem;'
        '  color: var(--text-muted);'
        '  text-transform: uppercase;'
        '  margin-top: 4px;'
        '}'
        '.mt-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.mt-table th {'
        '  text-align: left;'
        '  padding: 8px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.mt-table td {'
        '  padding: 8px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
        '.mt-bar {'
        '  width: 100%;'
        '  height: 8px;'
        '  background: var(--border);'
        '  border-radius: 4px;'
        '  overflow: hidden;'
        '  min-width: 100px;'
        '}'
        '.mt-bar-fill {'
        '  height: 100%;'
        '  border-radius: 4px;'
        '  transition: width 0.3s;'
        '}'
        '.mt-bar-ok { background: var(--accent); }'
        '.mt-bar-warn { background: var(--medium); }'
        '.mt-bar-over { background: var(--critical); }'
        '.mt-upgrade {'
        '  text-align: center;'
        '  padding: 60px 20px;'
        '  color: var(--text-muted);'
        '}'
        '.mt-upgrade-title {'
        '  font-size: 1.2rem;'
        '  font-weight: 700;'
        '  color: var(--text);'
        '  margin-bottom: 8px;'
        '}'
    )
    parts.append('</style>')

    parts.append(
        '<div id="mtContent">'
        '<div class="mt-summary" id="mtSummary"></div>'
        '<div class="mt-panel">'
        '<div class="mt-title">Usage by Client</div>'
        '<table class="mt-table">'
        '<thead><tr><th>Client</th><th>Scans</th><th>Assets</th><th>API Calls</th><th>Storage</th><th>Usage</th></tr></thead>'
        '<tbody id="mtBody">'
        '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
        '</div>'
    )

    parts.append('<script>')
    parts.append('''(function(){
    function barClass(pct) {
        if (pct >= 90) return "mt-bar-over";
        if (pct >= 70) return "mt-bar-warn";
        return "mt-bar-ok";
    }

    function fmtStorage(bytes) {
        if (!bytes && bytes !== 0) return "-";
        if (typeof bytes === "string") return bytes;
        if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + " GB";
        if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + " MB";
        if (bytes >= 1024) return (bytes / 1024).toFixed(1) + " KB";
        return bytes + " B";
    }

    document.addEventListener("tabload", function(e) {
        if (!e.detail || e.detail.tab !== "metering") return;

        var token = localStorage.getItem("donjon_token");
        var headers = {"Content-Type": "application/json"};
        if (token) headers["Authorization"] = "Bearer " + token;

        fetch("/api/v1/mssp/usage", {headers: headers}).then(function(r) {
            if (r.status === 403) throw {upgrade: true};
            if (!r.ok) throw new Error("API " + r.status);
            return r.json();
        }).then(function(data) {
            var clients = data.clients || data.usage || [];
            var totals = data.totals || data.summary || {};
            var period = data.period || data.billing_period || "Current Period";
            var summaryEl = document.getElementById("mtSummary");
            var body = document.getElementById("mtBody");

            var totalScans = totals.scans || totals.total_scans || 0;
            var totalAssets = totals.assets || totals.total_assets || 0;
            var totalApi = totals.api_calls || totals.total_api_calls || 0;
            var totalStorage = totals.storage || totals.total_storage || 0;

            summaryEl.innerHTML =
                '<div class="mt-sum-card"><div class="mt-sum-val">' + totalScans + '</div><div class="mt-sum-label">Total Scans</div></div>' +
                '<div class="mt-sum-card"><div class="mt-sum-val">' + totalAssets + '</div><div class="mt-sum-label">Total Assets</div></div>' +
                '<div class="mt-sum-card"><div class="mt-sum-val">' + totalApi.toLocaleString() + '</div><div class="mt-sum-label">API Calls</div></div>' +
                '<div class="mt-sum-card"><div class="mt-sum-val">' + fmtStorage(totalStorage) + '</div><div class="mt-sum-label">Storage Used</div></div>';

            if (clients.length === 0) {
                body.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">No usage data for this period.</td></tr>';
                return;
            }
            body.innerHTML = "";
            clients.forEach(function(c) {
                var tr = document.createElement("tr");
                var pct = c.usage_pct || c.percent || 0;
                var cls = barClass(pct);
                tr.innerHTML =
                    '<td>' + (c.name || c.client || "-") + '</td>' +
                    '<td style="font-family:var(--font-data);">' + (c.scans || 0) + '</td>' +
                    '<td style="font-family:var(--font-data);">' + (c.assets || 0) + '</td>' +
                    '<td style="font-family:var(--font-data);">' + (c.api_calls || 0) + '</td>' +
                    '<td style="font-family:var(--font-data);font-size:0.8rem;">' + fmtStorage(c.storage || 0) + '</td>' +
                    '<td><div class="mt-bar"><div class="mt-bar-fill ' + cls + '" style="width:' + Math.min(pct, 100) + '%;"></div></div>' +
                    '<span style="font-size:0.75rem;color:var(--text-muted);">' + pct + '%</span></td>';
                body.appendChild(tr);
            });
        }).catch(function(err) {
            if (err && err.upgrade) {
                document.getElementById("mtContent").innerHTML =
                    '<div class="mt-upgrade"><div class="mt-upgrade-title">Managed Feature</div>' +
                    'Usage metering requires a Managed license.<br>' +
                    'Contact sales or upgrade your license to access this feature.</div>';
                return;
            }
            document.getElementById("mtBody").innerHTML =
                '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">Failed to load metering data.</td></tr>';
        });
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
