#!/usr/bin/env python3
"""
Donjon Platform - SSO Tab (HTML)
Enterprise tier: fetches SSO metadata and shows configuration status.
All CSS/JS inline for air-gap operation.
"""


def generate_sso_html() -> str:
    """Return the SSO tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.sso-panel {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 24px;'
        '  margin-bottom: 20px;'
        '  max-width: 800px;'
        '}'
        '.sso-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  margin-bottom: 16px;'
        '}'
        '.sso-row {'
        '  display: flex;'
        '  justify-content: space-between;'
        '  align-items: center;'
        '  padding: 10px 0;'
        '  border-bottom: 1px solid var(--border);'
        '}'
        '.sso-row:last-child { border-bottom: none; }'
        '.sso-label {'
        '  font-size: 0.85rem;'
        '  color: var(--text-muted);'
        '  font-weight: 500;'
        '}'
        '.sso-value {'
        '  font-size: 0.85rem;'
        '  font-family: var(--font-data);'
        '  color: var(--text);'
        '}'
        '.sso-status {'
        '  display: inline-block;'
        '  padding: 3px 10px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.sso-status-active { background: rgba(34,197,94,0.15); color: #22c55e; }'
        '.sso-status-inactive { background: rgba(239,68,68,0.15); color: #ef4444; }'
        '.sso-upgrade {'
        '  text-align: center;'
        '  padding: 60px 20px;'
        '  color: var(--text-muted);'
        '}'
        '.sso-upgrade-title {'
        '  font-size: 1.2rem;'
        '  font-weight: 700;'
        '  color: var(--text);'
        '  margin-bottom: 8px;'
        '}'
    )
    parts.append('</style>')

    parts.append(
        '<div id="ssoContent">'
        '<div class="sso-panel">'
        '<div class="sso-title">SSO Configuration</div>'
        '<div id="ssoDetails">'
        '<div style="color:var(--text-muted);text-align:center;padding:20px;">Loading...</div>'
        '</div>'
        '</div>'
        '</div>'
    )

    parts.append('<script>')
    parts.append('''(function(){
    document.addEventListener("tabload", function(e) {
        if (!e.detail || e.detail.tab !== "sso") return;

        var token = localStorage.getItem("donjon_token");
        var headers = {"Content-Type": "application/json"};
        if (token) headers["Authorization"] = "Bearer " + token;

        fetch("/api/v1/sso/metadata", {headers: headers}).then(function(r) {
            if (r.status === 403) throw {upgrade: true};
            if (!r.ok) throw new Error("API " + r.status);
            return r.json();
        }).then(function(data) {
            var el = document.getElementById("ssoDetails");
            var enabled = data.enabled || data.active || false;
            var provider = data.provider || data.idp || "Not configured";
            var entityId = data.entity_id || data.entityId || "-";
            var acsUrl = data.acs_url || data.acsUrl || "-";
            var lastSync = data.last_sync || data.lastSync || "-";
            var protocol = data.protocol || "SAML 2.0";

            var statusClass = enabled ? "sso-status-active" : "sso-status-inactive";
            var statusText = enabled ? "Active" : "Inactive";

            el.innerHTML =
                '<div class="sso-row"><span class="sso-label">Status</span>' +
                '<span class="sso-status ' + statusClass + '">' + statusText + '</span></div>' +
                '<div class="sso-row"><span class="sso-label">Provider</span>' +
                '<span class="sso-value">' + provider + '</span></div>' +
                '<div class="sso-row"><span class="sso-label">Protocol</span>' +
                '<span class="sso-value">' + protocol + '</span></div>' +
                '<div class="sso-row"><span class="sso-label">Entity ID</span>' +
                '<span class="sso-value">' + entityId + '</span></div>' +
                '<div class="sso-row"><span class="sso-label">ACS URL</span>' +
                '<span class="sso-value">' + acsUrl + '</span></div>' +
                '<div class="sso-row"><span class="sso-label">Last Sync</span>' +
                '<span class="sso-value">' + lastSync + '</span></div>';
        }).catch(function(err) {
            if (err && err.upgrade) {
                document.getElementById("ssoContent").innerHTML =
                    '<div class="sso-upgrade"><div class="sso-upgrade-title">Enterprise Feature</div>' +
                    'SSO configuration requires an Enterprise or Managed license.<br>' +
                    'Contact sales or upgrade your license to access this feature.</div>';
                return;
            }
            document.getElementById("ssoDetails").innerHTML =
                '<div style="color:var(--text-muted);text-align:center;padding:20px;">Failed to load SSO configuration.</div>';
        });
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
