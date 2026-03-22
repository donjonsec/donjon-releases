#!/usr/bin/env python3
"""
Donjon Platform - Settings Tab (HTML)
Fetches platform configuration from API and renders
editable settings fields.
All CSS/JS inline for air-gap operation.
"""


def generate_settings_html() -> str:
    """Return the settings tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.st-section {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  margin-bottom: 16px;'
        '}'
        '.st-section-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  color: var(--text);'
        '  margin-bottom: 16px;'
        '  padding-bottom: 8px;'
        '  border-bottom: 1px solid var(--border);'
        '}'
        '.st-row {'
        '  display: flex;'
        '  align-items: center;'
        '  justify-content: space-between;'
        '  padding: 10px 0;'
        '  border-bottom: 1px solid var(--border);'
        '}'
        '.st-row:last-child { border-bottom: none; }'
        '.st-row-label {'
        '  font-size: 0.82rem;'
        '  font-weight: 500;'
        '  color: var(--text-muted);'
        '  min-width: 200px;'
        '}'
        '.st-input {'
        '  background: var(--bg-body);'
        '  border: 1px solid var(--border);'
        '  border-radius: 6px;'
        '  padding: 6px 12px;'
        '  color: var(--text);'
        '  font-size: 0.85rem;'
        '  font-family: var(--font-data);'
        '  width: 280px;'
        '}'
        '.st-input:focus { outline: none; border-color: var(--accent); }'
        '.st-btn {'
        '  background: var(--accent);'
        '  color: #fff;'
        '  border: none;'
        '  border-radius: 6px;'
        '  padding: 8px 20px;'
        '  font-size: 0.85rem;'
        '  font-weight: 600;'
        '  cursor: pointer;'
        '  font-family: var(--font-ui);'
        '  transition: background 0.2s;'
        '}'
        '.st-btn:hover { background: var(--accent-hover); }'
        '.st-save-bar {'
        '  display: flex;'
        '  align-items: center;'
        '  gap: 12px;'
        '  margin-top: 16px;'
        '}'
        '.st-msg {'
        '  font-size: 0.82rem;'
        '  font-weight: 500;'
        '  padding: 4px 12px;'
        '  border-radius: 6px;'
        '  display: none;'
        '}'
        '.st-msg.ok { display: inline-block; background: rgba(34,197,94,0.15); color: #22c55e; }'
        '.st-msg.err { display: inline-block; background: rgba(239,68,68,0.15); color: #ef4444; }'
        '.st-paths {'
        '  font-family: var(--font-data);'
        '  font-size: 0.82rem;'
        '  color: var(--text);'
        '}'
    )
    parts.append('</style>')

    # Scan settings section
    parts.append(
        '<div class="st-section">'
        '<div class="st-section-title">Scan Settings</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Default Timeout (seconds)</span>'
        '<input class="st-input" id="stScanTimeout" data-key="scan.default_timeout" />'
        '</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Max Concurrent Scans</span>'
        '<input class="st-input" id="stScanConcurrent" data-key="scan.max_concurrent" />'
        '</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Retry Count</span>'
        '<input class="st-input" id="stScanRetry" data-key="scan.retry_count" />'
        '</div>'
        '</div>'
    )

    # Reporting settings
    parts.append(
        '<div class="st-section">'
        '<div class="st-section-title">Reporting</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Company Name</span>'
        '<input class="st-input" id="stCompany" data-key="reporting.company_name" />'
        '</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Output Format</span>'
        '<input class="st-input" id="stFormat" data-key="reporting.output_format" placeholder="pdf" />'
        '</div>'
        '</div>'
    )

    # AI settings
    parts.append(
        '<div class="st-section">'
        '<div class="st-section-title">AI Engine</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Provider</span>'
        '<input class="st-input" id="stAIProvider" data-key="ai.provider" placeholder="ollama" />'
        '</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Model</span>'
        '<input class="st-input" id="stAIModel" data-key="ai.model" />'
        '</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Temperature</span>'
        '<input class="st-input" id="stAITemp" data-key="ai.temperature" placeholder="0.7" />'
        '</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Max Tokens</span>'
        '<input class="st-input" id="stAITokens" data-key="ai.max_tokens" placeholder="2048" />'
        '</div>'
        '</div>'
    )

    # Notifications settings
    parts.append(
        '<div class="st-section">'
        '<div class="st-section-title">Notifications</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Enabled</span>'
        '<input class="st-input" id="stNotifEnabled" data-key="notifications.enabled" placeholder="true" />'
        '</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Email</span>'
        '<input class="st-input" id="stNotifEmail" data-key="notifications.email" />'
        '</div>'
        '</div>'
    )

    # Dashboard settings
    parts.append(
        '<div class="st-section">'
        '<div class="st-section-title">Dashboard</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Refresh Interval (seconds)</span>'
        '<input class="st-input" id="stDashRefresh" data-key="dashboard.refresh_interval" placeholder="30" />'
        '</div>'
        '<div class="st-row">'
        '<span class="st-row-label">Logging Level</span>'
        '<input class="st-input" id="stLogLevel" data-key="logging.level" placeholder="INFO" />'
        '</div>'
        '</div>'
    )

    # Paths section (read-only)
    parts.append(
        '<div class="st-section">'
        '<div class="st-section-title">Data Paths</div>'
        '<div id="stPaths">'
        '<div style="color:var(--text-muted);text-align:center;padding:12px;">Loading...</div>'
        '</div>'
        '</div>'
    )

    # Save bar
    parts.append(
        '<div class="st-save-bar">'
        '<button class="st-btn" id="stSaveBtn">Save Settings</button>'
        '<span class="st-msg" id="stMsg"></span>'
        '</div>'
    )

    # JavaScript
    parts.append('<script>')
    parts.append('''(function(){
    var loaded = false;

    function loadSettings() {
        if (loaded) return;
        loaded = true;

        // Fetch current config
        fetch("/api/v1/settings/config").then(function(r){return r.json();}).then(function(d){
            var cfg = d.config || d;
            // Populate all inputs by data-key
            document.querySelectorAll("[data-key]").forEach(function(input) {
                var key = input.getAttribute("data-key");
                var parts = key.split(".");
                var val = cfg;
                for (var i = 0; i < parts.length && val; i++) {
                    val = val[parts[i]];
                }
                if (val !== undefined && val !== null) {
                    input.value = val;
                }
            });
        }).catch(function(){
            // Fields stay empty — that's fine for initial setup
        });

        // Fetch paths
        fetch("/api/v1/settings/paths").then(function(r){return r.json();}).then(function(d){
            var paths = d.paths || d;
            var el = document.getElementById("stPaths");
            var html = "";
            for (var k in paths) {
                html += '<div class="st-row">' +
                    '<span class="st-row-label">' + k + '</span>' +
                    '<span class="st-paths">' + paths[k] + '</span></div>';
            }
            el.innerHTML = html || '<div style="color:var(--text-muted);text-align:center;">No paths configured.</div>';
        }).catch(function(){
            document.getElementById("stPaths").innerHTML =
                '<div style="color:var(--text-muted);text-align:center;">Path info unavailable.</div>';
        });

        // Save button
        document.getElementById("stSaveBtn").addEventListener("click", function() {
            var payload = {};
            document.querySelectorAll("[data-key]").forEach(function(input) {
                var val = input.value.trim();
                if (val !== "") {
                    payload[input.getAttribute("data-key")] = val;
                }
            });

            var msg = document.getElementById("stMsg");
            msg.className = "st-msg";
            msg.textContent = "";

            fetch("/api/v1/settings/config", {
                method: "PUT",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(payload)
            }).then(function(r){
                if (!r.ok) throw new Error("API " + r.status);
                return r.json();
            }).then(function(){
                msg.className = "st-msg ok";
                msg.textContent = "Settings saved successfully.";
                setTimeout(function(){ msg.className = "st-msg"; }, 3000);
            }).catch(function(err){
                msg.className = "st-msg err";
                msg.textContent = "Save failed: " + err.message;
                setTimeout(function(){ msg.className = "st-msg"; }, 5000);
            });
        });
    }

    document.addEventListener("tabload", function(e) {
        if (e.detail && e.detail.tab === "settings") {
            loadSettings();
        }
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
