#!/usr/bin/env python3
"""
Donjon Platform - Overview Tab (HTML)
Fetches stats from API and renders a summary dashboard.
All CSS/JS inline for air-gap operation.
"""


def generate_overview_html() -> str:
    """Return the overview tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.ov-grid {'
        '  display: grid;'
        '  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));'
        '  gap: 16px;'
        '  margin-bottom: 24px;'
        '}'
        '.ov-card {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '}'
        '.ov-card-label {'
        '  font-size: 0.8rem;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  text-transform: uppercase;'
        '  letter-spacing: 0.05em;'
        '  margin-bottom: 8px;'
        '}'
        '.ov-card-value {'
        '  font-size: 2rem;'
        '  font-weight: 700;'
        '  font-family: var(--font-data);'
        '  color: var(--text);'
        '}'
        '.ov-card-value.green { color: var(--accent); }'
        '.ov-card-value.red { color: var(--critical); }'
        '.ov-card-value.orange { color: var(--high); }'
        '.ov-section {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  margin-bottom: 16px;'
        '}'
        '.ov-section-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  color: var(--text);'
        '  margin-bottom: 12px;'
        '}'
        '.ov-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.ov-table th {'
        '  text-align: left;'
        '  padding: 8px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.ov-table td {'
        '  padding: 8px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
        '.ov-sev {'
        '  display: inline-block;'
        '  padding: 2px 8px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.ov-sev-critical { background: rgba(220,38,38,0.15); color: #dc2626; }'
        '.ov-sev-high { background: rgba(234,88,12,0.15); color: #ea580c; }'
        '.ov-sev-medium { background: rgba(234,179,8,0.15); color: #eab308; }'
        '.ov-sev-low { background: rgba(59,130,246,0.15); color: #3b82f6; }'
        '.ov-sev-info { background: rgba(107,114,128,0.15); color: #6B7280; }'
    )
    parts.append('</style>')

    # Stat cards
    parts.append('<div class="ov-grid" id="ovCards">')
    for card_id, label in [
        ('ovSessions', 'Scan Sessions'),
        ('ovFindings', 'Open Findings'),
        ('ovCritical', 'Critical'),
        ('ovHigh', 'High'),
        ('ovAssets', 'Assets'),
        ('ovAgents', 'Agents'),
    ]:
        parts.append(
            '<div class="ov-card">'
            '<div class="ov-card-label">' + label + '</div>'
            '<div class="ov-card-value" id="' + card_id + '">-</div>'
            '</div>'
        )
    parts.append('</div>')

    # Recent findings table
    parts.append(
        '<div class="ov-section">'
        '<div class="ov-section-title">Recent Findings</div>'
        '<table class="ov-table">'
        '<thead><tr>'
        '<th>Severity</th><th>Finding</th><th>Target</th><th>Scanner</th>'
        '</tr></thead>'
        '<tbody id="ovFindingsBody">'
        '<tr><td colspan="4" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
    )

    # Module status
    parts.append(
        '<div class="ov-section">'
        '<div class="ov-section-title">Module Status</div>'
        '<div id="ovModules" style="display:flex;flex-wrap:wrap;gap:8px;"></div>'
        '</div>'
    )

    # JavaScript
    parts.append('<script>')
    parts.append('''(function(){
    var loaded = false;

    function loadOverview() {
        if (loaded) return;
        loaded = true;

        // Fetch stats
        fetch("/api/v1/stats").then(function(r){return r.json();}).then(function(d){
            document.getElementById("ovSessions").textContent = d.sessions_total || 0;
            var of = d.open_findings || 0;
            document.getElementById("ovFindings").textContent = of;
            document.getElementById("ovFindings").className = "ov-card-value" + (of > 0 ? " orange" : " green");

            var bySev = d.findings_by_severity || {};
            var crit = bySev.CRITICAL || bySev.critical || 0;
            var high = bySev.HIGH || bySev.high || 0;
            document.getElementById("ovCritical").textContent = crit;
            document.getElementById("ovCritical").className = "ov-card-value" + (crit > 0 ? " red" : "");
            document.getElementById("ovHigh").textContent = high;
            document.getElementById("ovHigh").className = "ov-card-value" + (high > 0 ? " orange" : "");

            var assets = d.assets || {};
            document.getElementById("ovAssets").textContent = assets.total || assets.count || 0;
            document.getElementById("ovAgents").textContent = (d.agents || {}).connected || 0;
        }).catch(function(){});

        // Fetch recent findings
        fetch("/api/v1/findings?limit=10").then(function(r){return r.json();}).then(function(findings){
            var list = Array.isArray(findings) ? findings : (findings.findings || findings.results || []);
            var body = document.getElementById("ovFindingsBody");
            if (list.length === 0) {
                body.innerHTML = '<tr><td colspan="4" style="color:var(--text-muted);text-align:center;">No findings yet. Run a scan to get started.</td></tr>';
                return;
            }
            body.innerHTML = "";
            list.slice(0, 10).forEach(function(f) {
                var sev = (f.severity || "info").toLowerCase();
                var tr = document.createElement("tr");
                tr.innerHTML =
                    '<td><span class="ov-sev ov-sev-' + sev + '">' + sev.toUpperCase() + '</span></td>' +
                    '<td>' + (f.title || f.finding || f.description || "").substring(0, 80) + '</td>' +
                    '<td>' + (f.host || f.target || f.affected_asset || "") + '</td>' +
                    '<td>' + (f.scanner || f.tool || "") + '</td>';
                body.appendChild(tr);
            });
        }).catch(function(){
            document.getElementById("ovFindingsBody").innerHTML =
                '<tr><td colspan="4" style="color:var(--text-muted);text-align:center;">No findings yet. Run a scan to get started.</td></tr>';
        });

        // Fetch module health
        fetch("/api/v1/health").then(function(r){return r.json();}).then(function(d){
            var mods = d.modules || {};
            var container = document.getElementById("ovModules");
            container.innerHTML = "";
            for (var name in mods) {
                var ok = mods[name];
                var el = document.createElement("span");
                el.style.cssText = "padding:4px 10px;border-radius:6px;font-size:0.8rem;font-weight:500;" +
                    (ok ? "background:rgba(34,197,94,0.15);color:#22c55e;" : "background:rgba(239,68,68,0.15);color:#ef4444;");
                el.textContent = (ok ? "\\u2713 " : "\\u2717 ") + name;
                container.appendChild(el);
            }
        }).catch(function(){});
    }

    document.addEventListener("tabload", function(e) {
        if (e.detail && e.detail.tab === "overview") {
            loadOverview();
        }
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
