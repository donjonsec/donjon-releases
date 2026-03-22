#!/usr/bin/env python3
"""
Donjon Platform - AI Assistant Tab (HTML)
Fetches AI engine status/config from API and provides
an interface to analyze findings with AI.
All CSS/JS inline for air-gap operation.
"""


def generate_ai_html() -> str:
    """Return the AI assistant tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.ai-grid {'
        '  display: grid;'
        '  grid-template-columns: 1fr 1fr;'
        '  gap: 16px;'
        '  margin-bottom: 24px;'
        '}'
        '@media (max-width: 900px) {'
        '  .ai-grid { grid-template-columns: 1fr; }'
        '}'
        '.ai-card {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '}'
        '.ai-card-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  color: var(--text);'
        '  margin-bottom: 16px;'
        '}'
        '.ai-status-row {'
        '  display: flex;'
        '  align-items: center;'
        '  justify-content: space-between;'
        '  padding: 8px 0;'
        '  border-bottom: 1px solid var(--border);'
        '}'
        '.ai-status-row:last-child { border-bottom: none; }'
        '.ai-status-key {'
        '  font-size: 0.82rem;'
        '  font-weight: 500;'
        '  color: var(--text-muted);'
        '}'
        '.ai-status-val {'
        '  font-size: 0.85rem;'
        '  font-weight: 600;'
        '  font-family: var(--font-data);'
        '  color: var(--text);'
        '}'
        '.ai-badge {'
        '  display: inline-block;'
        '  padding: 2px 10px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.ai-badge-ok { background: rgba(34,197,94,0.15); color: #22c55e; }'
        '.ai-badge-err { background: rgba(239,68,68,0.15); color: #ef4444; }'
        '.ai-badge-warn { background: rgba(234,179,8,0.15); color: #eab308; }'
        '.ai-textarea {'
        '  width: 100%;'
        '  min-height: 120px;'
        '  background: var(--bg-body);'
        '  border: 1px solid var(--border);'
        '  border-radius: 6px;'
        '  padding: 12px;'
        '  color: var(--text);'
        '  font-size: 0.85rem;'
        '  font-family: var(--font-data);'
        '  resize: vertical;'
        '}'
        '.ai-textarea:focus { outline: none; border-color: var(--accent); }'
        '.ai-btn {'
        '  background: var(--accent);'
        '  color: #fff;'
        '  border: none;'
        '  border-radius: 6px;'
        '  padding: 8px 16px;'
        '  font-size: 0.85rem;'
        '  font-weight: 600;'
        '  cursor: pointer;'
        '  font-family: var(--font-ui);'
        '  transition: background 0.2s;'
        '  margin-top: 12px;'
        '}'
        '.ai-btn:hover { background: var(--accent-hover); }'
        '.ai-btn:disabled {'
        '  opacity: 0.5;'
        '  cursor: not-allowed;'
        '}'
        '.ai-result {'
        '  background: var(--bg-body);'
        '  border: 1px solid var(--border);'
        '  border-radius: 6px;'
        '  padding: 16px;'
        '  margin-top: 16px;'
        '  font-size: 0.85rem;'
        '  font-family: var(--font-data);'
        '  color: var(--text);'
        '  white-space: pre-wrap;'
        '  line-height: 1.6;'
        '  max-height: 400px;'
        '  overflow-y: auto;'
        '  display: none;'
        '}'
        '.ai-result.visible { display: block; }'
    )
    parts.append('</style>')

    # Status + Config grid
    parts.append('<div class="ai-grid">')

    # AI Status
    parts.append(
        '<div class="ai-card">'
        '<div class="ai-card-title">AI Engine Status</div>'
        '<div id="aiStatusRows">'
        '<div style="color:var(--text-muted);text-align:center;padding:20px;">Loading...</div>'
        '</div>'
        '</div>'
    )

    # AI Config
    parts.append(
        '<div class="ai-card">'
        '<div class="ai-card-title">Configuration</div>'
        '<div id="aiConfigRows">'
        '<div style="color:var(--text-muted);text-align:center;padding:20px;">Loading...</div>'
        '</div>'
        '</div>'
    )

    parts.append('</div>')  # close grid

    # Query interface
    parts.append(
        '<div class="ai-card">'
        '<div class="ai-card-title">Analyze Finding</div>'
        '<textarea class="ai-textarea" id="aiInput" '
        'placeholder="Paste a finding or vulnerability description here for AI analysis..."></textarea>'
        '<div style="display:flex;gap:8px;">'
        '<button class="ai-btn" id="aiAnalyzeBtn">Analyze</button>'
        '<button class="ai-btn" id="aiTriageBtn" style="background:var(--high);">Triage</button>'
        '<button class="ai-btn" id="aiRemediateBtn" style="background:var(--low);">Remediate</button>'
        '</div>'
        '<div class="ai-result" id="aiResult"></div>'
        '</div>'
    )

    # JavaScript
    parts.append('<script>')
    parts.append('''(function(){
    var loaded = false;

    function statusRow(key, val) {
        return '<div class="ai-status-row">' +
            '<span class="ai-status-key">' + key + '</span>' +
            '<span class="ai-status-val">' + val + '</span></div>';
    }

    function statusBadge(ok) {
        if (ok === true || ok === "connected" || ok === "ready" || ok === "ok") {
            return '<span class="ai-badge ai-badge-ok">CONNECTED</span>';
        }
        if (ok === "configured" || ok === "available") {
            return '<span class="ai-badge ai-badge-warn">CONFIGURED</span>';
        }
        return '<span class="ai-badge ai-badge-err">UNAVAILABLE</span>';
    }

    function loadAI() {
        if (loaded) return;
        loaded = true;

        // Fetch status
        fetch("/api/v1/ai/status").then(function(r){return r.json();}).then(function(d){
            var el = document.getElementById("aiStatusRows");
            var html = "";
            html += statusRow("Status", statusBadge(d.status || d.connected || d.available));
            html += statusRow("Provider", d.provider || d.engine || "-");
            html += statusRow("Model", d.model || d.model_name || "-");
            if (d.endpoint || d.base_url) html += statusRow("Endpoint", d.endpoint || d.base_url);
            if (d.version) html += statusRow("Version", d.version);
            if (d.last_query || d.last_used) html += statusRow("Last Query", d.last_query || d.last_used);
            el.innerHTML = html;
        }).catch(function(){
            document.getElementById("aiStatusRows").innerHTML =
                statusRow("Status", statusBadge(false)) +
                statusRow("Provider", "Not configured") +
                statusRow("Model", "-");
        });

        // Fetch config
        fetch("/api/v1/ai/config").then(function(r){return r.json();}).then(function(d){
            var el = document.getElementById("aiConfigRows");
            var html = "";
            var cfg = d.config || d;
            html += statusRow("Provider", cfg.provider || cfg.ai_provider || "-");
            html += statusRow("Model", cfg.model || cfg.ai_model || "-");
            html += statusRow("Temperature", (cfg.temperature !== undefined ? cfg.temperature : "-"));
            html += statusRow("Max Tokens", (cfg.max_tokens !== undefined ? cfg.max_tokens : "-"));
            if (cfg.endpoint || cfg.base_url) html += statusRow("Endpoint", cfg.endpoint || cfg.base_url);
            el.innerHTML = html;
        }).catch(function(){
            document.getElementById("aiConfigRows").innerHTML =
                '<div style="color:var(--text-muted);text-align:center;padding:12px;">AI not configured. Set provider in Settings.</div>';
        });

        // Bind analyze buttons
        function doAI(endpoint) {
            var text = document.getElementById("aiInput").value.trim();
            if (!text) { alert("Enter a finding to analyze."); return; }
            var resultEl = document.getElementById("aiResult");
            resultEl.className = "ai-result visible";
            resultEl.textContent = "Analyzing...";

            var btns = document.querySelectorAll(".ai-btn");
            btns.forEach(function(b){ b.disabled = true; });

            fetch("/api/v1/ai/" + endpoint, {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({finding: text, text: text, description: text})
            }).then(function(r){return r.json();}).then(function(d){
                var output = d.analysis || d.result || d.triage || d.remediation || d.response || d.message || JSON.stringify(d, null, 2);
                resultEl.textContent = output;
                btns.forEach(function(b){ b.disabled = false; });
            }).catch(function(err){
                resultEl.textContent = "Error: " + err.message + "\\nEnsure AI engine is configured in Settings.";
                btns.forEach(function(b){ b.disabled = false; });
            });
        }

        document.getElementById("aiAnalyzeBtn").addEventListener("click", function(){ doAI("analyze"); });
        document.getElementById("aiTriageBtn").addEventListener("click", function(){ doAI("triage"); });
        document.getElementById("aiRemediateBtn").addEventListener("click", function(){ doAI("remediate"); });
    }

    document.addEventListener("tabload", function(e) {
        if (e.detail && e.detail.tab === "ai-assistant") {
            loadAI();
        }
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
