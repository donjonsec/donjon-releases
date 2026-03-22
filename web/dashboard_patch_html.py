#!/usr/bin/env python3
"""
Donjon Platform - Patch Verification Tab (HTML)
Fetches findings filtered by remediation status and shows
patch verification progress per finding.
All CSS/JS inline for air-gap operation.
"""


def generate_patch_html() -> str:
    """Return the patch verification tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.pv-stats {'
        '  display: grid;'
        '  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));'
        '  gap: 16px;'
        '  margin-bottom: 24px;'
        '}'
        '.pv-stat {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 16px 20px;'
        '  text-align: center;'
        '}'
        '.pv-stat-value {'
        '  font-size: 1.8rem;'
        '  font-weight: 700;'
        '  font-family: var(--font-data);'
        '  color: var(--text);'
        '}'
        '.pv-stat-value.green { color: var(--low); }'
        '.pv-stat-value.orange { color: var(--high); }'
        '.pv-stat-value.red { color: var(--critical); }'
        '.pv-stat-label {'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  text-transform: uppercase;'
        '  margin-top: 4px;'
        '}'
        '.pv-card {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  margin-bottom: 16px;'
        '}'
        '.pv-card-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  color: var(--text);'
        '  margin-bottom: 16px;'
        '}'
        '.pv-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.pv-table th {'
        '  text-align: left;'
        '  padding: 8px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.pv-table td {'
        '  padding: 8px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
        '.pv-sev {'
        '  display: inline-block;'
        '  padding: 2px 8px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.pv-sev-critical { background: rgba(220,38,38,0.15); color: #dc2626; }'
        '.pv-sev-high { background: rgba(234,88,12,0.15); color: #ea580c; }'
        '.pv-sev-medium { background: rgba(234,179,8,0.15); color: #eab308; }'
        '.pv-sev-low { background: rgba(59,130,246,0.15); color: #3b82f6; }'
        '.pv-badge {'
        '  display: inline-block;'
        '  padding: 2px 8px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.pv-badge-verified { background: rgba(34,197,94,0.15); color: #22c55e; }'
        '.pv-badge-pending { background: rgba(234,179,8,0.15); color: #eab308; }'
        '.pv-badge-failed { background: rgba(239,68,68,0.15); color: #ef4444; }'
        '.pv-badge-open { background: rgba(107,114,128,0.15); color: #6B7280; }'
        '.pv-progress-bar {'
        '  height: 8px;'
        '  background: var(--bg-surface-alt);'
        '  border-radius: 4px;'
        '  overflow: hidden;'
        '  margin-top: 8px;'
        '}'
        '.pv-progress-fill {'
        '  height: 100%;'
        '  background: var(--low);'
        '  border-radius: 4px;'
        '  transition: width 0.6s ease;'
        '}'
    )
    parts.append('</style>')

    # Stat cards
    parts.append('<div class="pv-stats">')
    for sid, label in [
        ('pvTotal', 'Total Findings'),
        ('pvPatched', 'Verified Patched'),
        ('pvPending', 'Pending Verification'),
        ('pvFailed', 'Failed Verification'),
        ('pvRate', 'Patch Rate'),
    ]:
        parts.append(
            '<div class="pv-stat">'
            '<div class="pv-stat-value" id="' + sid + '">-</div>'
            '<div class="pv-stat-label">' + label + '</div>'
            '</div>'
        )
    parts.append('</div>')

    # Progress bar
    parts.append(
        '<div class="pv-card">'
        '<div class="pv-card-title">Overall Patch Progress</div>'
        '<div style="display:flex;justify-content:space-between;font-size:0.82rem;color:var(--text-muted);">'
        '<span id="pvProgressLabel">0% verified</span>'
        '<span id="pvProgressCount">0 / 0</span>'
        '</div>'
        '<div class="pv-progress-bar">'
        '<div class="pv-progress-fill" id="pvProgressFill" style="width:0%"></div>'
        '</div>'
        '</div>'
    )

    # Findings table
    parts.append(
        '<div class="pv-card">'
        '<div class="pv-card-title">Findings &amp; Patch Status</div>'
        '<table class="pv-table">'
        '<thead><tr>'
        '<th>Severity</th><th>Finding</th><th>Target</th><th>Remediation</th><th>Patch Status</th>'
        '</tr></thead>'
        '<tbody id="pvBody">'
        '<tr><td colspan="5" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
    )

    # JavaScript
    parts.append('<script>')
    parts.append('''(function(){
    var loaded = false;

    function sevBadge(sev) {
        var s = (sev || "info").toLowerCase();
        var cls = "pv-sev pv-sev-" + (s === "critical" || s === "high" || s === "medium" || s === "low" ? s : "low");
        return '<span class="' + cls + '">' + s.toUpperCase() + '</span>';
    }

    function patchBadge(status) {
        var s = (status || "open").toLowerCase();
        var cls = "pv-badge pv-badge-";
        if (s === "verified" || s === "patched" || s === "fixed" || s === "resolved") cls += "verified";
        else if (s === "pending" || s === "in_progress" || s === "in progress") cls += "pending";
        else if (s === "failed" || s === "regression") cls += "failed";
        else cls += "open";
        return '<span class="' + cls + '">' + s.toUpperCase() + '</span>';
    }

    function loadPatch() {
        if (loaded) return;
        loaded = true;

        // Fetch all findings
        fetch("/api/v1/findings").then(function(r){return r.json();}).then(function(data){
            var list = Array.isArray(data) ? data : (data.findings || data.results || []);

            // Also try remediation data
            fetch("/api/v1/remediation").then(function(r){return r.json();}).then(function(rData){
                var remList = Array.isArray(rData) ? rData : (rData.items || rData.remediations || []);
                var remMap = {};
                remList.forEach(function(r) {
                    var fid = r.finding_id || r.id;
                    if (fid) remMap[fid] = r;
                });
                renderFindings(list, remMap);
            }).catch(function(){
                renderFindings(list, {});
            });
        }).catch(function(){
            document.getElementById("pvBody").innerHTML =
                '<tr><td colspan="5" style="color:var(--text-muted);text-align:center;">No findings data available. Run a scan first.</td></tr>';
        });
    }

    function renderFindings(list, remMap) {
        var total = list.length;
        var verified = 0, pending = 0, failed = 0;

        list.forEach(function(f) {
            var fid = f.id || f.finding_id || "";
            var rem = remMap[fid] || {};
            var st = (rem.status || f.remediation_status || f.patch_status || f.status || "open").toLowerCase();
            if (st === "verified" || st === "patched" || st === "fixed" || st === "resolved") verified++;
            else if (st === "pending" || st === "in_progress" || st === "in progress") pending++;
            else if (st === "failed" || st === "regression") failed++;
        });

        document.getElementById("pvTotal").textContent = total;

        var verifEl = document.getElementById("pvPatched");
        verifEl.textContent = verified;
        verifEl.className = "pv-stat-value green";

        var pendEl = document.getElementById("pvPending");
        pendEl.textContent = pending;
        pendEl.className = "pv-stat-value" + (pending > 0 ? " orange" : "");

        var failEl = document.getElementById("pvFailed");
        failEl.textContent = failed;
        failEl.className = "pv-stat-value" + (failed > 0 ? " red" : "");

        var rate = total > 0 ? Math.round((verified / total) * 100) : 0;
        document.getElementById("pvRate").textContent = rate + "%";
        document.getElementById("pvRate").className = "pv-stat-value" + (rate >= 80 ? " green" : rate >= 50 ? " orange" : " red");

        document.getElementById("pvProgressLabel").textContent = rate + "% verified";
        document.getElementById("pvProgressCount").textContent = verified + " / " + total;
        document.getElementById("pvProgressFill").style.width = rate + "%";

        var body = document.getElementById("pvBody");
        if (total === 0) {
            body.innerHTML = '<tr><td colspan="5" style="color:var(--text-muted);text-align:center;">No findings to verify. Run a scan first.</td></tr>';
            return;
        }
        body.innerHTML = "";
        list.slice(0, 50).forEach(function(f) {
            var fid = f.id || f.finding_id || "";
            var rem = remMap[fid] || {};
            var st = rem.status || f.remediation_status || f.patch_status || f.status || "open";
            var tr = document.createElement("tr");
            tr.innerHTML =
                '<td>' + sevBadge(f.severity) + '</td>' +
                '<td>' + (f.title || f.finding || f.description || "-").substring(0, 70) + '</td>' +
                '<td style="font-family:var(--font-data);font-size:0.82rem;">' + (f.host || f.target || f.affected_asset || "-") + '</td>' +
                '<td>' + (rem.action || rem.remediation || f.remediation || "-").substring(0, 50) + '</td>' +
                '<td>' + patchBadge(st) + '</td>';
            body.appendChild(tr);
        });
    }

    document.addEventListener("tabload", function(e) {
        if (e.detail && e.detail.tab === "patch-verification") {
            loadPatch();
        }
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
