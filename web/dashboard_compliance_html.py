#!/usr/bin/env python3
"""
Donjon Platform - Compliance Tab (HTML)
Fetches compliance data from API and renders framework coverage,
overlap matrix, and gap analysis.
All CSS/JS inline for air-gap operation.
"""


def generate_compliance_html() -> str:
    """Return the compliance tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.cp-grid {'
        '  display: grid;'
        '  grid-template-columns: 1fr 1fr;'
        '  gap: 16px;'
        '  margin-bottom: 24px;'
        '}'
        '@media (max-width: 900px) {'
        '  .cp-grid { grid-template-columns: 1fr; }'
        '}'
        '.cp-card {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '}'
        '.cp-card-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  color: var(--text);'
        '  margin-bottom: 16px;'
        '}'
        '.cp-bar-row {'
        '  display: flex;'
        '  align-items: center;'
        '  gap: 12px;'
        '  margin-bottom: 10px;'
        '}'
        '.cp-bar-label {'
        '  width: 140px;'
        '  font-size: 0.82rem;'
        '  font-weight: 500;'
        '  color: var(--text);'
        '  flex-shrink: 0;'
        '}'
        '.cp-bar-track {'
        '  flex: 1;'
        '  height: 22px;'
        '  background: var(--bg-surface-alt);'
        '  border-radius: 4px;'
        '  overflow: hidden;'
        '  position: relative;'
        '}'
        '.cp-bar-fill {'
        '  height: 100%;'
        '  background: var(--accent);'
        '  border-radius: 4px;'
        '  transition: width 0.6s ease;'
        '}'
        '.cp-bar-pct {'
        '  width: 50px;'
        '  text-align: right;'
        '  font-size: 0.82rem;'
        '  font-weight: 600;'
        '  font-family: var(--font-data);'
        '  color: var(--text);'
        '}'
        '.cp-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.cp-table th {'
        '  text-align: left;'
        '  padding: 8px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.cp-table td {'
        '  padding: 8px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
        '.cp-stat-row {'
        '  display: flex;'
        '  gap: 16px;'
        '  margin-bottom: 24px;'
        '}'
        '.cp-stat {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 16px 20px;'
        '  flex: 1;'
        '  text-align: center;'
        '}'
        '.cp-stat-value {'
        '  font-size: 1.8rem;'
        '  font-weight: 700;'
        '  font-family: var(--font-data);'
        '  color: var(--accent);'
        '}'
        '.cp-stat-label {'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  text-transform: uppercase;'
        '  margin-top: 4px;'
        '}'
        '.cp-sev {'
        '  display: inline-block;'
        '  padding: 2px 8px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.cp-sev-high { background: rgba(234,88,12,0.15); color: #ea580c; }'
        '.cp-sev-medium { background: rgba(234,179,8,0.15); color: #eab308; }'
        '.cp-sev-low { background: rgba(59,130,246,0.15); color: #3b82f6; }'
    )
    parts.append('</style>')

    # Stat cards row
    parts.append(
        '<div class="cp-stat-row">'
        '<div class="cp-stat">'
        '<div class="cp-stat-value" id="cpTotalControls">-</div>'
        '<div class="cp-stat-label">Total Controls</div>'
        '</div>'
        '<div class="cp-stat">'
        '<div class="cp-stat-value" id="cpPassRate">-</div>'
        '<div class="cp-stat-label">Pass Rate</div>'
        '</div>'
        '<div class="cp-stat">'
        '<div class="cp-stat-value" id="cpGaps">-</div>'
        '<div class="cp-stat-label">Open Gaps</div>'
        '</div>'
        '<div class="cp-stat">'
        '<div class="cp-stat-value" id="cpOverlap">-</div>'
        '<div class="cp-stat-label">Shared Controls</div>'
        '</div>'
        '</div>'
    )

    # Grid: coverage bars + gap table
    parts.append('<div class="cp-grid">')

    # Framework coverage bars
    parts.append(
        '<div class="cp-card">'
        '<div class="cp-card-title">Framework Coverage</div>'
        '<div id="cpBars">'
        '<div style="color:var(--text-muted);text-align:center;padding:20px;">Loading...</div>'
        '</div>'
        '</div>'
    )

    # Top compliance gaps
    parts.append(
        '<div class="cp-card">'
        '<div class="cp-card-title">Top Compliance Gaps</div>'
        '<table class="cp-table">'
        '<thead><tr><th>Control</th><th>Framework</th><th>Priority</th></tr></thead>'
        '<tbody id="cpGapsBody">'
        '<tr><td colspan="3" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
    )

    parts.append('</div>')  # close grid

    # Overlap matrix
    parts.append(
        '<div class="cp-card">'
        '<div class="cp-card-title">Framework Overlap Matrix</div>'
        '<div id="cpOverlapMatrix">'
        '<div style="color:var(--text-muted);text-align:center;padding:20px;">Loading...</div>'
        '</div>'
        '</div>'
    )

    # JavaScript
    parts.append('<script>')
    parts.append('''(function(){
    var loaded = false;

    function loadCompliance() {
        if (loaded) return;
        loaded = true;

        // Fetch NIST 800-53 compliance report
        fetch("/api/v1/reports/compliance/nist_800_53").then(function(r){return r.json();}).then(function(d){
            var controls = d.controls || d.total_controls || 0;
            var passed = d.passed || d.compliant || 0;
            var failed = d.failed || d.non_compliant || 0;
            var total = controls || (passed + failed) || 1;
            var pct = Math.round((passed / total) * 100);

            document.getElementById("cpTotalControls").textContent = total;
            document.getElementById("cpPassRate").textContent = pct + "%";
            document.getElementById("cpGaps").textContent = failed;

            // Build framework coverage bars from families/categories
            var families = d.families || d.categories || d.frameworks || {};
            var barsEl = document.getElementById("cpBars");
            barsEl.innerHTML = "";

            if (typeof families === "object" && Object.keys(families).length > 0) {
                for (var fw in families) {
                    var fam = families[fw];
                    var p = 0;
                    if (typeof fam === "number") {
                        p = fam;
                    } else if (fam && typeof fam === "object") {
                        var fp = fam.passed || fam.compliant || 0;
                        var ft = fam.total || fam.controls || 1;
                        p = Math.round((fp / ft) * 100);
                    }
                    var row = document.createElement("div");
                    row.className = "cp-bar-row";
                    row.innerHTML =
                        '<div class="cp-bar-label">' + fw + '</div>' +
                        '<div class="cp-bar-track"><div class="cp-bar-fill" style="width:' + p + '%"></div></div>' +
                        '<div class="cp-bar-pct">' + p + '%</div>';
                    barsEl.appendChild(row);
                }
            } else {
                // Fallback: show single NIST bar
                barsEl.innerHTML =
                    '<div class="cp-bar-row">' +
                    '<div class="cp-bar-label">NIST 800-53</div>' +
                    '<div class="cp-bar-track"><div class="cp-bar-fill" style="width:' + pct + '%"></div></div>' +
                    '<div class="cp-bar-pct">' + pct + '%</div>' +
                    '</div>';
            }

            // Populate gaps table
            var gaps = d.gaps || d.failures || d.non_compliant_controls || [];
            var gapsBody = document.getElementById("cpGapsBody");
            if (Array.isArray(gaps) && gaps.length > 0) {
                gapsBody.innerHTML = "";
                gaps.slice(0, 15).forEach(function(g) {
                    var tr = document.createElement("tr");
                    var pri = (g.priority || g.severity || "medium").toLowerCase();
                    var priClass = "cp-sev cp-sev-" + (pri === "high" || pri === "critical" ? "high" : pri === "low" ? "low" : "medium");
                    tr.innerHTML =
                        '<td>' + (g.control_id || g.control || g.id || "-") + '</td>' +
                        '<td>' + (g.framework || g.family || "NIST 800-53") + '</td>' +
                        '<td><span class="' + priClass + '">' + pri.toUpperCase() + '</span></td>';
                    gapsBody.appendChild(tr);
                });
            } else {
                gapsBody.innerHTML = '<tr><td colspan="3" style="color:var(--text-muted);text-align:center;">No gaps found - fully compliant.</td></tr>';
            }
        }).catch(function(){
            document.getElementById("cpBars").innerHTML = '<div style="color:var(--text-muted);text-align:center;">No compliance data available. Run a compliance scan first.</div>';
            document.getElementById("cpGapsBody").innerHTML = '<tr><td colspan="3" style="color:var(--text-muted);text-align:center;">No data available.</td></tr>';
        });

        // Fetch overlap analysis
        fetch("/api/v1/compliance/overlap?frameworks=nist_800_53,hipaa").then(function(r){return r.json();}).then(function(d){
            var shared = d.shared_across_all || 0;
            document.getElementById("cpOverlap").textContent = shared;

            var matrix = d.overlap_matrix || {};
            var frameworks = d.frameworks || Object.keys(matrix);
            var el = document.getElementById("cpOverlapMatrix");

            if (frameworks.length === 0) {
                el.innerHTML = '<div style="color:var(--text-muted);text-align:center;">No overlap data available.</div>';
                return;
            }

            var html = '<table class="cp-table"><thead><tr><th></th>';
            frameworks.forEach(function(fw) { html += '<th>' + fw + '</th>'; });
            html += '</tr></thead><tbody>';
            frameworks.forEach(function(fwA) {
                html += '<tr><td style="font-weight:600;">' + fwA + '</td>';
                frameworks.forEach(function(fwB) {
                    var val = (matrix[fwA] && matrix[fwA][fwB]) || 0;
                    var bg = fwA === fwB ? 'var(--accent)' : 'transparent';
                    var color = fwA === fwB ? '#fff' : 'var(--text)';
                    html += '<td style="text-align:center;background:' + bg + ';color:' + color + ';border-radius:4px;">' + val + '</td>';
                });
                html += '</tr>';
            });
            html += '</tbody></table>';
            el.innerHTML = html;
        }).catch(function(){
            document.getElementById("cpOverlap").textContent = "-";
            document.getElementById("cpOverlapMatrix").innerHTML = '<div style="color:var(--text-muted);text-align:center;">Overlap analysis unavailable.</div>';
        });
    }

    document.addEventListener("tabload", function(e) {
        if (e.detail && e.detail.tab === "compliance") {
            loadCompliance();
        }
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
