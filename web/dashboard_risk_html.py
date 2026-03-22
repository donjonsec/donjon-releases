#!/usr/bin/env python3
"""
Donjon Platform - Risk Analysis Tab (HTML)
Fetches risk posture and matrix from API and renders
risk score, ALE values, and a risk matrix grid.
All CSS/JS inline for air-gap operation.
"""


def generate_risk_html() -> str:
    """Return the risk analysis tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.rk-stats {'
        '  display: grid;'
        '  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));'
        '  gap: 16px;'
        '  margin-bottom: 24px;'
        '}'
        '.rk-stat {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  text-align: center;'
        '}'
        '.rk-stat-value {'
        '  font-size: 1.8rem;'
        '  font-weight: 700;'
        '  font-family: var(--font-data);'
        '  color: var(--text);'
        '}'
        '.rk-stat-value.green { color: var(--low); }'
        '.rk-stat-value.orange { color: var(--high); }'
        '.rk-stat-value.red { color: var(--critical); }'
        '.rk-stat-label {'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  text-transform: uppercase;'
        '  margin-top: 4px;'
        '}'
        '.rk-grid {'
        '  display: grid;'
        '  grid-template-columns: 1fr 1fr;'
        '  gap: 16px;'
        '  margin-bottom: 24px;'
        '}'
        '@media (max-width: 900px) {'
        '  .rk-grid { grid-template-columns: 1fr; }'
        '}'
        '.rk-card {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '}'
        '.rk-card-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  color: var(--text);'
        '  margin-bottom: 16px;'
        '}'
        '.rk-matrix {'
        '  display: grid;'
        '  grid-template-columns: auto repeat(5, 1fr);'
        '  gap: 4px;'
        '}'
        '.rk-matrix-cell {'
        '  padding: 10px 6px;'
        '  text-align: center;'
        '  border-radius: 4px;'
        '  font-size: 0.8rem;'
        '  font-weight: 600;'
        '  font-family: var(--font-data);'
        '  min-width: 50px;'
        '}'
        '.rk-matrix-header {'
        '  font-size: 0.7rem;'
        '  color: var(--text-muted);'
        '  text-transform: uppercase;'
        '  padding: 6px;'
        '  text-align: center;'
        '}'
        '.rk-matrix-label {'
        '  font-size: 0.75rem;'
        '  color: var(--text);'
        '  font-weight: 600;'
        '  padding: 10px 8px 10px 0;'
        '  text-align: right;'
        '}'
        '.rk-cell-low { background: rgba(34,197,94,0.15); color: #22c55e; }'
        '.rk-cell-medium { background: rgba(234,179,8,0.15); color: #eab308; }'
        '.rk-cell-high { background: rgba(234,88,12,0.15); color: #ea580c; }'
        '.rk-cell-critical { background: rgba(239,68,68,0.15); color: #ef4444; }'
        '.rk-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.rk-table th {'
        '  text-align: left;'
        '  padding: 8px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.rk-table td {'
        '  padding: 8px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
    )
    parts.append('</style>')

    # Stat cards
    parts.append('<div class="rk-stats">')
    for sid, label in [
        ('rkScore', 'Risk Score'),
        ('rkALE', 'Annual Loss Exp.'),
        ('rkTotal', 'Total Risks'),
        ('rkCritical', 'Critical Risks'),
        ('rkMitigated', 'Mitigated'),
    ]:
        parts.append(
            '<div class="rk-stat">'
            '<div class="rk-stat-value" id="' + sid + '">-</div>'
            '<div class="rk-stat-label">' + label + '</div>'
            '</div>'
        )
    parts.append('</div>')

    # Grid: matrix + top risks
    parts.append('<div class="rk-grid">')

    # Risk matrix
    parts.append(
        '<div class="rk-card">'
        '<div class="rk-card-title">Risk Matrix (Likelihood x Impact)</div>'
        '<div id="rkMatrix">'
        '<div style="color:var(--text-muted);text-align:center;padding:20px;">Loading...</div>'
        '</div>'
        '</div>'
    )

    # Top risks table
    parts.append(
        '<div class="rk-card">'
        '<div class="rk-card-title">Top Risks</div>'
        '<table class="rk-table">'
        '<thead><tr><th>Risk</th><th>Impact</th><th>Likelihood</th><th>Status</th></tr></thead>'
        '<tbody id="rkRisksBody">'
        '<tr><td colspan="4" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
    )

    parts.append('</div>')  # close grid

    # JavaScript
    parts.append('<script>')
    parts.append('''(function(){
    var loaded = false;

    function loadRisk() {
        if (loaded) return;
        loaded = true;

        // Fetch risk posture
        fetch("/api/v1/risks/posture").then(function(r){return r.json();}).then(function(d){
            var score = d.risk_score || d.score || d.overall_score || 0;
            var ale = d.ale || d.annual_loss_expectancy || d.total_ale || 0;
            var total = d.total_risks || d.total || d.count || 0;
            var crit = d.critical || d.critical_count || 0;
            var mitigated = d.mitigated || d.mitigated_count || 0;

            var scoreEl = document.getElementById("rkScore");
            scoreEl.textContent = score;
            scoreEl.className = "rk-stat-value" + (score > 75 ? " red" : score > 50 ? " orange" : " green");

            document.getElementById("rkALE").textContent = "$" + Number(ale).toLocaleString();
            document.getElementById("rkTotal").textContent = total;

            var critEl = document.getElementById("rkCritical");
            critEl.textContent = crit;
            critEl.className = "rk-stat-value" + (crit > 0 ? " red" : "");

            document.getElementById("rkMitigated").textContent = mitigated;
        }).catch(function(){});

        // Fetch risk matrix
        fetch("/api/v1/risks/matrix").then(function(r){return r.json();}).then(function(d){
            var matrix = d.matrix || d;
            var el = document.getElementById("rkMatrix");

            // Build 5x5 matrix
            var impacts = ["Negligible", "Minor", "Moderate", "Major", "Severe"];
            var likelihoods = ["Rare", "Unlikely", "Possible", "Likely", "Certain"];

            function cellClass(li, ii) {
                var score = (li + 1) * (ii + 1);
                if (score >= 16) return "rk-cell-critical";
                if (score >= 9) return "rk-cell-high";
                if (score >= 4) return "rk-cell-medium";
                return "rk-cell-low";
            }

            function getCount(li, ii) {
                if (Array.isArray(matrix) && matrix[li] && matrix[li][ii] !== undefined) {
                    return matrix[li][ii];
                }
                if (matrix && matrix[likelihoods[li]] && matrix[likelihoods[li]][impacts[ii]] !== undefined) {
                    return matrix[likelihoods[li]][impacts[ii]];
                }
                return 0;
            }

            var html = '<div class="rk-matrix">';
            // Header row
            html += '<div class="rk-matrix-header"></div>';
            impacts.forEach(function(imp) {
                html += '<div class="rk-matrix-header">' + imp + '</div>';
            });

            // Data rows (highest likelihood at top)
            for (var li = likelihoods.length - 1; li >= 0; li--) {
                html += '<div class="rk-matrix-label">' + likelihoods[li] + '</div>';
                for (var ii = 0; ii < impacts.length; ii++) {
                    var count = getCount(li, ii);
                    var cls = cellClass(li, ii);
                    html += '<div class="rk-matrix-cell ' + cls + '">' + count + '</div>';
                }
            }
            html += '</div>';
            el.innerHTML = html;
        }).catch(function(){
            var el = document.getElementById("rkMatrix");
            // Show empty matrix even on error
            var impacts = ["Negligible", "Minor", "Moderate", "Major", "Severe"];
            var likelihoods = ["Rare", "Unlikely", "Possible", "Likely", "Certain"];
            function cellClass(li, ii) {
                var score = (li + 1) * (ii + 1);
                if (score >= 16) return "rk-cell-critical";
                if (score >= 9) return "rk-cell-high";
                if (score >= 4) return "rk-cell-medium";
                return "rk-cell-low";
            }
            var html = '<div class="rk-matrix">';
            html += '<div class="rk-matrix-header"></div>';
            impacts.forEach(function(imp) { html += '<div class="rk-matrix-header">' + imp + '</div>'; });
            for (var li = 4; li >= 0; li--) {
                html += '<div class="rk-matrix-label">' + likelihoods[li] + '</div>';
                for (var ii = 0; ii < 5; ii++) {
                    html += '<div class="rk-matrix-cell ' + cellClass(li, ii) + '">0</div>';
                }
            }
            html += '</div>';
            el.innerHTML = html;
        });

        // Fetch top risks for table
        fetch("/api/v1/risks").then(function(r){return r.json();}).then(function(d){
            var list = Array.isArray(d) ? d : (d.risks || d.items || []);
            var body = document.getElementById("rkRisksBody");
            if (list.length === 0) {
                body.innerHTML = '<tr><td colspan="4" style="color:var(--text-muted);text-align:center;">No risks registered yet.</td></tr>';
                return;
            }
            body.innerHTML = "";
            list.slice(0, 10).forEach(function(r) {
                var tr = document.createElement("tr");
                tr.innerHTML =
                    '<td>' + (r.title || r.name || r.description || "-").substring(0, 60) + '</td>' +
                    '<td>' + (r.impact || r.impact_level || "-") + '</td>' +
                    '<td>' + (r.likelihood || r.probability || "-") + '</td>' +
                    '<td>' + (r.status || r.state || "open") + '</td>';
                body.appendChild(tr);
            });
        }).catch(function(){
            document.getElementById("rkRisksBody").innerHTML =
                '<tr><td colspan="4" style="color:var(--text-muted);text-align:center;">No risk data available.</td></tr>';
        });
    }

    document.addEventListener("tabload", function(e) {
        if (e.detail && e.detail.tab === "risk-analysis") {
            loadRisk();
        }
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
