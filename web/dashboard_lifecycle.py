#!/usr/bin/env python3
"""
Donjon Platform - License Lifecycle Tab
Shows license status warnings, upgrade prompts, trial countdown,
empty-state guidance, and feature availability matrix.
All CSS/JS inline for air-gap operation.
"""


def generate_lifecycle() -> str:
    """Return the lifecycle tab HTML as a string."""
    parts = []

    # --- Scoped styles ---
    parts.append('<style>')
    parts.append(
        '.lc-grid {'
        '  display: grid;'
        '  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));'
        '  gap: 16px;'
        '  margin-bottom: 24px;'
        '}'
        '.lc-card {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '}'
        '.lc-card-header {'
        '  font-size: 0.85rem;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  text-transform: uppercase;'
        '  letter-spacing: 0.05em;'
        '  margin-bottom: 12px;'
        '}'
        '.lc-value {'
        '  font-size: 2rem;'
        '  font-weight: 700;'
        '  font-family: var(--font-data);'
        '  color: var(--text);'
        '}'
        '.lc-value.active { color: var(--accent); }'
        '.lc-value.warning { color: var(--high); }'
        '.lc-value.expired { color: var(--critical); }'
        '.lc-sub {'
        '  font-size: 0.8rem;'
        '  color: var(--text-muted);'
        '  margin-top: 4px;'
        '}'
        '.lc-alert {'
        '  padding: 16px 20px;'
        '  border-radius: var(--radius);'
        '  margin-bottom: 16px;'
        '  display: flex;'
        '  align-items: flex-start;'
        '  gap: 12px;'
        '}'
        '.lc-alert-info {'
        '  background: rgba(59,130,246,0.1);'
        '  border: 1px solid rgba(59,130,246,0.3);'
        '  color: var(--text);'
        '}'
        '.lc-alert-warning {'
        '  background: rgba(245,158,11,0.1);'
        '  border: 1px solid rgba(245,158,11,0.3);'
        '  color: var(--text);'
        '}'
        '.lc-alert-error {'
        '  background: rgba(239,68,68,0.1);'
        '  border: 1px solid rgba(239,68,68,0.3);'
        '  color: var(--text);'
        '}'
        '.lc-alert-icon { font-size: 1.3rem; flex-shrink: 0; }'
        '.lc-alert-body { flex: 1; }'
        '.lc-alert-title {'
        '  font-weight: 600;'
        '  margin-bottom: 4px;'
        '}'
        '.lc-alert-text {'
        '  font-size: 0.85rem;'
        '  color: var(--text-muted);'
        '}'
        '.lc-progress {'
        '  width: 100%;'
        '  height: 8px;'
        '  background: var(--bg-surface-alt);'
        '  border-radius: 4px;'
        '  overflow: hidden;'
        '  margin-top: 8px;'
        '}'
        '.lc-progress-bar {'
        '  height: 100%;'
        '  border-radius: 4px;'
        '  transition: width 0.5s ease;'
        '}'
        '.lc-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.lc-table th {'
        '  text-align: left;'
        '  padding: 10px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.lc-table td {'
        '  padding: 10px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
        '.lc-badge {'
        '  display: inline-block;'
        '  padding: 2px 8px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.lc-badge-yes {'
        '  background: rgba(34,197,94,0.15);'
        '  color: #22c55e;'
        '}'
        '.lc-badge-no {'
        '  background: rgba(107,114,128,0.15);'
        '  color: #6B7280;'
        '}'
        '.lc-badge-limited {'
        '  background: rgba(245,158,11,0.15);'
        '  color: #f59e0b;'
        '}'
        '.lc-upgrade-btn {'
        '  display: inline-flex;'
        '  align-items: center;'
        '  gap: 6px;'
        '  padding: 8px 16px;'
        '  background: var(--accent);'
        '  color: #fff;'
        '  border: none;'
        '  border-radius: var(--radius);'
        '  font-size: 0.85rem;'
        '  font-weight: 600;'
        '  cursor: pointer;'
        '  transition: background 0.2s;'
        '}'
        '.lc-upgrade-btn:hover { background: var(--accent-hover); }'
        '.lc-empty {'
        '  text-align: center;'
        '  padding: 60px 20px;'
        '  color: var(--text-muted);'
        '}'
        '.lc-empty-icon {'
        '  font-size: 3rem;'
        '  margin-bottom: 16px;'
        '}'
        '.lc-empty-title {'
        '  font-size: 1.2rem;'
        '  font-weight: 600;'
        '  color: var(--text);'
        '  margin-bottom: 8px;'
        '}'
        '.lc-section {'
        '  margin-bottom: 24px;'
        '}'
        '.lc-section-title {'
        '  font-size: 1rem;'
        '  font-weight: 600;'
        '  color: var(--text);'
        '  margin-bottom: 12px;'
        '}'
        '.lc-trial-countdown {'
        '  font-size: 3rem;'
        '  font-weight: 700;'
        '  font-family: var(--font-data);'
        '  text-align: center;'
        '  padding: 20px;'
        '}'
    )
    parts.append('</style>')

    # --- HTML structure ---

    # Alert container (populated by JS)
    parts.append('<div id="lcAlerts"></div>')

    # Status cards
    parts.append('<div class="lc-grid" id="lcCards">')
    parts.append(
        '<div class="lc-card">'
        '<div class="lc-card-header">License Tier</div>'
        '<div class="lc-value active" id="lcTier">-</div>'
        '<div class="lc-sub" id="lcTierSub">Loading...</div>'
        '</div>'
    )
    parts.append(
        '<div class="lc-card">'
        '<div class="lc-card-header">Status</div>'
        '<div class="lc-value" id="lcStatus">-</div>'
        '<div class="lc-sub" id="lcStatusSub"></div>'
        '</div>'
    )
    parts.append(
        '<div class="lc-card">'
        '<div class="lc-card-header">Scanners Available</div>'
        '<div class="lc-value" id="lcScanners">-</div>'
        '<div class="lc-sub" id="lcScannersSub"></div>'
        '</div>'
    )
    parts.append(
        '<div class="lc-card">'
        '<div class="lc-card-header">Frameworks Available</div>'
        '<div class="lc-value" id="lcFrameworks">-</div>'
        '<div class="lc-sub" id="lcFrameworksSub"></div>'
        '</div>'
    )
    parts.append('</div>')

    # Start Free Trial button (shown when no trial/license active)
    parts.append(
        '<div class="lc-card" id="lcStartTrialSection" style="display:none;">'
        '<div class="lc-section-title">Try Pro Free for 14 Days</div>'
        '<p style="color:var(--text-muted);font-size:0.9rem;margin-bottom:16px;">'
        'Unlock all 19 scanners, 30 compliance frameworks, AI analysis, '
        'scheduled scans, and PDF/SARIF export. No credit card required.</p>'
        '<button class="lc-upgrade-btn" id="lcStartTrialBtn" '
        'onclick="startFreeTrial()">'
        'Start Free Trial'
        '</button>'
        '<div id="lcTrialError" style="color:var(--critical);font-size:0.85rem;'
        'margin-top:8px;display:none;"></div>'
        '</div>'
    )

    # Trial countdown section
    parts.append(
        '<div class="lc-card" id="lcTrialSection" style="display:none;">'
        '<div class="lc-card-header">Trial Remaining</div>'
        '<div class="lc-trial-countdown" id="lcTrialDays">-</div>'
        '<div class="lc-progress"><div class="lc-progress-bar" id="lcTrialBar" '
        'style="width:100%;background:var(--accent);"></div></div>'
        '<div class="lc-sub" style="text-align:center;margin-top:8px;" id="lcTrialText">'
        '</div>'
        '</div>'
    )

    # Feature matrix
    parts.append('<div class="lc-section">')
    parts.append('<div class="lc-section-title">Feature Availability by Tier</div>')
    parts.append(
        '<div class="lc-card" style="overflow-x:auto;">'
        '<table class="lc-table" id="lcFeatureMatrix">'
        '<thead><tr>'
        '<th>Feature</th>'
        '<th>Community</th>'
        '<th>Pro</th>'
        '<th>Enterprise</th>'
        '<th>Managed</th>'
        '</tr></thead>'
        '<tbody id="lcFeatureBody"></tbody>'
        '</table>'
        '</div>'
    )
    parts.append('</div>')

    # Upgrade prompt
    parts.append(
        '<div class="lc-card" id="lcUpgradeSection" style="display:none;">'
        '<div class="lc-section-title">Upgrade Your License</div>'
        '<p style="color:var(--text-muted);font-size:0.9rem;margin-bottom:16px;" '
        'id="lcUpgradeText"></p>'
        '<button class="lc-upgrade-btn" id="lcUpgradeBtn">'
        '\u2191 Upgrade Now'
        '</button>'
        '</div>'
    )

    # Empty state (shown when no data)
    parts.append(
        '<div class="lc-empty" id="lcEmpty" style="display:none;">'
        '<div class="lc-empty-icon">\u26A0</div>'
        '<div class="lc-empty-title">No License Information Available</div>'
        '<p>Start a scan or activate a license to see lifecycle data.</p>'
        '</div>'
    )

    # --- JavaScript ---
    parts.append('<script>')
    parts.append('''(function(){
    var loaded = false;

    function loadLifecycle() {
        if (loaded) return;
        loaded = true;

        // Fetch license info
        fetch("/api/v1/license").then(function(r){return r.json();}).then(function(data){
            var tier = (data.tier || data.license_tier || "community").toLowerCase();
            var status = data.status || "active";

            // Update cards
            document.getElementById("lcTier").textContent = tier.charAt(0).toUpperCase() + tier.slice(1);
            document.getElementById("lcTierSub").textContent = tierDescription(tier);
            document.getElementById("lcStatus").textContent = status.charAt(0).toUpperCase() + status.slice(1);
            document.getElementById("lcStatus").className = "lc-value " + (status === "active" ? "active" : status === "expired" ? "expired" : "");

            // Alerts based on tier
            var alerts = document.getElementById("lcAlerts");
            alerts.innerHTML = "";

            if (tier === "community") {
                alerts.innerHTML +=
                    '<div class="lc-alert lc-alert-info">' +
                    '<span class="lc-alert-icon">\u2139</span>' +
                    '<div class="lc-alert-body">' +
                    '<div class="lc-alert-title">Community Edition</div>' +
                    '<div class="lc-alert-text">You have access to 7 core scanners and 3 compliance frameworks. Upgrade to Pro for advanced scanners, all 30 frameworks, and scheduled scans.</div>' +
                    '</div></div>';
                document.getElementById("lcUpgradeSection").style.display = "";
                document.getElementById("lcUpgradeText").textContent = "Unlock 10 additional scanners, 27 more compliance frameworks, PDF/SARIF export, AI analysis, and scheduled scans.";
            }

            if (status === "expired") {
                alerts.innerHTML +=
                    '<div class="lc-alert lc-alert-error">' +
                    '<span class="lc-alert-icon">\u26D4</span>' +
                    '<div class="lc-alert-body">' +
                    '<div class="lc-alert-title">License Expired</div>' +
                    '<div class="lc-alert-text">Your license has expired. Features have been downgraded to Community tier. Contact sales@donjonsec.com to renew, or use tools/license-refresh.py to import a new license file offline.</div>' +
                    '</div></div>';
            }

            // License expiry renewal notifications
            var licInfo = data.license || {};
            var expiresStr = licInfo.expires || "";
            if (expiresStr && status !== "expired") {
                var expiryDate = new Date(expiresStr.replace("Z", "+00:00"));
                var nowMs = Date.now();
                var daysLeft = Math.ceil((expiryDate.getTime() - nowMs) / 86400000);
                if (daysLeft <= 0) {
                    alerts.innerHTML +=
                        '<div class="lc-alert lc-alert-error">' +
                        '<span class="lc-alert-icon">\u26D4</span>' +
                        '<div class="lc-alert-body">' +
                        '<div class="lc-alert-title">License Expired</div>' +
                        '<div class="lc-alert-text">Your license expired ' + Math.abs(daysLeft) + ' day(s) ago. Features have been downgraded to Community tier. Contact sales@donjonsec.com to renew, or use tools/license-refresh.py for offline renewal.</div>' +
                        '</div></div>';
                } else if (daysLeft <= 7) {
                    alerts.innerHTML +=
                        '<div class="lc-alert lc-alert-error">' +
                        '<span class="lc-alert-icon">\u26A0</span>' +
                        '<div class="lc-alert-body">' +
                        '<div class="lc-alert-title">License Expires in ' + daysLeft + ' Day' + (daysLeft === 1 ? '' : 's') + '</div>' +
                        '<div class="lc-alert-text">Your ' + tier + ' license expires on ' + expiryDate.toLocaleDateString() + '. Contact sales@donjonsec.com to renew before access is downgraded to Community tier.</div>' +
                        '</div></div>';
                } else if (daysLeft <= 14) {
                    alerts.innerHTML +=
                        '<div class="lc-alert lc-alert-warning">' +
                        '<span class="lc-alert-icon">\u26A0</span>' +
                        '<div class="lc-alert-body">' +
                        '<div class="lc-alert-title">License Expires in ' + daysLeft + ' Days</div>' +
                        '<div class="lc-alert-text">Your ' + tier + ' license expires on ' + expiryDate.toLocaleDateString() + '. Plan your renewal to avoid service interruption.</div>' +
                        '</div></div>';
                } else if (daysLeft <= 30) {
                    alerts.innerHTML +=
                        '<div class="lc-alert lc-alert-info">' +
                        '<span class="lc-alert-icon">\u2139</span>' +
                        '<div class="lc-alert-body">' +
                        '<div class="lc-alert-title">License Expires in ' + daysLeft + ' Days</div>' +
                        '<div class="lc-alert-text">Your ' + tier + ' license expires on ' + expiryDate.toLocaleDateString() + '. Renewal reminders will increase as the date approaches.</div>' +
                        '</div></div>';
                }
            }

            // Scanner count based on tier
            var scannerCounts = {community: 7, pro: 19, enterprise: 19, managed: 19};
            var frameworkCounts = {community: 3, pro: 30, enterprise: 30, managed: 30};
            document.getElementById("lcScanners").textContent = scannerCounts[tier] || 7;
            document.getElementById("lcScannersSub").textContent = tier === "community" ? "7 core scanners" : "All 19 scanners";
            document.getElementById("lcFrameworks").textContent = frameworkCounts[tier] || 3;
            document.getElementById("lcFrameworksSub").textContent = tier === "community" ? "3 basic frameworks" : "All 30 frameworks";

            // Feature matrix
            populateFeatureMatrix(tier);
        }).catch(function(){
            document.getElementById("lcEmpty").style.display = "";
        });

        // Check trial status
        fetch("/api/v1/license/trial/status").then(function(r){return r.json();}).then(function(data){
            if (data.active || data.trial_active) {
                var section = document.getElementById("lcTrialSection");
                section.style.display = "";
                document.getElementById("lcStartTrialSection").style.display = "none";
                var days = data.days_remaining || data.remaining_days || 0;
                document.getElementById("lcTrialDays").textContent = days + " days";
                document.getElementById("lcTrialText").textContent = "Trial expires: " + (data.expires || data.expiry || "");
                var pct = Math.max(0, Math.min(100, (days / 14) * 100));
                var bar = document.getElementById("lcTrialBar");
                bar.style.width = pct + "%";
                bar.style.background = days <= 3 ? "var(--critical)" : days <= 7 ? "var(--high)" : "var(--accent)";

                if (days <= 3) {
                    var alerts = document.getElementById("lcAlerts");
                    alerts.innerHTML +=
                        '<div class="lc-alert lc-alert-warning">' +
                        '<span class="lc-alert-icon">\u23F3</span>' +
                        '<div class="lc-alert-body">' +
                        '<div class="lc-alert-title">Trial Expiring Soon</div>' +
                        '<div class="lc-alert-text">' + days + ' days remaining on your Pro trial. Upgrade to keep advanced features.</div>' +
                        '</div></div>';
                }
            } else if (data.trial_available && tier === "community") {
                document.getElementById("lcStartTrialSection").style.display = "";
            }
        }).catch(function(){});
    }

    function tierDescription(tier) {
        var desc = {
            community: "Free \u2014 core scanners, basic compliance, CSV/JSON export",
            pro: "Professional \u2014 all scanners, all frameworks, AI analysis",
            enterprise: "Enterprise \u2014 SSO, RBAC, multi-tenant, audit trail",
            managed: "Managed (MSSP) \u2014 client management, bulk scanning, white label"
        };
        return desc[tier] || tier;
    }

    function populateFeatureMatrix(currentTier) {
        var features = [
            ["Core Scanners (7)", "yes", "yes", "yes", "yes"],
            ["Advanced Scanners (10)", "no", "yes", "yes", "yes"],
            ["All Scan Depths", "limited", "yes", "yes", "yes"],
            ["Targets per Scan", "limited", "yes", "yes", "yes"],
            ["CSV/JSON Export", "yes", "yes", "yes", "yes"],
            ["PDF/SARIF/XML Export", "no", "yes", "yes", "yes"],
            ["Compliance Frameworks", "limited", "yes", "yes", "yes"],
            ["AI Analysis", "limited", "yes", "yes", "yes"],
            ["Scheduled Scans", "no", "yes", "yes", "yes"],
            ["SSO / SAML", "no", "no", "yes", "yes"],
            ["RBAC", "no", "no", "yes", "yes"],
            ["Multi-Tenant", "no", "no", "yes", "yes"],
            ["Audit Trail", "no", "no", "yes", "yes"],
            ["MSSP Client Mgmt", "no", "no", "no", "yes"],
            ["Bulk Orchestration", "no", "no", "no", "yes"],
            ["White Label", "no", "no", "no", "yes"],
            ["Cross-Client Reporting", "no", "no", "no", "yes"]
        ];

        var tiers = ["community", "pro", "enterprise", "managed"];
        var currentIdx = tiers.indexOf(currentTier);
        var body = document.getElementById("lcFeatureBody");
        body.innerHTML = "";

        features.forEach(function(row) {
            var tr = document.createElement("tr");
            var td0 = document.createElement("td");
            td0.textContent = row[0];
            td0.style.fontWeight = "500";
            tr.appendChild(td0);

            for (var i = 1; i <= 4; i++) {
                var td = document.createElement("td");
                var val = row[i];
                var badge = document.createElement("span");
                badge.className = "lc-badge lc-badge-" + val;
                badge.textContent = val === "yes" ? "\u2713" : val === "no" ? "\u2014" : "\u25CF";
                td.appendChild(badge);

                if (i - 1 === currentIdx) {
                    td.style.background = "rgba(99,102,241,0.08)";
                }
                tr.appendChild(td);
            }
            body.appendChild(tr);
        });
    }

    document.addEventListener("tabload", function(e) {
        if (e.detail && e.detail.tab === "lifecycle") {
            loadLifecycle();
        }
    });
})();

function startFreeTrial() {
    var btn = document.getElementById("lcStartTrialBtn");
    var errDiv = document.getElementById("lcTrialError");
    btn.disabled = true;
    btn.textContent = "Activating...";
    errDiv.style.display = "none";

    fetch("/api/v1/license/trial", {method: "POST", headers: {"Content-Type": "application/json"}})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.activated) {
                btn.textContent = "Trial Activated!";
                document.getElementById("lcStartTrialSection").style.display = "none";
                // Reload the lifecycle tab to show countdown
                var evt = new CustomEvent("tabload", {detail: {tab: "lifecycle"}});
                document.dispatchEvent(evt);
            } else {
                btn.disabled = false;
                btn.textContent = "Start Free Trial";
                errDiv.textContent = data.error || "Failed to activate trial";
                errDiv.style.display = "";
            }
        })
        .catch(function(e) {
            btn.disabled = false;
            btn.textContent = "Start Free Trial";
            errDiv.textContent = "Network error: " + e.message;
            errDiv.style.display = "";
        });
}''')
    parts.append('</script>')

    return ''.join(parts)
