#!/usr/bin/env python3
"""
Donjon Platform - Schedules Tab (HTML)
Fetches scan schedules from API and renders schedule list
with create/delete capabilities.
All CSS/JS inline for air-gap operation.
"""


def generate_schedules_html() -> str:
    """Return the schedules tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.sc-toolbar {'
        '  display: flex;'
        '  align-items: center;'
        '  justify-content: space-between;'
        '  margin-bottom: 16px;'
        '}'
        '.sc-btn {'
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
        '}'
        '.sc-btn:hover { background: var(--accent-hover); }'
        '.sc-btn-danger {'
        '  background: var(--critical);'
        '}'
        '.sc-btn-danger:hover { background: #dc2626; }'
        '.sc-btn-sm {'
        '  padding: 4px 10px;'
        '  font-size: 0.78rem;'
        '}'
        '.sc-card {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  margin-bottom: 16px;'
        '}'
        '.sc-card-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  color: var(--text);'
        '  margin-bottom: 16px;'
        '}'
        '.sc-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.sc-table th {'
        '  text-align: left;'
        '  padding: 8px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.sc-table td {'
        '  padding: 8px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
        '.sc-badge {'
        '  display: inline-block;'
        '  padding: 2px 8px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '}'
        '.sc-badge-active { background: rgba(34,197,94,0.15); color: #22c55e; }'
        '.sc-badge-paused { background: rgba(234,179,8,0.15); color: #eab308; }'
        '.sc-badge-disabled { background: rgba(107,114,128,0.15); color: #6B7280; }'
        '.sc-form {'
        '  display: none;'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--accent);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  margin-bottom: 16px;'
        '}'
        '.sc-form.open { display: block; }'
        '.sc-form-row {'
        '  display: flex;'
        '  gap: 12px;'
        '  margin-bottom: 12px;'
        '  flex-wrap: wrap;'
        '}'
        '.sc-form-group {'
        '  display: flex;'
        '  flex-direction: column;'
        '  gap: 4px;'
        '  flex: 1;'
        '  min-width: 160px;'
        '}'
        '.sc-form-group label {'
        '  font-size: 0.78rem;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  text-transform: uppercase;'
        '}'
        '.sc-input {'
        '  background: var(--bg-body);'
        '  border: 1px solid var(--border);'
        '  border-radius: 6px;'
        '  padding: 8px 12px;'
        '  color: var(--text);'
        '  font-size: 0.85rem;'
        '  font-family: var(--font-ui);'
        '}'
        '.sc-input:focus { outline: none; border-color: var(--accent); }'
    )
    parts.append('</style>')

    # Toolbar
    parts.append(
        '<div class="sc-toolbar">'
        '<div style="font-size:0.85rem;color:var(--text-muted);">'
        '<span id="scCount">0</span> schedules configured'
        '</div>'
        '<button class="sc-btn" id="scNewBtn">+ New Schedule</button>'
        '</div>'
    )

    # Create form (hidden by default)
    parts.append(
        '<div class="sc-form" id="scForm">'
        '<div class="sc-card-title">Create Schedule</div>'
        '<div class="sc-form-row">'
        '<div class="sc-form-group">'
        '<label>Name</label>'
        '<input class="sc-input" id="scFName" placeholder="Weekly full scan" />'
        '</div>'
        '<div class="sc-form-group">'
        '<label>Target</label>'
        '<input class="sc-input" id="scFTarget" placeholder="192.168.1.0/24" />'
        '</div>'
        '</div>'
        '<div class="sc-form-row">'
        '<div class="sc-form-group">'
        '<label>Frequency</label>'
        '<select class="sc-input" id="scFFreq">'
        '<option value="daily">Daily</option>'
        '<option value="weekly" selected>Weekly</option>'
        '<option value="monthly">Monthly</option>'
        '<option value="quarterly">Quarterly</option>'
        '</select>'
        '</div>'
        '<div class="sc-form-group">'
        '<label>Scanner</label>'
        '<input class="sc-input" id="scFScanner" placeholder="nmap" />'
        '</div>'
        '</div>'
        '<div style="display:flex;gap:8px;">'
        '<button class="sc-btn" id="scFSubmit">Create</button>'
        '<button class="sc-btn sc-btn-danger" id="scFCancel">Cancel</button>'
        '</div>'
        '</div>'
    )

    # Schedule list
    parts.append(
        '<div class="sc-card">'
        '<div class="sc-card-title">Scan Schedules</div>'
        '<table class="sc-table">'
        '<thead><tr>'
        '<th>Name</th><th>Target</th><th>Frequency</th><th>Next Run</th><th>Status</th><th>Actions</th>'
        '</tr></thead>'
        '<tbody id="scBody">'
        '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
    )

    # JavaScript
    parts.append('<script>')
    parts.append('''(function(){
    var loaded = false;

    function statusBadge(s) {
        var st = (s || "active").toLowerCase();
        var cls = st === "active" ? "sc-badge-active" : st === "paused" ? "sc-badge-paused" : "sc-badge-disabled";
        return '<span class="sc-badge ' + cls + '">' + st.toUpperCase() + '</span>';
    }

    function loadSchedules() {
        fetch("/api/v1/schedules").then(function(r){return r.json();}).then(function(d){
            var list = Array.isArray(d) ? d : (d.schedules || d.items || []);
            document.getElementById("scCount").textContent = list.length;
            var body = document.getElementById("scBody");
            if (list.length === 0) {
                body.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">No schedules configured. Click + New Schedule to create one.</td></tr>';
                return;
            }
            body.innerHTML = "";
            list.forEach(function(s) {
                var tr = document.createElement("tr");
                var sid = s.id || s.schedule_id || "";
                tr.innerHTML =
                    '<td>' + (s.name || s.title || "-") + '</td>' +
                    '<td style="font-family:var(--font-data);font-size:0.82rem;">' + (s.target || s.targets || "-") + '</td>' +
                    '<td>' + (s.frequency || s.interval || s.cron || "-") + '</td>' +
                    '<td style="font-family:var(--font-data);font-size:0.82rem;">' + (s.next_run || s.next_execution || "-") + '</td>' +
                    '<td>' + statusBadge(s.status || s.state) + '</td>' +
                    '<td><button class="sc-btn sc-btn-danger sc-btn-sm" data-del="' + sid + '">Delete</button></td>';
                body.appendChild(tr);
            });

            // Bind delete buttons
            body.querySelectorAll("[data-del]").forEach(function(btn) {
                btn.addEventListener("click", function() {
                    var id = btn.getAttribute("data-del");
                    if (!id) return;
                    if (!confirm("Delete this schedule?")) return;
                    fetch("/api/v1/schedules/" + id, {method: "DELETE"}).then(function(){
                        loadSchedules();
                    }).catch(function(){
                        alert("Failed to delete schedule.");
                    });
                });
            });
        }).catch(function(){
            document.getElementById("scBody").innerHTML =
                '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;">No schedules configured. Click + New Schedule to create one.</td></tr>';
        });
    }

    function init() {
        if (loaded) return;
        loaded = true;

        loadSchedules();

        // Toggle form
        var form = document.getElementById("scForm");
        document.getElementById("scNewBtn").addEventListener("click", function() {
            form.classList.toggle("open");
        });
        document.getElementById("scFCancel").addEventListener("click", function() {
            form.classList.remove("open");
        });

        // Submit new schedule
        document.getElementById("scFSubmit").addEventListener("click", function() {
            var name = document.getElementById("scFName").value.trim();
            var target = document.getElementById("scFTarget").value.trim();
            var freq = document.getElementById("scFFreq").value;
            var scanner = document.getElementById("scFScanner").value.trim() || "nmap";
            if (!name || !target) { alert("Name and target are required."); return; }

            fetch("/api/v1/schedules", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({name: name, target: target, frequency: freq, scanner: scanner})
            }).then(function(r){
                if (!r.ok) throw new Error("API " + r.status);
                return r.json();
            }).then(function(){
                form.classList.remove("open");
                document.getElementById("scFName").value = "";
                document.getElementById("scFTarget").value = "";
                document.getElementById("scFScanner").value = "";
                loadSchedules();
            }).catch(function(){
                alert("Failed to create schedule.");
            });
        });
    }

    document.addEventListener("tabload", function(e) {
        if (e.detail && e.detail.tab === "schedules") {
            init();
        }
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
