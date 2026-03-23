#!/usr/bin/env python3
"""
Donjon Platform - Scan Center Tab
Returns HTML section for scanner selection, target input, scan execution,
active scan progress, and results table.
All CSS/JS inline for air-gap operation.
"""


def generate_scan_center() -> str:
    """Return the scan center tab HTML as a string."""
    parts = []

    # --- Scoped styles ---
    parts.append('<style>')
    parts.append(
        '.sc-grid {'
        '  display: grid;'
        '  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));'
        '  gap: 12px;'
        '  margin-bottom: 20px;'
        '}'
        '.sc-card {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 16px;'
        '  cursor: pointer;'
        '  transition: border-color 0.2s, box-shadow 0.2s;'
        '  position: relative;'
        '}'
        '.sc-card:hover { border-color: var(--accent); }'
        '.sc-card.selected {'
        '  border-color: var(--accent);'
        '  box-shadow: 0 0 0 2px var(--accent);'
        '}'
        '.sc-card.locked {'
        '  opacity: 0.5;'
        '  cursor: not-allowed;'
        '}'
        '.sc-card.locked:hover { border-color: var(--border); }'
        '.sc-lock {'
        '  position: absolute;'
        '  top: 10px; right: 10px;'
        '  font-size: 1rem;'
        '  color: var(--text-muted);'
        '}'
        '.sc-card-check {'
        '  margin-right: 8px;'
        '  accent-color: var(--accent);'
        '  width: 16px; height: 16px;'
        '  vertical-align: middle;'
        '}'
        '.sc-card-name {'
        '  font-weight: 600;'
        '  font-size: 0.95rem;'
        '  display: inline;'
        '  vertical-align: middle;'
        '}'
        '.sc-card-desc {'
        '  font-size: 0.8rem;'
        '  color: var(--text-muted);'
        '  margin-top: 8px;'
        '  line-height: 1.4;'
        '}'
    )

    parts.append(
        '.sc-section {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '  margin-bottom: 20px;'
        '}'
        '.sc-section-title {'
        '  font-size: 1rem;'
        '  font-weight: 700;'
        '  margin-bottom: 12px;'
        '}'
        '.sc-textarea {'
        '  width: 100%;'
        '  min-height: 80px;'
        '  background: var(--bg-body);'
        '  color: var(--text);'
        '  border: 1px solid var(--border);'
        '  border-radius: 6px;'
        '  padding: 10px;'
        '  font-family: var(--font-data);'
        '  font-size: 0.85rem;'
        '  resize: vertical;'
        '}'
        '.sc-textarea:focus {'
        '  outline: none;'
        '  border-color: var(--accent);'
        '}'
    )

    parts.append(
        '.sc-btn {'
        '  background: var(--accent);'
        '  color: #fff;'
        '  border: none;'
        '  border-radius: 6px;'
        '  padding: 10px 20px;'
        '  font-size: 0.9rem;'
        '  font-weight: 600;'
        '  cursor: pointer;'
        '  font-family: var(--font-ui);'
        '  transition: background 0.2s;'
        '}'
        '.sc-btn:hover { background: var(--accent-hover); }'
        '.sc-btn:disabled {'
        '  opacity: 0.5;'
        '  cursor: not-allowed;'
        '}'
        '.sc-btn-secondary {'
        '  background: var(--bg-surface-alt);'
        '  color: var(--text);'
        '  border: 1px solid var(--border);'
        '}'
        '.sc-btn-secondary:hover { background: var(--border); }'
        '.sc-btn-row {'
        '  display: flex;'
        '  gap: 10px;'
        '  align-items: center;'
        '  margin-top: 12px;'
        '}'
    )

    # Depth selector
    parts.append(
        '.sc-depth-group {'
        '  display: flex;'
        '  gap: 16px;'
        '  margin-top: 8px;'
        '}'
        '.sc-depth-opt {'
        '  display: flex;'
        '  align-items: center;'
        '  gap: 6px;'
        '  cursor: pointer;'
        '  font-size: 0.9rem;'
        '}'
        '.sc-depth-opt input { accent-color: var(--accent); }'
        '.sc-depth-label { font-size: 0.75rem; color: var(--text-muted); }'
    )

    # Progress bars
    parts.append(
        '.sc-progress-list { list-style:none; }'
        '.sc-progress-item { padding:12px 0; border-bottom:1px solid var(--border); }'
        '.sc-progress-item:last-child { border-bottom:none; }'
        '.sc-progress-header { display:flex; justify-content:space-between;'
        ' margin-bottom:6px; font-size:0.85rem; }'
        '.sc-progress-bar { height:6px; background:var(--border);'
        ' border-radius:3px; overflow:hidden; }'
        '.sc-progress-fill { height:100%; background:var(--accent);'
        ' border-radius:3px; transition:width 0.5s ease; }'
        '.sc-empty { text-align:center; padding:24px;'
        ' color:var(--text-muted); font-size:0.9rem; }'
    )

    # Results table
    parts.append(
        '.sc-table-wrap { overflow-x:auto; }'
        '.sc-table { width:100%; border-collapse:collapse; font-size:0.85rem; }'
        '.sc-table th { text-align:left; padding:10px 12px;'
        ' border-bottom:2px solid var(--border); color:var(--text-muted);'
        ' font-weight:600; text-transform:uppercase; font-size:0.75rem;'
        ' letter-spacing:0.5px; }'
        '.sc-table td { padding:10px 12px; border-bottom:1px solid var(--border); }'
        '.sc-table tr:hover { background:var(--bg-surface-alt); }'
    )

    # Severity badges (WCAG AA: icon + text label)
    parts.append(
        '.sev-badge { display:inline-flex; align-items:center; gap:4px;'
        ' padding:2px 10px; border-radius:12px; font-size:0.75rem;'
        ' font-weight:700; text-transform:uppercase; }'
        '.sev-critical { background:rgba(239,68,68,0.15); color:#FCA5A5; }'
        '.sev-high { background:rgba(249,115,22,0.15); color:#FDBA74; }'
        '.sev-medium { background:rgba(234,179,8,0.15); color:#FDE047; }'
        '.sev-low { background:rgba(34,197,94,0.15); color:#86EFAC; }'
        '.sev-info { background:rgba(59,130,246,0.15); color:#93C5FD; }'
    )

    parts.append('</style>')

    # --- HTML Structure ---
    parts.append('<div id="sc-root">')

    # Scanner selection
    parts.append(
        '<div class="sc-section">'
        '<div class="sc-section-title">Select Scanners</div>'
        '<div class="sc-grid" id="scScannerGrid">'
        '<div class="sc-empty">Loading scanners\u2026</div>'
        '</div>'
        '</div>'
    )

    # Target input
    parts.append(
        '<div class="sc-section">'
        '<div class="sc-section-title">Targets</div>'
        '<textarea class="sc-textarea" id="scTargets" '
        'placeholder="Enter IPs, CIDRs, or hostnames (one per line)"></textarea>'
        '<div class="sc-btn-row">'
        '<button class="sc-btn sc-btn-secondary" id="scAutoDetect">'
        '\u2316 Auto-Detect Local Network'
        '</button>'
        '</div>'
        '</div>'
    )

    # Depth selector
    parts.append(
        '<div class="sc-section">'
        '<div class="sc-section-title">Scan Depth</div>'
        '<div class="sc-depth-group">'
    )
    depths = [
        ("quick",    "Quick",    "Port scan + service ID (~2 min)"),
        ("standard", "Standard", "Vuln scan + enumeration (~15 min)"),
        ("deep",     "Deep",     "Full audit + exploit check (~60 min)"),
    ]
    for value, label, desc in depths:
        checked = ' checked' if value == 'standard' else ''
        parts.append(
            '<label class="sc-depth-opt">'
            '<input type="radio" name="scanDepth" value="' + value + '"'
            + checked + '/>'
            '<span>' + label + '</span>'
            '<span class="sc-depth-label">(' + desc + ')</span>'
            '</label>'
        )
    parts.append(
        '</div>'
        '</div>'
    )

    # Start scan button
    parts.append(
        '<div class="sc-btn-row" style="margin-bottom:20px;">'
        '<button class="sc-btn" id="scStartBtn">'
        '\u25B6 Start Scan'
        '</button>'
        '</div>'
    )

    # Active scans
    parts.append(
        '<div class="sc-section">'
        '<div class="sc-section-title">Active Scans</div>'
        '<ul class="sc-progress-list" id="scActiveList">'
        '<li class="sc-empty">No active scans</li>'
        '</ul>'
        '</div>'
    )

    # Results table
    parts.append(
        '<div class="sc-section">'
        '<div class="sc-section-title">Results</div>'
        '<div class="sc-table-wrap">'
        '<table class="sc-table">'
        '<thead><tr>'
        '<th>Severity</th>'
        '<th>Finding</th>'
        '<th>Target</th>'
        '<th>Scanner</th>'
        '<th>Time</th>'
        '</tr></thead>'
        '<tbody id="scResultsBody">'
        '<tr><td colspan="5" class="sc-empty">No results yet</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
        '</div>'
    )

    parts.append('</div>')

    # --- JavaScript ---
    parts.append('<script>')
    parts.append(
        '(function(){'
        'var SEV_MAP={'
        '  "critical":{cls:"sev-critical",icon:"\\u26D4",label:"Critical"},'
        '  "high":{cls:"sev-high",icon:"\\u26A0",label:"High"},'
        '  "medium":{cls:"sev-medium",icon:"\\u25C6",label:"Medium"},'
        '  "low":{cls:"sev-low",icon:"\\u2139",label:"Low"},'
        '  "info":{cls:"sev-info",icon:"\\u24D8",label:"Info"}'
        '};'
    )

    # Load scanners
    parts.append(
        'function loadScanners(){'
        '  fetchAPI("/scanners").then(function(data){'
        '    var grid=document.getElementById("scScannerGrid");'
        '    grid.innerHTML="";'
        '    var scanners=data.scanners||data||[];'
        '    scanners.forEach(function(s){'
        '      var locked=s.min_tier&&s.min_tier!=="community"'
        '        &&s.min_tier!=="pro";'
        '      var div=document.createElement("div");'
        '      div.className="sc-card"+(locked?" locked":"");'
        '      div.setAttribute("data-scanner-id",s.id);'
        '      var inner="";'
        '      if(locked){inner+=\'<span class="sc-lock">\\u26BF Pro+</span>\';}'
        '      inner+=\'<input type="checkbox" class="sc-card-check"\';'
        '      if(locked){inner+=" disabled";}'
        '      inner+="/>";'
        '      inner+=\'<span class="sc-card-name">\'+esc(s.name)+\'</span>\';'
        '      inner+=\'<div class="sc-card-desc">\'+esc(s.description||"")+\'</div>\';'
        '      div.innerHTML=inner;'
        '      if(!locked){'
        '        div.addEventListener("click",function(e){'
        '          if(e.target.tagName==="INPUT")return;'
        '          var cb=div.querySelector("input");'
        '          cb.checked=!cb.checked;'
        '          div.classList.toggle("selected",cb.checked);'
        '        });'
        '        var cb=div.querySelector("input");'
        '        cb.addEventListener("change",function(){'
        '          div.classList.toggle("selected",cb.checked);'
        '        });'
        '      }'
        '      grid.appendChild(div);'
        '    });'
        '  }).catch(function(){'
        '    document.getElementById("scScannerGrid").innerHTML='
        '      \'<div class="sc-empty">Failed to load scanners</div>\';'
        '  });'
        '}'
    )

    # Auto-detect local network
    parts.append(
        'document.getElementById("scAutoDetect").addEventListener("click",function(){'
        '  var btn=this;'
        '  btn.disabled=true;'
        '  btn.textContent="Detecting\\u2026";'
        '  fetchAPI("/network/local").then(function(data){'
        '    var targets=data.suggested_targets||data.targets||data.subnets||[];'
        '    var ta=document.getElementById("scTargets");'
        '    ta.value=targets.join("\\n");'
        '    btn.disabled=false;'
        '    btn.textContent="\\u2316 Auto-Detect Local Network";'
        '    if(targets.length===0){'
        '      showToast&&showToast("No local networks detected","warning");'
        '    }else{'
        '      showToast&&showToast("Found "+targets.length+" targets","success");'
        '    }'
        '  }).catch(function(err){'
        '    showToast&&showToast("Network detection failed: "+err,"error");'
        '    btn.disabled=false;'
        '    btn.textContent="\\u2316 Auto-Detect Local Network";'
        '  });'
        '});'
    )

    # Start scan
    parts.append(
        'document.getElementById("scStartBtn").addEventListener("click",function(){'
        '  var checks=document.querySelectorAll(".sc-card-check:checked");'
        '  var scannerIds=[];'
        '  checks.forEach(function(cb){'
        '    scannerIds.push(cb.closest(".sc-card").getAttribute("data-scanner-id"));'
        '  });'
        '  if(scannerIds.length===0){alert("Select at least one scanner.");return;}'
        '  var targets=document.getElementById("scTargets").value.trim();'
        '  if(!targets){alert("Enter at least one target.");return;}'
        '  var depth=document.querySelector("input[name=scanDepth]:checked").value;'
        '  var btn=this;'
        '  btn.disabled=true;'
        '  btn.textContent="Starting\\u2026";'
        '  showToast&&showToast("Starting scan with "+scannerIds.length+" scanner(s)...","info");'
        '  fetchAPI("/scans",{method:"POST",body:{'
        '    scanner_ids:scannerIds,'
        '    targets:targets.split("\\n").map(function(t){return t.trim();}).filter(Boolean),'
        '    depth:depth'
        '  }}).then(function(data){'
        '    btn.disabled=false;'
        '    btn.textContent="\\u25B6 Start Scan";'
        '    showToast&&showToast("Scan started: "+(data.session_id||""),"success");'
        '    startScanPolling();'
        '  }).catch(function(e){'
        '    btn.disabled=false;'
        '    btn.textContent="\\u25B6 Start Scan";'
        '    showToast&&showToast("Scan failed: "+e.message,"error");'
        '  });'
        '});'
    )

    # Scan polling — updates active scans + results every 3s while running
    parts.append(
        'var _scanPollTimer=null;'
        'function startScanPolling(){'
        '  if(_scanPollTimer)clearInterval(_scanPollTimer);'
        '  loadActiveScans();'
        '  _scanPollTimer=setInterval(function(){'
        '    loadActiveScans();'
        '    loadResults();'
        '  },3000);'
        '}'
        'function stopScanPolling(){'
        '  if(_scanPollTimer){clearInterval(_scanPollTimer);_scanPollTimer=null;}'
        '}'
    )

    # Load active scans
    parts.append(
        'function loadActiveScans(){'
        '  fetchAPI("/scans?status=running").then(function(data){'
        '    var list=document.getElementById("scActiveList");'
        '    var scans=data.scans||data||[];'
        '    if(scans.length===0){'
        '      list.innerHTML=\'<li class="sc-empty">No active scans</li>\';'
        '      stopScanPolling();'
        '      loadResults();'
        '      return;'
        '    }'
        '    list.innerHTML="";'
        '    scans.forEach(function(s){'
        '      var pct=Math.round(s.progress||0);'
        '      var li=document.createElement("li");'
        '      li.className="sc-progress-item";'
        '      li.innerHTML='
        '        \'<div class="sc-progress-header">\'+'
        '        \'<span>\'+esc(s.name||s.id)+\'</span>\'+'
        '        \'<span>\'+pct+\'%</span>\'+'
        '        \'</div>\'+'
        '        \'<div class="sc-progress-bar">\'+'
        '        \'<div class="sc-progress-fill" style="width:\'+pct+\'%"></div>\'+'
        '        \'</div>\';'
        '      list.appendChild(li);'
        '    });'
        '  }).catch(function(){});'
        '}'
    )

    # Load results
    parts.append(
        'function loadResults(){'
        '  fetchAPI("/scans?status=completed&limit=50").then(function(data){'
        '    var tbody=document.getElementById("scResultsBody");'
        '    var findings=data.findings||data.results||[];'
        '    if(findings.length===0){'
        '      tbody.innerHTML=\'<tr><td colspan="5" class="sc-empty">No results yet</td></tr>\';'
        '      return;'
        '    }'
        '    tbody.innerHTML="";'
        '    findings.forEach(function(f){'
        '      var sev=SEV_MAP[f.severity]||SEV_MAP["info"];'
        '      var tr=document.createElement("tr");'
        '      tr.innerHTML='
        '        \'<td><span class="sev-badge \'+sev.cls+\'">\'+sev.icon+" "+sev.label+\'</span></td>\'+'
        '        \'<td>\'+esc(f.title||f.finding||"")+\'</td>\'+'
        '        \'<td style="font-family:var(--font-data)">\'+esc(f.target||"")+\'</td>\'+'
        '        \'<td>\'+esc(f.scanner||"")+\'</td>\'+'
        '        \'<td>\'+esc(f.timestamp||f.time||"")+\'</td>\';'
        '      tbody.appendChild(tr);'
        '    });'
        '  }).catch(function(){});'
        '}'
    )

    # Escape helper
    parts.append(
        'function esc(s){'
        '  var d=document.createElement("div");'
        '  d.appendChild(document.createTextNode(s));'
        '  return d.innerHTML;'
        '}'
    )

    # Tab load listener + polling
    parts.append(
        'document.addEventListener("tabload",function(e){'
        '  if(e.detail.tab==="scan-center"){'
        '    loadScanners();'
        '    loadActiveScans();'
        '    loadResults();'
        '  }'
        '});'
    )

    # Poll active scans every 5s when tab is visible
    parts.append(
        'var pollTimer=null;'
        'document.addEventListener("tabload",function(e){'
        '  if(e.detail.tab==="scan-center"){'
        '    if(pollTimer)clearInterval(pollTimer);'
        '    pollTimer=setInterval(function(){'
        '      var pane=document.getElementById("tab-scan-center");'
        '      if(pane&&pane.classList.contains("active")){'
        '        loadActiveScans();'
        '        loadResults();'
        '      }else{clearInterval(pollTimer);pollTimer=null;}'
        '    },5000);'
        '  }'
        '});'
    )

    parts.append('})();')
    parts.append('</script>')

    return ''.join(parts)
