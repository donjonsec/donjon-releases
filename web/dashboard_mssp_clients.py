#!/usr/bin/env python3
"""Donjon Platform - MSSP Client Portfolio Dashboard.
Self-contained HTML view for Managed-tier MSSP client management.
All CSS/JS inline for air-gapped operation.
"""


def generate_mssp_clients() -> str:
    """Return complete HTML string for the MSSP client portfolio view."""
    # -- CSS block --
    css = (
        "*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }"
        "\n:root {"
        "\n  --bg: #111827; --surface: #1F2937; --surface-alt: #283548;"
        "\n  --text: #F9FAFB; --text-muted: #9CA3AF; --accent: #6366F1;"
        "\n  --accent-hover: #818CF8; --accent-dim: #4F46E5;"
        "\n  --border: #374151; --radius: 8px;"
        "\n  --critical: #EF4444; --high: #F97316; --medium: #EAB308;"
        "\n  --low: #22C55E; --info: #3B82F6;"
        "\n  --active: #22C55E; --suspended: #F97316; --archived: #6B7280;"
        "\n  --font-ui: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;"
        "\n  --font-data: 'Consolas', 'Courier New', monospace;"
        "\n  --shadow: 0 2px 12px rgba(0,0,0,0.4);"
        "\n}"
        "\nhtml { font-size: 14px; }"
        "\nbody {"
        "\n  font-family: var(--font-ui); background: var(--bg);"
        "\n  color: var(--text); line-height: 1.5; min-height: 100vh;"
        "\n}"
        "\na { color: var(--accent); text-decoration: none; }"
        "\na:hover { text-decoration: underline; }"
        "\n"
        "\n/* Layout */"
        "\n.page { max-width: 1440px; margin: 0 auto; padding: 24px; }"
        "\n.header {"
        "\n  display: flex; align-items: center; justify-content: space-between;"
        "\n  background: var(--surface); border: 1px solid var(--border);"
        "\n  border-radius: var(--radius); padding: 20px 28px; margin-bottom: 24px;"
        "\n}"
        "\n.header h1 { font-size: 1.5rem; font-weight: 600; }"
        "\n.header-sub { font-size: 0.85rem; color: var(--text-muted); margin-top: 2px; }"
        "\n"
        "\n/* Stats bar */"
        "\n.stats-bar {"
        "\n  display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));"
        "\n  gap: 16px; margin-bottom: 24px;"
        "\n}"
        "\n.stat-card {"
        "\n  background: var(--surface); border: 1px solid var(--border);"
        "\n  border-radius: var(--radius); padding: 16px 20px;"
        "\n}"
        "\n.stat-card .label { font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }"
        "\n.stat-card .value { font-size: 1.6rem; font-weight: 700; margin-top: 4px; font-family: var(--font-data); }"
        "\n"
        "\n/* Toolbar */"
        "\n.toolbar {"
        "\n  display: flex; align-items: center; gap: 12px;"
        "\n  flex-wrap: wrap; margin-bottom: 20px;"
        "\n}"
        "\n.search-input {"
        "\n  flex: 1; min-width: 220px; padding: 10px 14px;"
        "\n  background: var(--surface); border: 1px solid var(--border);"
        "\n  border-radius: var(--radius); color: var(--text);"
        "\n  font-size: 0.9rem; outline: none;"
        "\n}"
        "\n.search-input:focus { border-color: var(--accent); }"
        "\n.filter-select {"
        "\n  padding: 10px 14px; background: var(--surface);"
        "\n  border: 1px solid var(--border); border-radius: var(--radius);"
        "\n  color: var(--text); font-size: 0.9rem; cursor: pointer;"
        "\n}"
        "\n.btn {"
        "\n  padding: 10px 20px; border: none; border-radius: var(--radius);"
        "\n  font-size: 0.9rem; font-weight: 600; cursor: pointer; transition: background 0.15s;"
        "\n}"
        "\n.btn-primary { background: var(--accent); color: #fff; }"
        "\n.btn-primary:hover { background: var(--accent-hover); }"
        "\n.btn-secondary { background: var(--surface); color: var(--text); border: 1px solid var(--border); }"
        "\n.btn-secondary:hover { background: var(--surface-alt); }"
        "\n.btn-sm { padding: 6px 14px; font-size: 0.8rem; }"
        "\n"
        "\n/* Client grid */"
        "\n.client-grid {"
        "\n  display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));"
        "\n  gap: 20px;"
        "\n}"
        "\n.client-card {"
        "\n  background: var(--surface); border: 1px solid var(--border);"
        "\n  border-radius: var(--radius); padding: 20px; cursor: pointer;"
        "\n  transition: border-color 0.15s, transform 0.1s;"
        "\n}"
        "\n.client-card:hover { border-color: var(--accent); transform: translateY(-2px); }"
        "\n.client-card:focus { outline: 2px solid var(--accent); outline-offset: 2px; }"
        "\n.card-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }"
        "\n.client-name { font-size: 1.1rem; font-weight: 600; }"
        "\n"
        "\n/* Badges */"
        "\n.badge {"
        "\n  display: inline-block; padding: 3px 10px; border-radius: 12px;"
        "\n  font-size: 0.72rem; font-weight: 600; text-transform: uppercase;"
        "\n  letter-spacing: 0.04em;"
        "\n}"
        "\n.badge-active { background: rgba(34,197,94,0.15); color: var(--active); }"
        "\n.badge-suspended { background: rgba(249,115,22,0.15); color: var(--suspended); }"
        "\n.badge-archived { background: rgba(107,114,128,0.15); color: var(--archived); }"
        "\n"
        "\n/* Risk score */"
        "\n.risk-block { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }"
        "\n.risk-circle {"
        "\n  width: 52px; height: 52px; border-radius: 50%;"
        "\n  display: flex; align-items: center; justify-content: center;"
        "\n  font-size: 1.1rem; font-weight: 700; font-family: var(--font-data);"
        "\n  flex-shrink: 0;"
        "\n}"
        "\n.risk-low { background: rgba(34,197,94,0.15); color: var(--low); border: 2px solid var(--low); }"
        "\n.risk-medium { background: rgba(234,179,8,0.15); color: var(--medium); border: 2px solid var(--medium); }"
        "\n.risk-high { background: rgba(249,115,22,0.15); color: var(--high); border: 2px solid var(--high); }"
        "\n.risk-critical { background: rgba(239,68,68,0.15); color: var(--critical); border: 2px solid var(--critical); }"
        "\n"
        "\n/* Severity bar */"
        "\n.severity-bar { display: flex; gap: 8px; flex-wrap: wrap; }"
        "\n.sev-chip {"
        "\n  font-size: 0.75rem; padding: 2px 8px; border-radius: 4px;"
        "\n  font-family: var(--font-data); font-weight: 600;"
        "\n}"
        "\n.sev-critical { background: rgba(239,68,68,0.15); color: var(--critical); }"
        "\n.sev-high { background: rgba(249,115,22,0.15); color: var(--high); }"
        "\n.sev-medium { background: rgba(234,179,8,0.15); color: var(--medium); }"
        "\n.sev-low { background: rgba(34,197,94,0.15); color: var(--low); }"
        "\n.sev-info { background: rgba(59,130,246,0.15); color: var(--info); }"
        "\n"
        "\n/* Card meta */"
        "\n.card-meta { display: flex; justify-content: space-between; margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--border); font-size: 0.78rem; color: var(--text-muted); }"
        "\n"
        "\n/* Compliance bar */"
        "\n.compliance-bar { margin-top: 10px; }"
        "\n.compliance-track {"
        "\n  height: 6px; background: var(--border); border-radius: 3px; overflow: hidden;"
        "\n}"
        "\n.compliance-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }"
        "\n.compliance-label { display: flex; justify-content: space-between; font-size: 0.75rem; color: var(--text-muted); margin-top: 4px; }"
        "\n"
        "\n/* Empty state */"
        "\n.empty-state { text-align: center; padding: 60px 20px; color: var(--text-muted); }"
        "\n.empty-state h3 { font-size: 1.2rem; margin-bottom: 8px; color: var(--text); }"
        "\n"
        "\n/* Modal overlay */"
        "\n.modal-overlay {"
        "\n  position: fixed; inset: 0; background: rgba(0,0,0,0.6);"
        "\n  display: none; align-items: center; justify-content: center; z-index: 1000;"
        "\n}"
        "\n.modal-overlay.visible { display: flex; }"
        "\n.modal {"
        "\n  background: var(--surface); border: 1px solid var(--border);"
        "\n  border-radius: var(--radius); padding: 28px; width: 100%;"
        "\n  max-width: 520px; max-height: 90vh; overflow-y: auto;"
        "\n}"
        "\n.modal h2 { font-size: 1.2rem; margin-bottom: 20px; }"
        "\n.form-group { margin-bottom: 16px; }"
        "\n.form-group label {"
        "\n  display: block; font-size: 0.82rem; font-weight: 600;"
        "\n  color: var(--text-muted); margin-bottom: 6px;"
        "\n}"
        "\n.form-group input, .form-group select, .form-group textarea {"
        "\n  width: 100%; padding: 10px 12px; background: var(--bg);"
        "\n  border: 1px solid var(--border); border-radius: var(--radius);"
        "\n  color: var(--text); font-size: 0.9rem; font-family: var(--font-ui);"
        "\n}"
        "\n.form-group input:focus, .form-group select:focus, .form-group textarea:focus { border-color: var(--accent); outline: none; }"
        "\n.form-actions { display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px; }"
        "\n"
        "\n/* Loading */"
        "\n.loading { text-align: center; padding: 40px; color: var(--text-muted); }"
        "\n.spinner {"
        "\n  display: inline-block; width: 28px; height: 28px; border: 3px solid var(--border);"
        "\n  border-top-color: var(--accent); border-radius: 50%;"
        "\n  animation: spin 0.8s linear infinite;"
        "\n}"
        "\n@keyframes spin { to { transform: rotate(360deg); } }"
        "\n"
        "\n/* Toast */"
        "\n.toast {"
        "\n  position: fixed; bottom: 24px; right: 24px; padding: 12px 20px;"
        "\n  background: var(--surface-alt); border: 1px solid var(--border);"
        "\n  border-radius: var(--radius); color: var(--text); font-size: 0.85rem;"
        "\n  box-shadow: var(--shadow); transform: translateY(80px); opacity: 0;"
        "\n  transition: transform 0.3s, opacity 0.3s; z-index: 2000;"
        "\n}"
        "\n.toast.visible { transform: translateY(0); opacity: 1; }"
        "\n"
        "\n/* Skip link for a11y */"
        "\n.skip-link {"
        "\n  position: absolute; top: -40px; left: 0; padding: 8px 16px;"
        "\n  background: var(--accent); color: #fff; z-index: 3000;"
        "\n}"
        "\n.skip-link:focus { top: 0; }"
    )

    # -- JS block --
    js = (
        "const API_BASE = '/api/v1/mssp/clients';\n"
        "let clients = [];\n"
        "let currentFilter = 'all';\n"
        "let searchQuery = '';\n"
        "\n"
        "async function fetchAPI(url, options) {\n"
        "  const resp = await fetch(url, options || {});\n"
        "  if (!resp.ok) {\n"
        "    const text = await resp.text();\n"
        "    throw new Error('API error ' + resp.status + ': ' + text);\n"
        "  }\n"
        "  return resp.json();\n"
        "}\n"
        "\n"
        "function riskClass(score) {\n"
        "  if (score >= 80) return 'risk-critical';\n"
        "  if (score >= 60) return 'risk-high';\n"
        "  if (score >= 40) return 'risk-medium';\n"
        "  return 'risk-low';\n"
        "}\n"
        "\n"
        "function badgeClass(status) {\n"
        "  if (status === 'active') return 'badge-active';\n"
        "  if (status === 'suspended') return 'badge-suspended';\n"
        "  return 'badge-archived';\n"
        "}\n"
        "\n"
        "function complianceColor(pct) {\n"
        "  if (pct >= 80) return 'var(--low)';\n"
        "  if (pct >= 60) return 'var(--medium)';\n"
        "  return 'var(--critical)';\n"
        "}\n"
        "\n"
        "function escapeHtml(str) {\n"
        "  var d = document.createElement('div');\n"
        "  d.appendChild(document.createTextNode(str || ''));\n"
        "  return d.innerHTML;\n"
        "}\n"
        "\n"
        "function renderCard(c) {\n"
        "  var sev = c.severity_breakdown || {};\n"
        "  var chips = '';\n"
        "  if (sev.critical) chips += '<span class=\"sev-chip sev-critical\">C:' + sev.critical + '</span>';\n"
        "  if (sev.high) chips += '<span class=\"sev-chip sev-high\">H:' + sev.high + '</span>';\n"
        "  if (sev.medium) chips += '<span class=\"sev-chip sev-medium\">M:' + sev.medium + '</span>';\n"
        "  if (sev.low) chips += '<span class=\"sev-chip sev-low\">L:' + sev.low + '</span>';\n"
        "  if (sev.info) chips += '<span class=\"sev-chip sev-info\">I:' + sev.info + '</span>';\n"
        "\n"
        "  var compPct = c.compliance_pct || 0;\n"
        "  var lastScan = c.last_scan_date ? new Date(c.last_scan_date).toLocaleDateString() : 'Never';\n"
        "\n"
        "  return '<div class=\"client-card\" tabindex=\"0\" role=\"button\"'\n"
        "    + ' aria-label=\"View details for ' + escapeHtml(c.name) + '\"'\n"
        "    + ' onclick=\"drillDown(\\'' + escapeHtml(c.id) + '\\')\"'\n"
        "    + ' onkeydown=\"if(event.key===\\'Enter\\')drillDown(\\'' + escapeHtml(c.id) + '\\')\"'\n"
        "    + '>'\n"
        "    + '<div class=\"card-top\">'\n"
        "    + '<span class=\"client-name\">' + escapeHtml(c.name) + '</span>'\n"
        "    + '<span class=\"badge ' + badgeClass(c.status) + '\">' + escapeHtml(c.status) + '</span>'\n"
        "    + '</div>'\n"
        "    + '<div class=\"risk-block\">'\n"
        "    + '<div class=\"risk-circle ' + riskClass(c.risk_score) + '\">' + (c.risk_score || 0) + '</div>'\n"
        "    + '<div><div style=\"font-size:0.82rem;color:var(--text-muted)\">Risk Score</div>'\n"
        "    + '<div class=\"severity-bar\">' + chips + '</div></div>'\n"
        "    + '</div>'\n"
        "    + '<div class=\"compliance-bar\">'\n"
        "    + '<div class=\"compliance-track\">'\n"
        "    + '<div class=\"compliance-fill\" style=\"width:' + compPct + '%;background:' + complianceColor(compPct) + '\"></div>'\n"
        "    + '</div>'\n"
        "    + '<div class=\"compliance-label\"><span>Compliance</span><span>' + compPct + '%</span></div>'\n"
        "    + '</div>'\n"
        "    + '<div class=\"card-meta\">'\n"
        "    + '<span>Last scan: ' + lastScan + '</span>'\n"
        "    + '<span>' + (c.total_findings || 0) + ' findings</span>'\n"
        "    + '</div>'\n"
        "    + '</div>';\n"
        "}\n"
        "\n"
        "function getFilteredClients() {\n"
        "  return clients.filter(function(c) {\n"
        "    var matchStatus = (currentFilter === 'all') || (c.status === currentFilter);\n"
        "    var matchSearch = !searchQuery\n"
        "      || (c.name || '').toLowerCase().indexOf(searchQuery.toLowerCase()) !== -1;\n"
        "    return matchStatus && matchSearch;\n"
        "  });\n"
        "}\n"
        "\n"
        "function renderClients() {\n"
        "  var grid = document.getElementById('clientGrid');\n"
        "  var filtered = getFilteredClients();\n"
        "  if (filtered.length === 0) {\n"
        "    grid.innerHTML = '<div class=\"empty-state\"><h3>No clients found</h3>'\n"
        "      + '<p>Adjust your filters or create a new client.</p></div>';\n"
        "    return;\n"
        "  }\n"
        "  var html = '';\n"
        "  for (var i = 0; i < filtered.length; i++) {\n"
        "    html += renderCard(filtered[i]);\n"
        "  }\n"
        "  grid.innerHTML = html;\n"
        "}\n"
        "\n"
        "function updateStats() {\n"
        "  var active = 0, suspended = 0, archived = 0, totalRisk = 0;\n"
        "  for (var i = 0; i < clients.length; i++) {\n"
        "    if (clients[i].status === 'active') active++;\n"
        "    else if (clients[i].status === 'suspended') suspended++;\n"
        "    else archived++;\n"
        "    totalRisk += (clients[i].risk_score || 0);\n"
        "  }\n"
        "  var avgRisk = clients.length ? Math.round(totalRisk / clients.length) : 0;\n"
        "  document.getElementById('statTotal').textContent = clients.length;\n"
        "  document.getElementById('statActive').textContent = active;\n"
        "  document.getElementById('statSuspended').textContent = suspended;\n"
        "  document.getElementById('statAvgRisk').textContent = avgRisk;\n"
        "}\n"
        "\n"
        "function showToast(msg) {\n"
        "  var t = document.getElementById('toast');\n"
        "  t.textContent = msg;\n"
        "  t.classList.add('visible');\n"
        "  setTimeout(function() { t.classList.remove('visible'); }, 3000);\n"
        "}\n"
        "\n"
        "async function loadClients() {\n"
        "  document.getElementById('clientGrid').innerHTML =\n"
        "    '<div class=\"loading\"><div class=\"spinner\"></div><p>Loading clients...</p></div>';\n"
        "  try {\n"
        "    var data = await fetchAPI(API_BASE);\n"
        "    clients = data.clients || data || [];\n"
        "    updateStats();\n"
        "    renderClients();\n"
        "  } catch (err) {\n"
        "    document.getElementById('clientGrid').innerHTML =\n"
        "      '<div class=\"empty-state\"><h3>Failed to load clients</h3>'\n"
        "      + '<p>' + escapeHtml(err.message) + '</p></div>';\n"
        "  }\n"
        "}\n"
        "\n"
        "function drillDown(clientId) {\n"
        "  window.location.href = '/mssp/clients/' + encodeURIComponent(clientId);\n"
        "}\n"
        "\n"
        "function openCreateModal() {\n"
        "  document.getElementById('createModal').classList.add('visible');\n"
        "  document.getElementById('newClientName').focus();\n"
        "}\n"
        "\n"
        "function closeCreateModal() {\n"
        "  document.getElementById('createModal').classList.remove('visible');\n"
        "  document.getElementById('createForm').reset();\n"
        "}\n"
        "\n"
        "async function handleCreateSubmit(e) {\n"
        "  e.preventDefault();\n"
        "  var payload = {\n"
        "    name: document.getElementById('newClientName').value.trim(),\n"
        "    contact_email: document.getElementById('newClientEmail').value.trim(),\n"
        "    industry: document.getElementById('newClientIndustry').value,\n"
        "    notes: document.getElementById('newClientNotes').value.trim()\n"
        "  };\n"
        "  if (!payload.name) { showToast('Client name is required'); return; }\n"
        "  try {\n"
        "    await fetchAPI(API_BASE, {\n"
        "      method: 'POST',\n"
        "      headers: { 'Content-Type': 'application/json' },\n"
        "      body: JSON.stringify(payload)\n"
        "    });\n"
        "    closeCreateModal();\n"
        "    showToast('Client created successfully');\n"
        "    loadClients();\n"
        "  } catch (err) {\n"
        "    showToast('Error: ' + err.message);\n"
        "  }\n"
        "}\n"
        "\n"
        "document.addEventListener('DOMContentLoaded', function() {\n"
        "  loadClients();\n"
        "\n"
        "  document.getElementById('searchInput').addEventListener('input', function(e) {\n"
        "    searchQuery = e.target.value;\n"
        "    renderClients();\n"
        "  });\n"
        "\n"
        "  document.getElementById('statusFilter').addEventListener('change', function(e) {\n"
        "    currentFilter = e.target.value;\n"
        "    renderClients();\n"
        "  });\n"
        "\n"
        "  document.getElementById('createForm').addEventListener('submit', handleCreateSubmit);\n"
        "\n"
        "  document.getElementById('createModal').addEventListener('click', function(e) {\n"
        "    if (e.target === this) closeCreateModal();\n"
        "  });\n"
        "\n"
        "  document.addEventListener('keydown', function(e) {\n"
        "    if (e.key === 'Escape') closeCreateModal();\n"
        "  });\n"
        "});\n"
    )

    # -- HTML body --
    body = (
        '<a class="skip-link" href="#clientGrid">Skip to client list</a>\n'
        '<div class="page">\n'
        '  <header class="header">\n'
        '    <div>\n'
        '      <h1>MSSP Client Portfolio</h1>\n'
        '      <div class="header-sub">Managed Security Service Provider &mdash; Client Overview</div>\n'
        '    </div>\n'
        '    <button class="btn btn-primary" onclick="openCreateModal()" aria-label="Create new client">\n'
        '      + New Client\n'
        '    </button>\n'
        '  </header>\n'
        '\n'
        '  <div class="stats-bar" role="region" aria-label="Portfolio statistics">\n'
        '    <div class="stat-card"><div class="label">Total Clients</div><div class="value" id="statTotal">-</div></div>\n'
        '    <div class="stat-card"><div class="label">Active</div><div class="value" id="statActive" style="color:var(--active)">-</div></div>\n'
        '    <div class="stat-card"><div class="label">Suspended</div><div class="value" id="statSuspended" style="color:var(--suspended)">-</div></div>\n'
        '    <div class="stat-card"><div class="label">Avg Risk Score</div><div class="value" id="statAvgRisk">-</div></div>\n'
        '  </div>\n'
        '\n'
        '  <div class="toolbar">\n'
        '    <input id="searchInput" class="search-input" type="search"\n'
        '           placeholder="Search clients..." aria-label="Search clients">\n'
        '    <select id="statusFilter" class="filter-select" aria-label="Filter by status">\n'
        '      <option value="all">All Statuses</option>\n'
        '      <option value="active">Active</option>\n'
        '      <option value="suspended">Suspended</option>\n'
        '      <option value="archived">Archived</option>\n'
        '    </select>\n'
        '    <button class="btn btn-secondary" onclick="loadClients()" aria-label="Refresh client list">\n'
        '      Refresh\n'
        '    </button>\n'
        '  </div>\n'
        '\n'
        '  <main id="clientGrid" class="client-grid" role="list" aria-label="Client list">\n'
        '    <div class="loading"><div class="spinner"></div><p>Loading clients...</p></div>\n'
        '  </main>\n'
        '</div>\n'
        '\n'
        '<!-- Create Client Modal -->\n'
        '<div id="createModal" class="modal-overlay" role="dialog" aria-modal="true" aria-label="Create new client">\n'
        '  <div class="modal">\n'
        '    <h2>Create New Client</h2>\n'
        '    <form id="createForm">\n'
        '      <div class="form-group">\n'
        '        <label for="newClientName">Client Name *</label>\n'
        '        <input id="newClientName" type="text" required placeholder="Acme Corporation">\n'
        '      </div>\n'
        '      <div class="form-group">\n'
        '        <label for="newClientEmail">Contact Email</label>\n'
        '        <input id="newClientEmail" type="email" placeholder="security@acme.com">\n'
        '      </div>\n'
        '      <div class="form-group">\n'
        '        <label for="newClientIndustry">Industry</label>\n'
        '        <select id="newClientIndustry">\n'
        '          <option value="">Select...</option>\n'
        '          <option value="finance">Finance</option>\n'
        '          <option value="healthcare">Healthcare</option>\n'
        '          <option value="technology">Technology</option>\n'
        '          <option value="manufacturing">Manufacturing</option>\n'
        '          <option value="retail">Retail</option>\n'
        '          <option value="government">Government</option>\n'
        '          <option value="education">Education</option>\n'
        '          <option value="other">Other</option>\n'
        '        </select>\n'
        '      </div>\n'
        '      <div class="form-group">\n'
        '        <label for="newClientNotes">Notes</label>\n'
        '        <textarea id="newClientNotes" rows="3" placeholder="Optional notes..."></textarea>\n'
        '      </div>\n'
        '      <div class="form-actions">\n'
        '        <button type="button" class="btn btn-secondary" onclick="closeCreateModal()">Cancel</button>\n'
        '        <button type="submit" class="btn btn-primary">Create Client</button>\n'
        '      </div>\n'
        '    </form>\n'
        '  </div>\n'
        '</div>\n'
        '\n'
        '<div id="toast" class="toast" role="alert" aria-live="polite"></div>\n'
    )

    # -- Assemble full HTML --
    html = (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<title>Donjon MSSP - Client Portfolio</title>\n'
        '<style>\n' + css + '\n</style>\n'
        '</head>\n'
        '<body>\n'
        + body
        + '<script>\n' + js + '</script>\n'
        '</body>\n'
        '</html>'
    )

    return html
