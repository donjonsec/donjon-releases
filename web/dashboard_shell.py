#!/usr/bin/env python3
"""
Donjon Platform - Dashboard Shell (Theme C Hybrid)
Sidebar-based SPA shell with dark/light theme toggle.
All CSS/JS inline for air-gap operation.
"""


def generate_shell() -> str:
    """Return the complete dashboard shell HTML as a string."""
    parts = []

    # --- DOCTYPE and head ---
    parts.append(
        '<!DOCTYPE html>'
        '<html lang="en" data-theme="dark">'
        '<head>'
        '<meta charset="utf-8"/>'
        '<meta name="viewport" content="width=device-width, initial-scale=1"/>'
        '<title>Donjon Platform</title>'
        '<style>'
    )

    # --- CSS variables: dark theme ---
    parts.append(
        '[data-theme="dark"] {'
        '  --bg-body: #111827;'
        '  --bg-surface: #1F2937;'
        '  --bg-surface-alt: #283548;'
        '  --border: #374151;'
        '  --text: #F9FAFB;'
        '  --text-muted: #9CA3AF;'
        '  --accent: #6366F1;'
        '  --accent-hover: #818CF8;'
        '  --sidebar-bg: #0F172A;'
        '  --sidebar-hover: #1E293B;'
        '  --shadow: 0 2px 12px rgba(0,0,0,0.4);'
        '}'
    )

    # --- CSS variables: light theme ---
    parts.append(
        '[data-theme="light"] {'
        '  --bg-body: #F3F4F6;'
        '  --bg-surface: #FFFFFF;'
        '  --bg-surface-alt: #F9FAFB;'
        '  --border: #D1D5DB;'
        '  --text: #111827;'
        '  --text-muted: #6B7280;'
        '  --accent: #4F46E5;'
        '  --accent-hover: #6366F1;'
        '  --sidebar-bg: #1F2937;'
        '  --sidebar-hover: #374151;'
        '  --shadow: 0 2px 12px rgba(0,0,0,0.1);'
        '}'
    )

    # --- Shared severity / utility colors ---
    parts.append(
        ':root {'
        '  --critical: #EF4444;'
        '  --high: #F97316;'
        '  --medium: #EAB308;'
        '  --low: #22C55E;'
        '  --info: #3B82F6;'
        '  --font-ui: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;'
        '  --font-data: Consolas, "Courier New", "Liberation Mono", monospace;'
        '  --radius: 8px;'
        '}'
    )

    # --- CSS Reset ---
    parts.append(
        '*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }'
        'html { font-size: 14px; }'
        'body {'
        '  font-family: var(--font-ui);'
        '  background: var(--bg-body);'
        '  color: var(--text);'
        '  line-height: 1.5;'
        '  min-height: 100vh;'
        '  display: flex;'
        '}'
        'a { color: var(--accent); text-decoration: none; }'
        'a:hover { text-decoration: underline; }'
    )

    # --- Sidebar CSS ---
    parts.append(
        '.sidebar {'
        '  width: 240px;'
        '  min-width: 240px;'
        '  background: var(--sidebar-bg);'
        '  border-right: 1px solid var(--border);'
        '  display: flex;'
        '  flex-direction: column;'
        '  height: 100vh;'
        '  position: fixed;'
        '  top: 0;'
        '  left: 0;'
        '  z-index: 100;'
        '  overflow-y: auto;'
        '  transition: transform 0.25s ease;'
        '}'
        '.sidebar-brand {'
        '  display: flex;'
        '  align-items: center;'
        '  gap: 12px;'
        '  padding: 20px 16px;'
        '  border-bottom: 1px solid var(--border);'
        '}'
        '.sidebar-logo {'
        '  width: 36px; height: 36px;'
        '  background: var(--accent);'
        '  border-radius: 8px;'
        '  display: flex; align-items: center; justify-content: center;'
        '  font-size: 18px; font-weight: 700; color: #fff;'
        '}'
        '.sidebar-brand-text {'
        '  font-size: 1.1rem;'
        '  font-weight: 700;'
        '  color: #F9FAFB;'
        '  letter-spacing: 0.5px;'
        '}'
    )

    # --- Nav items CSS ---
    parts.append(
        '.nav-section {'
        '  padding: 12px 0;'
        '}'
        '.nav-section-label {'
        '  padding: 6px 16px;'
        '  font-size: 0.7rem;'
        '  text-transform: uppercase;'
        '  letter-spacing: 1px;'
        '  color: #6B7280;'
        '  font-weight: 600;'
        '}'
        '.nav-item {'
        '  display: flex;'
        '  align-items: center;'
        '  gap: 10px;'
        '  padding: 10px 16px;'
        '  color: #D1D5DB;'
        '  cursor: pointer;'
        '  font-size: 0.9rem;'
        '  font-weight: 500;'
        '  border: none;'
        '  background: none;'
        '  width: 100%;'
        '  text-align: left;'
        '  font-family: var(--font-ui);'
        '  transition: background 0.15s, color 0.15s;'
        '}'
        '.nav-item:hover {'
        '  background: var(--sidebar-hover);'
        '  color: #F9FAFB;'
        '}'
        '.nav-item.active {'
        '  background: var(--accent);'
        '  color: #fff;'
        '  border-radius: 0;'
        '}'
        '.nav-icon { font-size: 1.1rem; width: 22px; text-align: center; }'
        '.sidebar-footer {'
        '  margin-top: auto;'
        '  padding: 12px 16px;'
        '  border-top: 1px solid var(--border);'
        '}'
    )

    # --- Main content CSS ---
    parts.append(
        '.main-content {'
        '  margin-left: 240px;'
        '  flex: 1;'
        '  padding: 24px 32px;'
        '  min-height: 100vh;'
        '  width: calc(100% - 240px);'
        '}'
        '.topbar {'
        '  display: flex;'
        '  align-items: center;'
        '  justify-content: space-between;'
        '  margin-bottom: 24px;'
        '}'
        '.topbar h2 {'
        '  font-size: 1.4rem;'
        '  font-weight: 700;'
        '}'
        '.topbar-actions { display: flex; gap: 8px; align-items: center; }'
    )

    # --- Theme toggle button CSS ---
    parts.append(
        '.theme-toggle {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: 6px;'
        '  padding: 6px 10px;'
        '  cursor: pointer;'
        '  font-size: 1.1rem;'
        '  color: var(--text);'
        '  transition: background 0.2s;'
        '}'
        '.theme-toggle:hover { background: var(--bg-surface-alt); }'
    )

    # --- Mobile hamburger CSS ---
    parts.append(
        '.hamburger {'
        '  display: none;'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: 6px;'
        '  padding: 6px 10px;'
        '  cursor: pointer;'
        '  font-size: 1.2rem;'
        '  color: var(--text);'
        '}'
        '.sidebar-overlay {'
        '  display: none;'
        '  position: fixed;'
        '  top: 0; left: 0; right: 0; bottom: 0;'
        '  background: rgba(0,0,0,0.5);'
        '  z-index: 99;'
        '}'
    )

    # --- Tab content area CSS ---
    parts.append(
        '.tab-content { display: none; }'
        '.tab-content.active { display: block; }'
        '.tab-loading {'
        '  text-align: center;'
        '  padding: 60px 20px;'
        '  color: var(--text-muted);'
        '  font-size: 1rem;'
        '}'
    )

    # --- Enterprise/MSSP section CSS ---
    parts.append(
        '.nav-section.hidden { display: none; }'
    )

    # --- Responsive ---
    parts.append(
        '@media (max-width: 768px) {'
        '  .hamburger { display: block; }'
        '  .sidebar { transform: translateX(-100%); }'
        '  .sidebar.open { transform: translateX(0); }'
        '  .sidebar-overlay.open { display: block; }'
        '  .main-content { margin-left: 0; width: 100%; padding: 16px; }'
        '}'
    )

    parts.append('</style></head>')

    # --- Body: Sidebar ---
    parts.append('<body>')
    parts.append('<div class="sidebar-overlay" id="sidebarOverlay"></div>')
    parts.append('<nav class="sidebar" id="sidebar">')

    # Brand
    parts.append(
        '<div class="sidebar-brand">'
        '<div class="sidebar-logo">D</div>'
        '<span class="sidebar-brand-text">Donjon</span>'
        '</div>'
    )

    # Core nav items
    nav_core = [
        ("overview",           "\u2302", "Overview"),
        ("scan-center",        "\u2316", "Scan Center"),
        ("compliance",         "\u2611", "Compliance"),
        ("risk-analysis",      "\u2621", "Risk Analysis"),
        ("patch-verification", "\u2699", "Patch Verification"),
        ("schedules",          "\u23F0", "Schedules"),
        ("ai-assistant",       "\u2728", "AI Assistant"),
        ("trends",             "\u2197", "Trends"),
        ("lifecycle",          "\u267B", "License"),
        ("settings",           "\u2638", "Settings"),
    ]

    parts.append('<div class="nav-section">')
    parts.append('<div class="nav-section-label">Platform</div>')
    for tab_id, icon, label in nav_core:
        active = ' active' if tab_id == 'overview' else ''
        parts.append(
            '<button class="nav-item' + active + '" data-tab="' + tab_id + '">'
            '<span class="nav-icon">' + icon + '</span>'
            + label +
            '</button>'
        )
    parts.append('</div>')

    # Enterprise nav items
    nav_enterprise = [
        ("users-roles", "\u263A", "Users &amp; Roles"),
        ("sso",         "\u26BF", "SSO"),
        ("tenants",     "\u2616", "Tenants"),
        ("audit-log",   "\u2709", "Audit Log"),
    ]

    parts.append('<div class="nav-section" id="navEnterprise">')
    parts.append('<div class="nav-section-label">Enterprise</div>')
    for tab_id, icon, label in nav_enterprise:
        parts.append(
            '<button class="nav-item" data-tab="' + tab_id + '">'
            '<span class="nav-icon">' + icon + '</span>'
            + label +
            '</button>'
        )
    parts.append('</div>')

    # MSSP nav items
    nav_mssp = [
        ("clients",    "\u2637", "Clients"),
        ("bulk-scans", "\u29C9", "Bulk Scans"),
        ("reports",    "\u2630", "Reports"),
        ("metering",   "\u2328", "Metering"),
    ]

    parts.append('<div class="nav-section" id="navMSSP">')
    parts.append('<div class="nav-section-label">Managed</div>')
    for tab_id, icon, label in nav_mssp:
        parts.append(
            '<button class="nav-item" data-tab="' + tab_id + '">'
            '<span class="nav-icon">' + icon + '</span>'
            + label +
            '</button>'
        )
    parts.append('</div>')

    # Sidebar footer
    parts.append(
        '<div class="sidebar-footer">'
        '<span style="font-size:0.75rem;color:#6B7280;">'
        'Donjon Platform v7.3.0'
        '</span>'
        '</div>'
    )

    parts.append('</nav>')

    # --- Body: Main content ---
    parts.append('<main class="main-content">')
    parts.append(
        '<div class="topbar">'
        '<div style="display:flex;align-items:center;gap:12px;">'
        '<button class="hamburger" id="hamburgerBtn">'
        '\u2630'
        '</button>'
        '<h2 id="pageTitle">Overview</h2>'
        '</div>'
        '<div class="topbar-actions">'
        '<button class="theme-toggle" id="themeToggle" '
        'title="Toggle theme">'
        '\u263D'
        '</button>'
        '</div>'
        '</div>'
    )

    # Tab content placeholders
    all_tabs = (
        [t[0] for t in nav_core]
        + [t[0] for t in nav_enterprise]
        + [t[0] for t in nav_mssp]
    )
    # Load sub-module HTML generators
    _tab_html = {}
    try:
        from web.dashboard_overview_html import generate_overview_html
        _tab_html["overview"] = generate_overview_html()
    except Exception:
        pass
    try:
        from web.dashboard_scan_center import generate_scan_center
        _tab_html["scan-center"] = generate_scan_center()
    except Exception:
        pass
    try:
        from web.dashboard_lifecycle import generate_lifecycle
        _tab_html["lifecycle"] = generate_lifecycle()
    except Exception:
        pass
    try:
        from web.dashboard_trends import generate_trends
        _tab_html["trends"] = generate_trends()
    except Exception:
        pass
    try:
        from web.dashboard_compliance_html import generate_compliance_html
        _tab_html["compliance"] = generate_compliance_html()
    except Exception:
        pass
    try:
        from web.dashboard_risk_html import generate_risk_html
        _tab_html["risk-analysis"] = generate_risk_html()
    except Exception:
        pass
    try:
        from web.dashboard_schedules_html import generate_schedules_html
        _tab_html["schedules"] = generate_schedules_html()
    except Exception:
        pass
    try:
        from web.dashboard_ai_html import generate_ai_html
        _tab_html["ai-assistant"] = generate_ai_html()
    except Exception:
        pass
    try:
        from web.dashboard_settings_html import generate_settings_html
        _tab_html["settings"] = generate_settings_html()
    except Exception:
        pass
    try:
        from web.dashboard_patch_html import generate_patch_html
        _tab_html["patch-verification"] = generate_patch_html()
    except Exception:
        pass

    for tab_id in all_tabs:
        active = ' active' if tab_id == 'overview' else ''
        inner = _tab_html.get(tab_id, '<div class="tab-loading">Loading\u2026</div>')
        parts.append(
            '<div class="tab-content' + active + '" id="tab-' + tab_id + '">'
            + inner +
            '</div>'
        )

    parts.append('</main>')

    # --- JavaScript ---
    parts.append('<script>')

    parts.append(
        '(function(){'
        # ---- fetchAPI helper ----
        'window.fetchAPI=function(path,opts){'
        '  opts=opts||{};'
        '  var headers=opts.headers||{};'
        '  headers["Content-Type"]="application/json";'
        '  var token=localStorage.getItem("donjon_token");'
        '  if(token){headers["Authorization"]="Bearer "+token;}'
        '  return fetch("/api/v1"+path,{'
        '    method:opts.method||"GET",'
        '    headers:headers,'
        '    body:opts.body?JSON.stringify(opts.body):undefined'
        '  }).then(function(r){'
        '    if(!r.ok){throw new Error("API "+r.status);}'
        '    return r.json();'
        '  });'
        '};'
    )

    parts.append(
        # ---- Tier visibility ----
        'function applyTier(){'
        '  fetchAPI("/license").then(function(d){'
        '    var tier=d.tier||"community";'
        '    var ent=document.getElementById("navEnterprise");'
        '    var mssp=document.getElementById("navMSSP");'
        '    if(tier==="enterprise"||tier==="managed"){'
        '      ent.classList.remove("hidden");'
        '    }else{ent.classList.add("hidden");}'
        '    if(tier==="managed"){'
        '      mssp.classList.remove("hidden");'
        '    }else{mssp.classList.add("hidden");}'
        '  }).catch(function(){'
        '    document.getElementById("navEnterprise").classList.add("hidden");'
        '    document.getElementById("navMSSP").classList.add("hidden");'
        '  });'
        '}'
        'applyTier();'
    )

    parts.append(
        # ---- Tab switching ----
        'var navItems=document.querySelectorAll(".nav-item");'
        'var tabPanes=document.querySelectorAll(".tab-content");'
        'var pageTitle=document.getElementById("pageTitle");'
        'var loaded={};'
        ''
        'function switchTab(tabId){'
        '  navItems.forEach(function(n){'
        '    n.classList.toggle("active",n.getAttribute("data-tab")===tabId);'
        '  });'
        '  tabPanes.forEach(function(p){'
        '    p.classList.toggle("active",p.id==="tab-"+tabId);'
        '  });'
        '  pageTitle.textContent='
        '    document.querySelector(".nav-item[data-tab=\\""+tabId+"\\"]").textContent.trim();'
        '  if(!loaded[tabId]){'
        '    loaded[tabId]=true;'
        '    var evt=new CustomEvent("tabload",{detail:{tab:tabId}});'
        '    document.dispatchEvent(evt);'
        '  }'
        '  closeSidebar();'
        '}'
        ''
        'navItems.forEach(function(btn){'
        '  btn.addEventListener("click",function(){'
        '    switchTab(btn.getAttribute("data-tab"));'
        '  });'
        '});'
        # Fire initial tab
        'loaded["overview"]=true;'
        'document.dispatchEvent(new CustomEvent("tabload",{detail:{tab:"overview"}}));'
    )

    parts.append(
        # ---- Theme toggle ----
        'var themeBtn=document.getElementById("themeToggle");'
        'function setTheme(t){'
        '  document.documentElement.setAttribute("data-theme",t);'
        '  themeBtn.textContent=t==="dark"?"\\u263D":"\\u2600";'
        '  localStorage.setItem("donjon_theme",t);'
        '}'
        'var saved=localStorage.getItem("donjon_theme")||"dark";'
        'setTheme(saved);'
        'themeBtn.addEventListener("click",function(){'
        '  var cur=document.documentElement.getAttribute("data-theme");'
        '  setTheme(cur==="dark"?"light":"dark");'
        '});'
    )

    parts.append(
        # ---- Mobile sidebar toggle ----
        'var sidebar=document.getElementById("sidebar");'
        'var overlay=document.getElementById("sidebarOverlay");'
        'var hamburger=document.getElementById("hamburgerBtn");'
        'function closeSidebar(){'
        '  sidebar.classList.remove("open");'
        '  overlay.classList.remove("open");'
        '}'
        'hamburger.addEventListener("click",function(){'
        '  sidebar.classList.toggle("open");'
        '  overlay.classList.toggle("open");'
        '});'
        'overlay.addEventListener("click",closeSidebar);'
    )

    parts.append('})();')
    parts.append('</script>')
    parts.append('</body></html>')

    return ''.join(parts)
