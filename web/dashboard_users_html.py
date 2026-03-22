#!/usr/bin/env python3
"""
Donjon Platform - Users & Roles Tab (HTML)
Enterprise tier: fetches RBAC roles and user list.
All CSS/JS inline for air-gap operation.
"""


def generate_users_html() -> str:
    """Return the users-roles tab HTML as a string."""
    parts = []

    parts.append('<style>')
    parts.append(
        '.ur-grid {'
        '  display: grid;'
        '  grid-template-columns: 1fr 1fr;'
        '  gap: 20px;'
        '  margin-bottom: 24px;'
        '}'
        '@media (max-width: 900px) { .ur-grid { grid-template-columns: 1fr; } }'
        '.ur-panel {'
        '  background: var(--bg-surface);'
        '  border: 1px solid var(--border);'
        '  border-radius: var(--radius);'
        '  padding: 20px;'
        '}'
        '.ur-panel-title {'
        '  font-size: 0.95rem;'
        '  font-weight: 600;'
        '  margin-bottom: 12px;'
        '}'
        '.ur-table {'
        '  width: 100%;'
        '  border-collapse: collapse;'
        '  font-size: 0.85rem;'
        '}'
        '.ur-table th {'
        '  text-align: left;'
        '  padding: 8px 12px;'
        '  font-weight: 600;'
        '  color: var(--text-muted);'
        '  border-bottom: 2px solid var(--border);'
        '  font-size: 0.8rem;'
        '  text-transform: uppercase;'
        '}'
        '.ur-table td {'
        '  padding: 8px 12px;'
        '  border-bottom: 1px solid var(--border);'
        '  color: var(--text);'
        '}'
        '.ur-badge {'
        '  display: inline-block;'
        '  padding: 2px 8px;'
        '  border-radius: 10px;'
        '  font-size: 0.75rem;'
        '  font-weight: 600;'
        '  background: rgba(99,102,241,0.15);'
        '  color: var(--accent);'
        '}'
        '.ur-upgrade {'
        '  text-align: center;'
        '  padding: 60px 20px;'
        '  color: var(--text-muted);'
        '}'
        '.ur-upgrade-title {'
        '  font-size: 1.2rem;'
        '  font-weight: 700;'
        '  color: var(--text);'
        '  margin-bottom: 8px;'
        '}'
    )
    parts.append('</style>')

    parts.append(
        '<div id="urContent">'
        '<div class="ur-grid">'
        '<div class="ur-panel">'
        '<div class="ur-panel-title">Users</div>'
        '<table class="ur-table">'
        '<thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Status</th></tr></thead>'
        '<tbody id="urUsersBody">'
        '<tr><td colspan="4" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
        '<div class="ur-panel">'
        '<div class="ur-panel-title">Roles</div>'
        '<table class="ur-table">'
        '<thead><tr><th>Role</th><th>Permissions</th><th>Members</th></tr></thead>'
        '<tbody id="urRolesBody">'
        '<tr><td colspan="3" style="color:var(--text-muted);text-align:center;">Loading...</td></tr>'
        '</tbody>'
        '</table>'
        '</div>'
        '</div>'
        '</div>'
    )

    parts.append('<script>')
    parts.append('''(function(){
    document.addEventListener("tabload", function(e) {
        if (!e.detail || e.detail.tab !== "users-roles") return;

        var token = localStorage.getItem("donjon_token");
        var headers = {"Content-Type": "application/json"};
        if (token) headers["Authorization"] = "Bearer " + token;

        fetch("/api/v1/rbac/roles", {headers: headers}).then(function(r) {
            if (r.status === 403) throw {upgrade: true};
            if (!r.ok) throw new Error("API " + r.status);
            return r.json();
        }).then(function(data) {
            var roles = Array.isArray(data) ? data : (data.roles || []);
            var body = document.getElementById("urRolesBody");
            if (roles.length === 0) {
                body.innerHTML = '<tr><td colspan="3" style="color:var(--text-muted);text-align:center;">No roles configured.</td></tr>';
                return;
            }
            body.innerHTML = "";
            roles.forEach(function(r) {
                var tr = document.createElement("tr");
                var perms = (r.permissions || []).join(", ") || "-";
                tr.innerHTML =
                    '<td><span class="ur-badge">' + (r.name || r.role || "-") + '</span></td>' +
                    '<td>' + perms.substring(0, 80) + '</td>' +
                    '<td>' + (r.member_count || r.members || 0) + '</td>';
                body.appendChild(tr);
            });
        }).catch(function(err) {
            if (err && err.upgrade) {
                document.getElementById("urContent").innerHTML =
                    '<div class="ur-upgrade"><div class="ur-upgrade-title">Enterprise Feature</div>' +
                    'Users &amp; Roles management requires an Enterprise or Managed license.<br>' +
                    'Contact sales or upgrade your license to access this feature.</div>';
                return;
            }
            document.getElementById("urRolesBody").innerHTML =
                '<tr><td colspan="3" style="color:var(--text-muted);text-align:center;">Failed to load roles.</td></tr>';
        });

        fetch("/api/v1/rbac/users", {headers: headers}).then(function(r) {
            if (r.status === 403) return null;
            if (!r.ok) throw new Error("API " + r.status);
            return r.json();
        }).then(function(data) {
            if (!data) return;
            var users = Array.isArray(data) ? data : (data.users || []);
            var body = document.getElementById("urUsersBody");
            if (users.length === 0) {
                body.innerHTML = '<tr><td colspan="4" style="color:var(--text-muted);text-align:center;">No users found.</td></tr>';
                return;
            }
            body.innerHTML = "";
            users.forEach(function(u) {
                var tr = document.createElement("tr");
                var status = (u.active !== false && u.disabled !== true) ? "Active" : "Disabled";
                tr.innerHTML =
                    '<td>' + (u.username || u.name || "-") + '</td>' +
                    '<td>' + (u.email || "-") + '</td>' +
                    '<td><span class="ur-badge">' + (u.role || u.roles || "-") + '</span></td>' +
                    '<td>' + status + '</td>';
                body.appendChild(tr);
            });
        }).catch(function(){
            var el = document.getElementById("urUsersBody");
            if (el) el.innerHTML = '<tr><td colspan="4" style="color:var(--text-muted);text-align:center;">Failed to load users.</td></tr>';
        });
    });
})();''')
    parts.append('</script>')

    return ''.join(parts)
